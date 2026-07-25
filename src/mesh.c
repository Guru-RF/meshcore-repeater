/* mesh.c - MeshCore repeater forwarding logic. */
#include "mesh.h"
#include "advert.h"
#include "sx126x.h"
#include "hal.h"
#include "log.h"
#include "util.h"
#include "hmac_sha256.h"
#include "crypto/aes128.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void mesh_init(mc_mesh_t *m, const mc_identity_t *id, const mc_config_t *cfg)
{
    memset(m, 0, sizeof(*m));
    m->id = id;
    m->cfg = cfg;
    m->start_ms = hal_millis();
}

/* Returns true if hash was already present; otherwise records it. */
static bool seen_check_and_add(mc_mesh_t *m, const uint8_t *hash)
{
    for (int i = 0; i < MESH_SEEN_SIZE; i++) {
        if (memcmp(m->seen[i], hash, MC_MAX_HASH_SIZE) == 0)
            return true;
    }
    memcpy(m->seen[m->seen_idx], hash, MC_MAX_HASH_SIZE);
    m->seen_idx = (m->seen_idx + 1) % MESH_SEEN_SIZE;
    return false;
}

static void neighbor_update(mc_mesh_t *m, const uint8_t pub[MC_PUB_KEY_SIZE],
                            const mc_packet_t *pkt, int16_t rssi, int8_t snr_q)
{
    uint32_t now = (uint32_t)time(NULL);
    int free_slot = -1, oldest = 0;
    uint32_t oldest_ts = 0xFFFFFFFFu;

    for (int i = 0; i < MESH_MAX_NEIGHBORS; i++) {
        mesh_neighbor_t *n = &m->neighbors[i];
        if (n->used && memcmp(n->pub, pub, MC_PUB_KEY_SIZE) == 0) {
            n->rssi = rssi; n->snr_q = snr_q; n->last_seen = now; n->count++;
            mc_advert_extract(pkt, &n->type, n->name, sizeof(n->name));
            return;
        }
        if (!n->used && free_slot < 0)
            free_slot = i;
        if (n->used && n->last_seen < oldest_ts) {
            oldest_ts = n->last_seen; oldest = i;
        }
    }

    int idx = (free_slot >= 0) ? free_slot : oldest; /* reuse oldest if full */
    mesh_neighbor_t *n = &m->neighbors[idx];
    memset(n, 0, sizeof(*n));
    n->used = true;
    memcpy(n->pub, pub, MC_PUB_KEY_SIZE);
    n->rssi = rssi; n->snr_q = snr_q; n->last_seen = now; n->count = 1;
    mc_advert_extract(pkt, &n->type, n->name, sizeof(n->name));
}

static void enqueue(mc_mesh_t *m, const mc_packet_t *pkt, uint8_t priority, uint32_t delay_ms)
{
    uint64_t now = hal_millis();
    for (int i = 0; i < MESH_TXQ_SIZE; i++) {
        if (!m->txq[i].used) {
            m->txq[i].used = true;
            m->txq[i].pkt = *pkt;
            m->txq[i].priority = priority;
            m->txq[i].due_ms = now + delay_ms;
            return;
        }
    }
    m->stats.tx_queue_full++;
    log_warn("mesh: TX queue full, dropping packet (type=%u)", pkt_payload_type(pkt));
}

/* ---- strict ham content policy: forward public, drop private ---- */
typedef enum {
    FWD_OK_PUBLIC,        /* advert / trace (already sig-checked upstream) */
    FWD_OK_GRP_PUBLIC,    /* group message on a configured public channel */
    FWD_DROP_DM,          /* private pairwise-encrypted unicast */
    FWD_DROP_GRP_UNMATCHED,/* group message on an unconfigured channel */
    FWD_DROP_GRP_MACFAIL, /* channel hash matched but the MAC did not verify */
    FWD_DROP_OTHER,       /* ack / control / multipart / raw / unknown types */
} fwd_decision_t;

/*
 * Decide whether a received packet may be retransmitted. Amateur-radio rules
 * forbid relaying content whose meaning is obscured, so this is a strict
 * allow-list with a fail-safe DROP default:
 *   - ADVERT (Ed25519-signed plaintext) and TRACE (plaintext) -> forward.
 *   - GRP_TXT/GRP_DATA -> forward only if the packet's channel MAC verifies
 *     against a configured PUBLIC channel (published key => not obscured). The
 *     MAC is HMAC-SHA256(secret, ciphertext)[0..1]; no decryption is needed.
 *   - everything else (private unicast, unknown channels, unknown types) -> drop.
 */
static fwd_decision_t classify_forward(const mc_mesh_t *m, const mc_packet_t *pkt,
                                       const mc_pub_channel_t **matched)
{
    if (matched)
        *matched = NULL;

    switch (pkt_payload_type(pkt)) {
    case PAYLOAD_TYPE_ADVERT:   /* signature already verified in mesh_on_recv */
    case PAYLOAD_TYPE_TRACE:    /* plaintext */
        return FWD_OK_PUBLIC;

    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA: {
        /* payload = [channel_hash:1][MAC:2][AES-128 ciphertext]; min 1+2+16 */
        if (pkt->payload_len < 19)
            return FWD_DROP_GRP_UNMATCHED;
        uint8_t chash      = pkt->payload[0];
        const uint8_t *mac = &pkt->payload[1];
        const uint8_t *ct  = &pkt->payload[3];
        size_t ctlen       = (size_t)pkt->payload_len - 3;
        bool hash_seen = false;
        for (int i = 0; i < m->cfg->n_public_channels; i++) {
            const mc_pub_channel_t *ch = &m->cfg->public_channels[i];
            if (ch->hash != chash)
                continue;
            hash_seen = true;
            uint8_t h[32];
            hmac_sha256(ch->secret, sizeof(ch->secret), ct, ctlen, h);
            if (h[0] == mac[0] && h[1] == mac[1]) {
                if (matched)
                    *matched = ch;
                return FWD_OK_GRP_PUBLIC;      /* proven public content */
            }
        }
        return hash_seen ? FWD_DROP_GRP_MACFAIL : FWD_DROP_GRP_UNMATCHED;
    }

    case PAYLOAD_TYPE_REQ:
    case PAYLOAD_TYPE_RESPONSE:
    case PAYLOAD_TYPE_TXT_MSG:
    case PAYLOAD_TYPE_ANON_REQ:
    case PAYLOAD_TYPE_PATH:
        return FWD_DROP_DM;                    /* pairwise-encrypted private unicast */

    default:                                   /* ack/multipart/control/raw/unknown */
        return FWD_DROP_OTHER;
    }
}

static const char *payload_type_name(uint8_t pt)
{
    switch (pt) {
    case PAYLOAD_TYPE_REQ:        return "REQ";
    case PAYLOAD_TYPE_RESPONSE:   return "RESPONSE";
    case PAYLOAD_TYPE_TXT_MSG:    return "TXT_MSG";
    case PAYLOAD_TYPE_ACK:        return "ACK";
    case PAYLOAD_TYPE_ADVERT:     return "ADVERT";
    case PAYLOAD_TYPE_GRP_TXT:    return "GRP_TXT";
    case PAYLOAD_TYPE_GRP_DATA:   return "GRP_DATA";
    case PAYLOAD_TYPE_ANON_REQ:   return "ANON_REQ";
    case PAYLOAD_TYPE_PATH:       return "PATH";
    case PAYLOAD_TYPE_TRACE:      return "TRACE";
    case PAYLOAD_TYPE_MULTIPART:  return "MULTIPART";
    case PAYLOAD_TYPE_CONTROL:    return "CONTROL";
    case PAYLOAD_TYPE_RAW_CUSTOM: return "RAW_CUSTOM";
    default:                      return "?";
    }
}

static const char *decision_reason(fwd_decision_t d)
{
    switch (d) {
    case FWD_DROP_DM:            return "private direct message";
    case FWD_DROP_GRP_UNMATCHED: return "group msg on an unconfigured channel";
    case FWD_DROP_GRP_MACFAIL:   return "group msg failed public-channel MAC";
    default:                     return "non-public payload type";
    }
}

/* ---- public-channel message codec (only used for CONFIGURED public keys) ---- */

/* Decrypt a public GRP_TXT into out (NUL-terminated). Returns plaintext length,
 * or -1. Caller must have MAC-verified the packet against `ch` already. */
static int channel_decrypt(const mc_pub_channel_t *ch, const mc_packet_t *pkt,
                           uint8_t *out, size_t outsz)
{
    if (pkt->payload_len < 19)
        return -1;
    size_t ctlen = (size_t)pkt->payload_len - 3;
    if (ctlen % 16 != 0 || ctlen + 1 > outsz)
        return -1;
    memcpy(out, &pkt->payload[3], ctlen);
    aes128_ctx_t ac;
    aes128_init(&ac, ch->secret);          /* AES key = first 16 bytes of secret */
    aes128_ecb_decrypt(&ac, out, ctlen);
    out[ctlen] = '\0';                     /* terminate at the padded end */
    return (int)ctlen;
}

/* MeshCore group-text plaintext: [timestamp:4][txt_type:1]["sender: message"].
 * Return a pointer to the message body (after the first ": "), or the whole
 * text if there is no separator; NULL if the plaintext is too short. */
static const char *grp_message_body(const uint8_t *plain, int plen)
{
    if (plen < 5)
        return NULL;
    const char *text = (const char *)&plain[5];
    const char *sep = strstr(text, ": ");
    return sep ? sep + 2 : text;
}

static bool is_ping(const char *msg)
{
    while (*msg == ' ' || *msg == '\t') msg++;
    if (strncasecmp(msg, "ping", 4) != 0)
        return false;
    const char *p = msg + 4;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return *p == '\0';                     /* exactly "ping" (+ trailing space) */
}

/* Build an encrypted public GRP_TXT carrying "sender: text". Returns 0 on ok. */
static int channel_build_txt(const mc_pub_channel_t *ch, const char *sender,
                             const char *text, uint32_t ts, mc_packet_t *pkt)
{
    uint8_t plain[MC_MAX_PACKET_PAYLOAD];
    size_t i = 0;
    wr_u32le(&plain[0], ts);  i = 4;
    plain[i++] = 0;                                    /* txt_type = plain */
    int n = snprintf((char *)&plain[i], sizeof(plain) - i, "%s: %s",
                     sender ? sender : "", text);
    if (n < 0)
        return -1;
    i += (size_t)n;                                    /* strlen, no NUL (matches MeshCore) */
    size_t ctlen = (i + 15) & ~(size_t)15;             /* zero-pad up to a 16-byte block */
    if (ctlen == 0) ctlen = 16;
    if (3 + ctlen > MC_MAX_PACKET_PAYLOAD)
        return -1;
    while (i < ctlen) plain[i++] = 0;

    aes128_ctx_t ac;
    aes128_init(&ac, ch->secret);
    aes128_ecb_encrypt(&ac, plain, ctlen);

    memset(pkt, 0, sizeof(*pkt));
    pkt->header   = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, ROUTE_TYPE_FLOOD);
    pkt->path_len = 0;                                 /* fresh flood, 1-byte hash size */
    pkt->payload[0] = ch->hash;
    uint8_t mac[32];
    hmac_sha256(ch->secret, sizeof(ch->secret), plain, ctlen, mac);
    pkt->payload[1] = mac[0];
    pkt->payload[2] = mac[1];
    memcpy(&pkt->payload[3], plain, ctlen);
    pkt->payload_len = (uint16_t)(3 + ctlen);
    return 0;
}

static void send_pong(mc_mesh_t *m, const mc_pub_channel_t *ch, int16_t rssi, int8_t snr_q)
{
    /* report the signal we heard the ping at, so it doubles as a coverage check */
    char txt[48];
    snprintf(txt, sizeof(txt), "pong rssi %ddBm snr %.1fdB", rssi, snr_q / 4.0);

    mc_packet_t pkt;
    if (channel_build_txt(ch, m->cfg->name, txt, (uint32_t)time(NULL), &pkt) != 0)
        return;
    /* record our own message so its echo is treated as a duplicate */
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    seen_check_and_add(m, hash);
    enqueue(m, &pkt, 1, hal_rng_int(0, 3) * 50);       /* small jitter */
    m->stats.pong_sent++;
    log_info("mesh: ping -> pong (rssi %d snr %.1f) on channel '%s'",
             rssi, snr_q / 4.0, ch->name[0] ? ch->name : "-");
}

/* Verbose display + ping/pong handling for an allowed public group message. */
static void handle_public_grp(mc_mesh_t *m, const mc_packet_t *pkt,
                              const mc_pub_channel_t *ch)
{
    if (pkt_payload_type(pkt) != PAYLOAD_TYPE_GRP_TXT) {
        if (m->cfg->verbose)
            log_info("[public %s] <data, %u bytes>", ch->name[0] ? ch->name : "-",
                     (unsigned)pkt->payload_len);
        return;
    }
    uint8_t plain[MC_MAX_PACKET_PAYLOAD];
    int plen = channel_decrypt(ch, pkt, plain, sizeof(plain));
    if (plen < 5)
        return;
    if (m->cfg->verbose)
        log_info("[public %s] %s", ch->name[0] ? ch->name : "-", (const char *)&plain[5]);

    if (m->cfg->ping_pong) {
        const char *body = grp_message_body(plain, plen);
        if (body && is_ping(body)) {
            m->stats.ping_seen++;
            send_pong(m, ch, pkt->rssi_dbm, pkt->snr_q);
        }
    }
}

void mesh_on_recv(mc_mesh_t *m, const uint8_t *raw, size_t len,
                  int16_t rssi_dbm, int8_t snr_q)
{
    mc_packet_t pkt;
    if (pkt_parse(&pkt, raw, len) != 0) {
        m->stats.rx_bad_parse++;
        return;
    }
    pkt.rssi_dbm = rssi_dbm;
    pkt.snr_q = snr_q;
    m->stats.rx_total++;

    /* dedup (records hash on first sight) */
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    if (seen_check_and_add(m, hash)) {
        m->stats.rx_dup++;
        return;
    }

    uint8_t pt = pkt_payload_type(&pkt);

    if (pt == PAYLOAD_TYPE_ADVERT) {
        uint8_t pub[MC_PUB_KEY_SIZE];
        if (!mc_advert_verify(&pkt, pub)) {
            m->stats.rx_advert_bad++;
            log_debug("mesh: dropped advert with bad signature");
            return; /* forged - do not propagate */
        }
        m->stats.rx_advert++;
        neighbor_update(m, pub, &pkt, rssi_dbm, snr_q);
        if (m->cfg->verbose) {
            uint8_t atype = 0; char aname[32];
            double lat, lon;
            mc_advert_extract(&pkt, &atype, aname, sizeof(aname));
            if (mc_advert_extract_location(&pkt, &lat, &lon))
                log_info("[advert] '%s' type=%u  loc %.5f,%.5f  rssi %d snr %.1f",
                         aname[0] ? aname : "?", atype, lat, lon, rssi_dbm, snr_q / 4.0);
            else
                log_info("[advert] '%s' type=%u  rssi %d snr %.1f",
                         aname[0] ? aname : "?", atype, rssi_dbm, snr_q / 4.0);
        }
    }

    if (pt == PAYLOAD_TYPE_TRACE) {
        /* TODO: MeshCore appends our SNR to the trace path and relays it.
         * Not yet implemented to avoid corrupting trace path semantics;
         * trace packets are counted but not forwarded by this node. */
        m->stats.trace_seen++;
        if (m->cfg->verbose)
            log_info("[trace] %u hops, rssi %d snr %.1f (not forwarded yet)",
                     pkt_path_hash_count(&pkt), rssi_dbm, snr_q / 4.0);
        return;
    }

    if (!m->cfg->forward)
        return;

    /* ham content policy: relay only provably-public traffic, drop the rest */
    const mc_pub_channel_t *pub_ch = NULL;
    fwd_decision_t decision = classify_forward(m, &pkt, &pub_ch);
    if (decision == FWD_OK_GRP_PUBLIC) {
        m->stats.fwd_grp_public++;
        handle_public_grp(m, &pkt, pub_ch);   /* verbose display + ping/pong */
    } else if (decision != FWD_OK_PUBLIC) {   /* a drop */
        m->stats.fwd_denied++;
        switch (decision) {
        case FWD_DROP_DM:            m->stats.fwd_denied_dm++; break;
        case FWD_DROP_GRP_UNMATCHED: m->stats.fwd_denied_grp++; break;
        case FWD_DROP_GRP_MACFAIL:   m->stats.fwd_denied_grp++; m->stats.grp_mac_fail++; break;
        default:                     m->stats.fwd_denied_other++; break;
        }
        if (m->cfg->verbose)
            log_info("[ignored] type=0x%02X dropped: %s", pt, decision_reason(decision));
        return;
    }

    if (pkt_is_route_flood(&pkt)) {
        uint8_t n  = pkt_path_hash_count(&pkt);
        uint8_t hs = pkt_path_hash_size(&pkt);
        if (!pkt.marked_dnr && (uint16_t)((n + 1) * hs) <= MC_MAX_PATH_SIZE) {
            /* append our path hash and bump the hop count */
            mc_identity_copy_hash(m->id, &pkt.path[n * hs], hs);
            pkt_set_path_hash_count(&pkt, (uint8_t)(n + 1));

            uint32_t raw_len = (uint32_t)pkt_raw_length(&pkt);
            uint32_t airtime = sx126x_airtime_ms(raw_len);
            uint32_t t = (airtime * 52 / 50) / 2;
            uint32_t delay = hal_rng_int(0, 5) * t;

            enqueue(m, &pkt, (uint8_t)(n + 1), delay); /* closer sources = higher priority */
            m->stats.fwd_flood++;
        } else {
            m->stats.fwd_dropped++;
        }
    } else { /* direct */
        uint8_t n  = pkt_path_hash_count(&pkt);
        uint8_t hs = pkt_path_hash_size(&pkt);
        if (n >= 1 && mc_identity_hash_match(m->id, pkt.path, hs)) {
            /* we are the next hop: strip ourselves from the front of the path */
            memmove(pkt.path, pkt.path + hs, (size_t)(n - 1) * hs);
            pkt_set_path_hash_count(&pkt, (uint8_t)(n - 1));
            enqueue(m, &pkt, 0, 0); /* routed traffic is highest priority, no delay */
            m->stats.fwd_direct++;
        }
        /* not addressed to us -> ignore */
    }
}

/* pick the most urgent due entry (lowest priority value, then earliest due) */
static int pick_due(mc_mesh_t *m, uint64_t now)
{
    int best = -1;
    for (int i = 0; i < MESH_TXQ_SIZE; i++) {
        if (!m->txq[i].used || m->txq[i].due_ms > now)
            continue;
        if (best < 0 ||
            m->txq[i].priority < m->txq[best].priority ||
            (m->txq[i].priority == m->txq[best].priority &&
             m->txq[i].due_ms < m->txq[best].due_ms)) {
            best = i;
        }
    }
    return best;
}

void mesh_service_tx(mc_mesh_t *m, uint64_t now_ms)
{
    int idx = pick_due(m, now_ms);
    if (idx < 0)
        return;

    mesh_tx_entry_t *e = &m->txq[idx];

    /* listen-before-talk */
    if (m->cfg->use_cad && sx126x_channel_busy() == 1) {
        m->stats.tx_cad_busy++;
        e->due_ms = now_ms + hal_rng_int(1, 4) * 120; /* CAD-fail backoff */
        return;
    }

    uint8_t raw[MC_MAX_TRANS_UNIT];
    int n = pkt_serialize(&e->pkt, raw, sizeof(raw));
    if (n > 0) {
        uint32_t airtime = sx126x_airtime_ms((size_t)n);
        int rc = sx126x_transmit(raw, (size_t)n, airtime + 1000);
        if (rc == 0) {
            m->stats.tx_total++;
            if (m->cfg->verbose)
                log_info("[tx] %s %s %dB %uhop airtime %ums",
                         payload_type_name(pkt_payload_type(&e->pkt)),
                         pkt_is_route_flood(&e->pkt) ? "flood" : "direct",
                         n, pkt_path_hash_count(&e->pkt), airtime);
        } else {
            log_warn("mesh: TX failed (rc=%d, len=%d)", rc, n);
        }
    }
    e->used = false; /* one shot - drop on serialise failure too */
}

int mesh_send_advert(mc_mesh_t *m)
{
    mc_advert_info_t info;
    memset(&info, 0, sizeof(info));
    info.type = ADV_TYPE_REPEATER;
    info.name = m->cfg->name;
    info.has_location = m->cfg->has_location;
    info.latitude = m->cfg->latitude;
    info.longitude = m->cfg->longitude;

    mc_packet_t pkt;
    if (mc_advert_build(&pkt, m->id, &info, (uint32_t)time(NULL)) != 0) {
        log_warn("mesh: could not build advert (no secret key?)");
        return -1;
    }

    /* record our own advert so a neighbour's echo is treated as a duplicate */
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    seen_check_and_add(m, hash);

    enqueue(m, &pkt, 0, hal_rng_int(0, 3) * 50); /* small jitter */
    m->stats.adverts_sent++;
    log_info("mesh: queued self-advert '%s'", m->cfg->name);
    return 0;
}

int mesh_neighbor_count(const mc_mesh_t *m)
{
    int c = 0;
    for (int i = 0; i < MESH_MAX_NEIGHBORS; i++)
        if (m->neighbors[i].used)
            c++;
    return c;
}
