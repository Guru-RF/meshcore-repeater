/* mesh.c - MeshCore repeater forwarding logic. */
#include "mesh.h"
#include "advert.h"
#include "sx126x.h"
#include "hal.h"
#include "log.h"
#include "util.h"
#include "hmac_sha256.h"
#include "aprsis.h"
#include "monitor.h"
#include "mbox.h"
#include "backbone.h"
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
    mbox_init(&m->mbox);
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
            n->hops = pkt_path_hash_count(pkt);
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
    n->hops = pkt_path_hash_count(pkt);
    mc_advert_extract(pkt, &n->type, n->name, sizeof(n->name));
}

/* Queue a packet for transmission. `own` = this node originated it (advert,
 * pong, ...) rather than relaying it. Everything queued is offered to the
 * backbone hub as a bridge candidate, except frames the hub sent us. */
static bool enqueue(mc_mesh_t *m, const mc_packet_t *pkt, uint8_t priority,
                    uint32_t delay_ms, int8_t power_dbm, bool own)
{
    uint64_t now = hal_millis();
    for (int i = 0; i < MESH_TXQ_SIZE; i++) {
        if (!m->txq[i].used) {
            m->txq[i].used = true;
            m->txq[i].pkt = *pkt;
            m->txq[i].priority = priority;
            m->txq[i].due_ms = now + delay_ms;
            m->txq[i].power_dbm = power_dbm;
            if (m->bb && m->rx_src != MESH_SRC_BACKBONE) {
                uint8_t raw[MC_MAX_TRANS_UNIT];
                int n = pkt_serialize(pkt, raw, sizeof(raw));
                if (n > 0)
                    backbone_offer(m->bb, raw, (size_t)n, own);
            }
            return true;
        }
    }
    m->stats.tx_queue_full++;
    log_warn("mesh: TX queue full, dropping packet (type=%u)", pkt_payload_type(pkt));
    return false;
}

int mesh_txq_free(const mc_mesh_t *m)
{
    int n = 0;
    for (int i = 0; i < MESH_TXQ_SIZE; i++)
        if (!m->txq[i].used)
            n++;
    return n;
}

/* Flood back-off: rand(0..5) slots of half the packet's airtime (+4%), as
 * MeshCore's Mesh::getRetransmitDelay. */
static uint32_t flood_backoff_ms(const mc_packet_t *pkt)
{
    uint32_t airtime = sx126x_airtime_ms((size_t)pkt_raw_length(pkt));
    uint32_t t = (airtime * 52 / 50) / 2;
    return hal_rng_int(0, 5) * t;
}

/* Delay before answering a command heard on air (pong, help, #mbox reply):
 * MeshCore's SERVER_RESPONSE_DELAY, so the sender is back in RX, plus a small
 * jitter. */
static uint32_t reply_delay_ms(void)
{
    return MESH_REPLY_DELAY_MS + hal_rng_int(0, 3) * 50;
}

/* Chip power for packets this node ORIGINATES (adverts, pongs). In hotspot
 * mode use the "high" level so they reach the repeater network. */
static int8_t own_tx_power(const mc_mesh_t *m)
{
    return (m->cfg->role == ROLE_HOTSPOT) ? m->cfg->hotspot_power_high : m->cfg->tx_power;
}

/* Emit a "[drop]" monitor event for a parsed packet (payload type + group
 * channel-hash inferred). No-op when no monitor is attached. */
static void mon_pkt_drop(mc_mesh_t *m, const mc_packet_t *pkt, const char *reason)
{
    if (!m->mon) return;
    uint8_t pt = pkt_payload_type(pkt);
    int chash = ((pt == PAYLOAD_TYPE_GRP_TXT || pt == PAYLOAD_TYPE_GRP_DATA) && pkt->payload_len >= 1)
                ? pkt->payload[0] : -1;
    monitor_drop(m->mon, pt, reason, chash);
}

/* Does the packet's path contain an affinity repeater's hash (came via the
 * mesh)? Used to pick downlink (low) vs uplink (high) power in hotspot mode. */
static bool path_has_affinity(const mc_mesh_t *m, const mc_packet_t *pkt)
{
    uint8_t n  = pkt_path_hash_count(pkt);
    uint8_t hs = pkt_path_hash_size(pkt);
    for (uint8_t h = 0; h < n; h++) {
        uint8_t b = pkt->path[h * hs];        /* 1-byte path hash = pub[0] */
        for (int i = 0; i < m->n_affinity_hash; i++)
            if (m->affinity_hash[i] == b)
                return true;
    }
    return false;
}

/* Learn an affinity repeater's path-hash (pub[0]) from its verified advert. */
static void learn_affinity(mc_mesh_t *m, const uint8_t pub[MC_PUB_KEY_SIZE])
{
    for (int i = 0; i < m->n_affinity_hash; i++)
        if (m->affinity_hash[i] == pub[0])
            return;
    if (m->n_affinity_hash < MC_MAX_AFFINITY)
        m->affinity_hash[m->n_affinity_hash++] = pub[0];
    else
        log_warn("mesh: affinity hash table full (%d) - downlink from further "
                 "repeaters may be misclassified; narrow the affinity list", MC_MAX_AFFINITY);
}

/*
 * Hotspot-role forwarding decision. A forwardable packet (per the ham content
 * policy) is further scoped to the operator's personal bridge, and its TX power
 * is set by direction: household->repeater (uplink) = full power (reach the
 * repeater), repeater->household (downlink) = lowest. Returns true to forward.
 *   - Adverts are classified by advertiser: an affinity repeater -> downlink;
 *     a home device (ON6URE*, friends) -> uplink; anyone else -> drop.
 *   - Group messages are classified by path: an affinity repeater in the path
 *     means it came from the mesh (downlink, forward all); otherwise it was
 *     heard locally (uplink) and is only bridged if its sender is a home device.
 */
static bool hotspot_decide(mc_mesh_t *m, const mc_packet_t *pkt,
                           const char *aname, const char *grp_sender, int8_t *power)
{
    uint8_t pt = pkt_payload_type(pkt);
    if (pt == PAYLOAD_TYPE_ADVERT) {
        if (config_is_affinity(m->cfg, aname)) { *power = m->cfg->hotspot_power_low;  return true; }
        if (config_is_home(m->cfg, aname))     { *power = m->cfg->hotspot_power_high; return true; }
        *power = m->cfg->hotspot_power_low;
        return false;                                  /* not our repeater or device */
    }
    if (path_has_affinity(m, pkt)) {                   /* came via a repeater -> downlink */
        *power = m->cfg->hotspot_power_low;
        return true;
    }
    /* A group message whose SENDER is an affinity repeater is that repeater's own
     * traffic (a pong/probe, or an mbox fetch reply routed back to us as a DIRECT
     * packet whose path holds only the downstream hops, not the repeater's hash)
     * -> downlink. This is what lets a routed reply reach a household device while
     * still dropping a stranger's DIRECT packet (whose sender is neither ours). */
    if (pt == PAYLOAD_TYPE_GRP_TXT && config_is_affinity(m->cfg, grp_sender)) {
        *power = m->cfg->hotspot_power_low;
        return true;
    }
    *power = m->cfg->hotspot_power_high;                /* heard locally -> uplink */
    if (pt == PAYLOAD_TYPE_GRP_TXT)
        return config_is_home(m->cfg, grp_sender);     /* only our devices (by sender) */
    /* GRP_DATA has no readable sender to scope by, so we can't confirm it is one
     * of ours -> don't uplink it (it still downlinks fine when it arrives via a
     * repeater). Everything else was already dropped by the content policy. */
    return false;
}

/* ---- strict ham content policy: forward public, drop private ---- */
typedef enum {
    FWD_OK_PUBLIC,        /* advert / trace (already sig-checked upstream) */
    FWD_OK_GRP_PUBLIC,    /* group message on a configured public channel */
    FWD_OK_REGION,        /* transport-flood tagged for a served #room region */
    FWD_DROP_DM,          /* private pairwise-encrypted unicast */
    FWD_DROP_GRP_UNMATCHED,/* group message on an unconfigured channel */
    FWD_DROP_GRP_MACFAIL, /* channel hash matched but the MAC did not verify */
    FWD_DROP_OTHER,       /* ack / control / multipart / raw / unknown types */
} fwd_decision_t;

/* MeshCore transport-region code: HMAC-SHA256(room_key, payload_type||payload)
 * truncated to 2 bytes, read as a little-endian uint16, with 0x0000/0xFFFF
 * reserved. Mirrors TransportKey::calcTransportCode. */
static uint16_t region_transport_code(const uint8_t key[16], uint8_t ptype,
                                      const uint8_t *payload, size_t plen)
{
    uint8_t msg[1 + MC_MAX_PACKET_PAYLOAD];
    if (plen > MC_MAX_PACKET_PAYLOAD)
        plen = MC_MAX_PACKET_PAYLOAD;
    msg[0] = ptype;
    memcpy(&msg[1], payload, plen);
    uint8_t h[32];
    hmac_sha256(key, 16, msg, 1 + plen, h);
    uint16_t code = (uint16_t)(h[0] | (h[1] << 8));
    if (code == 0)           code = 1;
    else if (code == 0xFFFF) code = 0xFFFE;
    return code;
}

/* Index of the configured #room (region) this packet is tagged for, or -1. A
 * match means it is a TRANSPORT_FLOOD whose transport code equals one of ours -
 * such group traffic is forwarded even without the channel key (the operator
 * declared that region public). */
static int region_match_index(const mc_mesh_t *m, const mc_packet_t *pkt)
{
    if (pkt_route_type(pkt) != ROUTE_TYPE_TRANSPORT_FLOOD)
        return -1;
    uint8_t ptype = pkt_payload_type(pkt);
    for (int i = 0; i < m->cfg->n_rooms; i++)
        if (region_transport_code(m->cfg->room_key[i], ptype,
                                  pkt->payload, pkt->payload_len) == pkt->transport_codes[0])
            return i;
    return -1;
}

static bool region_match(const mc_mesh_t *m, const mc_packet_t *pkt)
{
    return region_match_index(m, pkt) >= 0;
}

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
        /* Not on a channel we hold: still forward if it is a transport-flood
         * tagged for a #room region the operator has declared public. */
        if (region_match(m, pkt))
            return FWD_OK_REGION;
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

/* Parse "probe <secs> <count>" (or "probe stop"/"probe cancel" -> 0,0). Returns
 * true if the body is a probe command; secs and count get the (unclamped) args. */
static bool is_probe(const char *msg, int *secs, int *count)
{
    while (*msg == ' ' || *msg == '\t') msg++;
    if (strncasecmp(msg, "probe", 5) != 0)
        return false;
    const char *p = msg + 5;
    if (*p != ' ' && *p != '\t' && *p != '\0')
        return false;                       /* "probeXYZ" is not the command */
    while (*p == ' ' || *p == '\t') p++;
    if (!strncasecmp(p, "stop", 4) || !strncasecmp(p, "cancel", 6)) {
        *secs = 0; *count = 0; return true;
    }
    int s = 0, c = 0;
    if (sscanf(p, "%d %d", &s, &c) == 2) {
        *secs = s; *count = c; return true;
    }
    return false;
}

/* Body is exactly `word` (leading/trailing whitespace ok), e.g. "time" / "date". */
static bool is_word(const char *msg, const char *word)
{
    size_t wl = strlen(word);
    while (*msg == ' ' || *msg == '\t') msg++;
    if (strncasecmp(msg, word, wl) != 0)
        return false;
    const char *p = msg + wl;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return *p == '\0';
}

/* Build an encrypted public GRP_TXT carrying "sender: text". Returns 0 on ok. */
static int channel_build_txt(const mc_pub_channel_t *ch, const char *sender,
                             const char *text, uint32_t ts, uint8_t route_type,
                             mc_packet_t *pkt)
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
    pkt->header   = pkt_make_header(PAYLOAD_VER_1, PAYLOAD_TYPE_GRP_TXT, route_type);
    pkt->path_len = 0;                                 /* empty path (FLOOD: fresh; DIRECT: zero-hop/local) */
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
    if (channel_build_txt(ch, m->cfg->name, txt, (uint32_t)time(NULL), ROUTE_TYPE_FLOOD, &pkt) != 0)
        return;
    /* record our own message so its echo is treated as a duplicate */
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    seen_check_and_add(m, hash);
    enqueue(m, &pkt, 1, reply_delay_ms(), own_tx_power(m), true);
    m->stats.pong_sent++;
    log_info("mesh: ping -> pong (rssi %d snr %.1f) on channel '%s'",
             rssi, snr_q / 4.0, ch->name[0] ? ch->name : "-");
}

/* Arm a #mesh "time"/"date" broadcast for the NEXT minute boundary. Transmitting
 * exactly when a new minute starts gives clockless devices an exact reference (the
 * HH:MM has zero seconds). Requests within the same minute coalesce into one send;
 * the channel is copied so a config reload can't dangle it. */
static void tod_arm(mc_mesh_t *m, const mc_pub_channel_t *ch, bool want_time, bool want_date)
{
    if (!m->tod_time_pending && !m->tod_date_pending)
        m->tod_minute = (uint32_t)(time(NULL) / 60);   /* remember now; fire on the next rollover */
    m->tod_ch = *ch;
    if (want_time) m->tod_time_pending = true;
    if (want_date) m->tod_date_pending = true;
}

/* Flood a time/date line on the armed #mesh channel (originated, like a pong). */
static void send_tod(mc_mesh_t *m, const char *text)
{
    mc_packet_t pkt;
    if (channel_build_txt(&m->tod_ch, m->cfg->name, text, (uint32_t)time(NULL), ROUTE_TYPE_FLOOD, &pkt) != 0)
        return;
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    seen_check_and_add(m, hash);                        /* our own echo is a dup */
    enqueue(m, &pkt, 1, hal_rng_int(0, 3) * 50, own_tx_power(m), true);
    m->stats.timeofday_sent++;
}

#define MESH_HELP_COOLDOWN_MS  8000   /* min gap between "help" summaries (anti-spam) */

/* Answer "help" on the ping channel with a one-line summary of the commands that
 * are currently enabled. Floods like a pong so any listener sees it. */
static void send_help(mc_mesh_t *m, const mc_pub_channel_t *ch)
{
    char txt[160];
    snprintf(txt, sizeof(txt), "commands:%s%s%s help",
             m->cfg->ping_pong         ? " ping(alive)"                  : "",
             m->cfg->timeofday_enable  ? " time/date(UTC clock)"         : "",
             m->cfg->n_probe_allow > 0 ? " probe<secs count>(range,auth)" : "");
    mc_packet_t pkt;
    if (channel_build_txt(ch, m->cfg->name, txt, (uint32_t)time(NULL), ROUTE_TYPE_FLOOD, &pkt) != 0)
        return;
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    seen_check_and_add(m, hash);
    enqueue(m, &pkt, 1, reply_delay_ms(), own_tx_power(m), true);
    m->stats.help_sent++;
}

#define MBOX_REPLY_COOLDOWN_MS  8000   /* min gap between local mbox replies (anti-spam) */

/* Reply to a command by routing a DIRECT group message back along the REVERSE of
 * the path the command took, so it reaches the sender through any intermediate
 * hops (e.g. a personal hotspot) WITHOUT flooding the mesh. A command heard
 * directly (empty path) gets a zero-hop reply that only direct-range nodes see.
 *
 * Verified vs MeshCore: a flood appends each forwarder's hash at the BACK, so a
 * command arrives with path [H1..Hk] (H1 = first forwarder nearest the source,
 * Hk = last forwarder nearest us). A DIRECT packet is consumed front-first
 * (path[0] = next hop, stripped on forward), so to travel us->Hk->..->H1->source
 * the reply's path must be the reverse [Hk..H1], with path[0] = Hk. */
static bool send_routed_reply(mc_mesh_t *m, const mc_packet_t *rx,
                              const mc_pub_channel_t *ch, const char *text)
{
    mc_packet_t pkt;
    if (channel_build_txt(ch, m->cfg->name, text, (uint32_t)time(NULL), ROUTE_TYPE_DIRECT, &pkt) != 0)
        return false;                     /* too long to encode -> tell the caller nothing went out */

    uint8_t n  = pkt_path_hash_count(rx);
    uint8_t hs = pkt_path_hash_size(rx);
    if (n > 0 && (uint16_t)(n * hs) <= MC_MAX_PATH_SIZE) {
        for (uint8_t i = 0; i < n; i++)                 /* reverse: path[0] = the hop closest to us */
            memcpy(&pkt.path[i * hs], &rx->path[(size_t)(n - 1 - i) * hs], hs);
        pkt.path_len = (uint8_t)((((hs - 1) & 0x03) << 6) | (n & 0x3F));
    }

    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    seen_check_and_add(m, hash);          /* seed dedup so we don't display/re-forward our own echo */
    return enqueue(m, &pkt, 1, reply_delay_ms(), own_tx_power(m), true);
}

/* Per-sender reply rate-limit: at most one #mbox reply per base call per cooldown,
 * so a chatty/hostile station can't starve everyone else's fetch. Records the gate
 * and returns true when a reply is allowed now; false while still cooling down. */
static bool mbox_rate_ok(mc_mesh_t *m, const char *sender, uint64_t now)
{
    char base[MC_MBOX_CALL];
    size_t i = 0;
    while (sender && sender[i] && sender[i] != '-' && i + 1 < sizeof(base)) { base[i] = sender[i]; i++; }
    base[i] = '\0';
    if (base[0] == '\0')
        return false;                     /* no sender name -> can't address a mailbox, and an empty
                                             base must not masquerade as a free (unthrottled) gate slot */

    int free_slot = -1, oldest = 0;
    for (int k = 0; k < (int)(sizeof(m->mbox_gate) / sizeof(m->mbox_gate[0])); k++) {
        if (m->mbox_gate[k].call[0] == '\0') { if (free_slot < 0) free_slot = k; continue; }
        if (strcasecmp(m->mbox_gate[k].call, base) == 0) {
            if (now < m->mbox_gate[k].next_ms) return false;   /* this sender is still cooling down */
            m->mbox_gate[k].next_ms = now + MBOX_REPLY_COOLDOWN_MS;
            return true;
        }
        if (m->mbox_gate[k].next_ms < m->mbox_gate[oldest].next_ms) oldest = k;
    }
    int slot = (free_slot >= 0) ? free_slot : oldest;          /* reuse a free slot, else evict stalest */
    snprintf(m->mbox_gate[slot].call, sizeof(m->mbox_gate[slot].call), "%s", base);
    m->mbox_gate[slot].next_ms = now + MBOX_REPLY_COOLDOWN_MS;
    return true;
}

/* #mbox handling on the repeater. Returns true if the message should still flood
 * normally (an @mention is a message for the network), false if not (a fetch/help
 * command is answered by a routed reply and is not itself re-flooded). `pkt` is
 * the received command whose path is reversed to route the reply back. */
static bool mbox_handle(mc_mesh_t *m, const mc_packet_t *pkt,
                        const mc_pub_channel_t *ch, const char *sender, const char *body)
{
    char mention[MC_MBOX_CALL];
    const char *msg = NULL;
    mbox_cmd_t cmd = mbox_classify(body, mention, sizeof(mention), &msg);

    if (cmd == MBOX_MENTION) {
        mbox_store(&m->mbox, mention, sender, msg, (uint32_t)time(NULL));
        m->stats.mbox_stored++;
        return true;                      /* stored; the message still floods normally */
    }

    /* fetch / anything-else -> a reply routed back to the sender (rate-limited PER
     * sender so it can't be spammed); the command itself is not re-flooded. */
    if (!mbox_rate_ok(m, sender, hal_millis()))
        return false;

    /* msgs is sized so "name: mbox NN/NN: <msgs>" fits one packet even for a long
     * repeater name; send_routed_reply still guards the encode as a backstop. */
    char reply[160];
    if (cmd == MBOX_FETCH) {
        char msgs[110];
        int total = 0;
        int shown = mbox_format_fetch(&m->mbox, sender, msgs, sizeof(msgs), &total);
        if (total == 0)         snprintf(reply, sizeof(reply), "mbox: no messages for you");
        else if (shown == 0)    snprintf(reply, sizeof(reply), "mbox: %d msg(s) for you, too long to show here", total);
        else if (shown < total) snprintf(reply, sizeof(reply), "mbox %d/%d: %s", shown, total, msgs);
        else                    snprintf(reply, sizeof(reply), "mbox %d: %s", total, msgs);
    } else {
        snprintf(reply, sizeof(reply), "%s", mbox_help_text());
    }
    if (send_routed_reply(m, pkt, ch, reply))   /* count only a reply that actually went out */
        m->stats.mbox_replies++;
    return false;
}

#define MESH_PROBE_MAX_SECS   3600
#define MESH_PROBE_MAX_COUNT  100

void mesh_start_probe(mc_mesh_t *m, const mc_pub_channel_t *ch, int secs, int count)
{
    if (count <= 0) {                                    /* stop/cancel */
        if (m->probe_remaining > 0) log_info("probe: cancelled");
        m->probe_remaining = 0;
        return;
    }
    if (secs  < 1)                    secs  = 1;
    if (secs  > MESH_PROBE_MAX_SECS)  secs  = MESH_PROBE_MAX_SECS;
    if (count > MESH_PROBE_MAX_COUNT) count = MESH_PROBE_MAX_COUNT;
    m->probe_ch          = *ch;                          /* copy: reload-safe */
    m->probe_interval_ms = (uint32_t)secs * 1000u;
    m->probe_total       = count;
    m->probe_remaining   = count;
    m->probe_seq         = 0;
    m->probe_next_ms     = hal_millis() + MESH_REPLY_DELAY_MS; /* first one once the operator is back in RX */
    log_info("probe: %d x every %ds on '%s'", count, secs, ch->name[0] ? ch->name : "-");
}

void mesh_service_probe(mc_mesh_t *m, uint64_t now_ms)
{
    if (m->probe_remaining <= 0 || now_ms < m->probe_next_ms)
        return;
    m->probe_seq++;
    char txt[48];
    snprintf(txt, sizeof(txt), "probe %d/%d", m->probe_seq, m->probe_total);
    mc_packet_t pkt;
    if (channel_build_txt(&m->probe_ch, m->cfg->name, txt, (uint32_t)time(NULL), ROUTE_TYPE_FLOOD, &pkt) == 0) {
        uint8_t hash[MC_MAX_HASH_SIZE];
        pkt_calc_hash(&pkt, hash);
        seen_check_and_add(m, hash);                     /* our echo is a dup */
        enqueue(m, &pkt, 1, hal_rng_int(0, 3) * 50, own_tx_power(m), true);
        m->stats.probes_sent++;
    }
    m->probe_remaining--;
    m->probe_next_ms = now_ms + m->probe_interval_ms;
}

void mesh_service_timeofday(mc_mesh_t *m, uint64_t now_ms)
{
    (void)now_ms;
    if (!m->tod_time_pending && !m->tod_date_pending)
        return;
    time_t t = time(NULL);
    uint32_t minute = (uint32_t)(t / 60);
    if (minute == m->tod_minute)              /* still the same minute: wait for the tick */
        return;
    m->tod_minute = minute;                   /* a new minute just started - answer now */

    struct tm g;
    gmtime_r(&t, &g);
    char txt[40];
    if (m->tod_time_pending) {                /* HH:MM, no seconds (it is :00 right now) */
        snprintf(txt, sizeof(txt), "time %02d:%02d UTC", g.tm_hour, g.tm_min);
        send_tod(m, txt);
        m->tod_time_pending = false;
        log_info("mesh: time -> %s on '%s'", txt, m->tod_ch.name[0] ? m->tod_ch.name : "-");
    }
    if (m->tod_date_pending) {
        snprintf(txt, sizeof(txt), "date %04d-%02d-%02d", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday);
        send_tod(m, txt);
        m->tod_date_pending = false;
        log_info("mesh: date -> %s on '%s'", txt, m->tod_ch.name[0] ? m->tod_ch.name : "-");
    }
}

/* Copy the self-reported sender name (the text before the first ": "). */
static void grp_sender_name(const uint8_t *plain, char *out, size_t outsz)
{
    const char *text = (const char *)&plain[5];
    const char *sep = strstr(text, ": ");
    size_t n = sep ? (size_t)(sep - text) : 0;
    if (n >= outsz) n = outsz - 1;
    memcpy(out, text, n);
    out[n] = '\0';
}

/* Verbose display, blacklist check and ping/pong for an allowed public group
 * message. Returns 1 to forward it, 0 if a command here consumed it (not
 * re-flooded), -1 if the sender is blacklisted (drop). A frame from the
 * backbone gets no local services: the repeater that heard it answers. */
static int process_public_grp(mc_mesh_t *m, const mc_packet_t *pkt,
                              const mc_pub_channel_t *ch,
                              char *sender_out, size_t sender_sz)
{
    if (sender_out && sender_sz) sender_out[0] = '\0';
    if (pkt_payload_type(pkt) != PAYLOAD_TYPE_GRP_TXT) {
        if (m->cfg->verbose)
            log_info("[public %s] <data, %u bytes>", ch->name[0] ? ch->name : "-",
                     (unsigned)pkt->payload_len);
        return 1;                       /* can't read a sender; forward */
    }
    uint8_t plain[MC_MAX_PACKET_PAYLOAD];
    int plen = channel_decrypt(ch, pkt, plain, sizeof(plain));
    if (plen < 5)
        return 1;                       /* undecodable; forward as-is */

    char sender[MC_BLACKLIST_NAME_LEN];
    grp_sender_name(plain, sender, sizeof(sender));
    if (sender_out && sender_sz) snprintf(sender_out, sender_sz, "%s", sender);
    if (config_is_blacklisted(m->cfg, sender)) {
        m->stats.blacklisted++;
        if (m->cfg->verbose)
            log_info("[ignored] blacklisted '%s' on %s", sender, ch->name[0] ? ch->name : "-");
        mon_pkt_drop(m, pkt, "blacklisted sender");
        return -1;                      /* drop: no forward, no pong */
    }

    if (m->cfg->verbose)
        log_info("[public %s] %s%s", ch->name[0] ? ch->name : "-", (const char *)&plain[5],
                 m->rx_src == MESH_SRC_BACKBONE ? "  (via backbone)" : "");
    if (m->mon)
        monitor_public(m->mon, ch->name, (const char *)&plain[5], pkt->rssi_dbm, pkt->snr_q);
    if (m->rx_src == MESH_SRC_BACKBONE)
        return 1;                       /* no local services for frames from the hub */

    const char *body = grp_message_body(plain, plen);
    if (body) {
        /* ping/pong and probe live on the ping channel (default "#mesh"); an
         * empty ping_channel means any public channel. */
        bool on_ping_ch = (m->cfg->ping_channel[0] == '\0' ||
                           strcmp(ch->name, m->cfg->ping_channel) == 0);
        int secs, count;
        if (m->cfg->ping_pong && is_ping(body)) {
            m->stats.ping_seen++;
            if (on_ping_ch)
                send_pong(m, ch, pkt->rssi_dbm, pkt->snr_q);
        } else if (on_ping_ch && m->cfg->n_probe_allow > 0 &&
                   is_probe(body, &secs, &count) && config_probe_allowed(m->cfg, sender)) {
            /* an authorised operator starts a coverage/range test from a device */
            log_info("probe: requested by '%s' (%ds x %d)", sender, secs, count);
            mesh_start_probe(m, ch, secs, count);
        } else if (on_ping_ch && m->cfg->timeofday_enable && is_word(body, "time")) {
            tod_arm(m, ch, true, false);   /* answered at the next minute boundary */
        } else if (on_ping_ch && m->cfg->timeofday_enable && is_word(body, "date")) {
            tod_arm(m, ch, false, true);
        } else if (on_ping_ch && is_word(body, "help")) {
            uint64_t now = hal_millis();
            if (!m->mesh_help_next_ms || now >= m->mesh_help_next_ms) {   /* anti-spam / coalesce */
                send_help(m, ch);
                m->mesh_help_next_ms = now + MESH_HELP_COOLDOWN_MS;
            }
        } else if (m->cfg->mbox_enable && m->cfg->role != ROLE_HOTSPOT &&
                   pkt_is_route_flood(pkt) && strcmp(ch->name, "#mbox") == 0) {
            /* the mailbox lives on the repeater: store @mentions (still flooded),
             * route a fetch/help reply back (and don't re-flood the command). A
             * hotspot does NOT run the mailbox - it forwards #mbox up to the
             * repeater like any other public channel. Only FLOOD packets are
             * commands: our routed reply comes back as a DIRECT packet and must
             * pass through untouched (else another mbox repeater on the path would
             * "help"-reply to it). */
            return mbox_handle(m, pkt, ch, sender, body) ? 1 : 0;
        }
    }
    return 1;
}

void mesh_on_rx_error(mc_mesh_t *m, int kind, int16_t rssi_dbm, int8_t snr_q)
{
    char reason[64];
    if (kind == SX126X_RX_CRC_ERR) {
        m->stats.rx_crc_err++;
        snprintf(reason, sizeof(reason), "CRC error (rssi %d snr %.1f)", rssi_dbm, snr_q / 4.0);
    } else {
        m->stats.rx_hdr_err++;
        snprintf(reason, sizeof(reason), "corrupt LoRa header");
    }
    if (m->mon) monitor_drop(m->mon, 0xFF, reason, -1);
}

int mesh_on_recv(mc_mesh_t *m, const uint8_t *raw, size_t len,
                 int16_t rssi_dbm, int8_t snr_q)
{
    bool rf = (m->rx_src != MESH_SRC_BACKBONE);   /* RF-only counters, services, neighbours */
    if (rf)
        m->stats.rx_airtime_ms += sx126x_airtime_ms(len);

    mc_packet_t pkt;
    if (pkt_parse(&pkt, raw, len) != 0) {
        if (rf)
            m->stats.rx_bad_parse++;
        if (m->mon) monitor_drop(m->mon, 0xFF, "parse error (malformed frame)", -1);
        return MESH_RX_MALFORMED;
    }
    pkt.rssi_dbm = rssi_dbm;
    pkt.snr_q = snr_q;
    if (rf)
        m->stats.rx_total++;

    /* dedup (records hash on first sight) */
    uint8_t hash[MC_MAX_HASH_SIZE];
    pkt_calc_hash(&pkt, hash);
    if (seen_check_and_add(m, hash)) {
        if (rf)
            m->stats.rx_dup++;
        mon_pkt_drop(m, &pkt, "duplicate (already seen)");
        return MESH_RX_DUPLICATE;
    }

    if (rf && pkt_route_type(&pkt) == ROUTE_TYPE_TRANSPORT_FLOOD)
        m->stats.rx_transport_flood++;      /* diagnostic: is the mesh using Transport? */

    uint8_t pt = pkt_payload_type(&pkt);
    uint8_t atype = 0; char aname[32] = "";                 /* advert name/type (hotspot) */
    char grp_sender[MC_BLACKLIST_NAME_LEN] = "";            /* decrypted public sender (hotspot) */

    if (pt == PAYLOAD_TYPE_ADVERT) {
        uint8_t pub[MC_PUB_KEY_SIZE];
        if (!mc_advert_verify(&pkt, pub)) {
            if (rf)
                m->stats.rx_advert_bad++;
            log_debug("mesh: dropped advert with bad signature");
            mon_pkt_drop(m, &pkt, "advert: bad signature");
            return MESH_RX_POLICY; /* forged - do not propagate */
        }
        mc_advert_extract(&pkt, &atype, aname, sizeof(aname));
        if (config_is_blacklisted(m->cfg, aname)) {
            m->stats.blacklisted++;
            if (m->cfg->verbose)
                log_info("[ignored] blacklisted advert '%s'", aname);
            mon_pkt_drop(m, &pkt, "advert: blacklisted sender");
            return MESH_RX_POLICY; /* don't register as a neighbour, don't re-flood */
        }
        if (rf) {                  /* the neighbour table is what this radio hears */
            m->stats.rx_advert++;
            neighbor_update(m, pub, &pkt, rssi_dbm, snr_q);
            if (m->cfg->role == ROLE_HOTSPOT && config_is_affinity(m->cfg, aname))
                learn_affinity(m, pub);   /* remember its path-hash for downlink detection */
        }

        double lat, lon;
        bool has_loc = mc_advert_extract_location(&pkt, &lat, &lon);
        if (m->cfg->verbose) {
            char sig[32];
            if (rf) snprintf(sig, sizeof(sig), "rssi %d snr %.1f", rssi_dbm, snr_q / 4.0);
            else    snprintf(sig, sizeof(sig), "via backbone");
            if (has_loc)
                log_info("[advert] '%s' type=%u  loc %.5f,%.5f  %s",
                         aname[0] ? aname : "?", atype, lat, lon, sig);
            else
                log_info("[advert] '%s' type=%u  %s", aname[0] ? aname : "?", atype, sig);
        }
        if (m->mon)
            monitor_advert(m->mon, aname, atype, has_loc, lat, lon, rssi_dbm, snr_q);
        /* APRS-IS iGate: gate a node's advertised position (validated inside). Only
         * what this radio heard: the hub's frames were gated where they were heard. */
        if (rf && m->aprs && has_loc)
            aprsis_gate_node(m->aprs, hal_millis(), aname, atype, lat, lon, pub);
    }

    if (pt == PAYLOAD_TYPE_TRACE) {
        /* TODO: MeshCore appends our SNR to the trace path and relays it.
         * Not yet implemented to avoid corrupting trace path semantics;
         * trace packets are counted but not forwarded by this node. */
        if (rf)
            m->stats.trace_seen++;
        if (m->cfg->verbose)
            log_info("[trace] %u hops, rssi %d snr %.1f (not forwarded yet)",
                     pkt_path_hash_count(&pkt), rssi_dbm, snr_q / 4.0);
        mon_pkt_drop(m, &pkt, "trace (not forwarded yet)");
        return MESH_RX_LOCAL;
    }

    if (!m->cfg->forward)
        return MESH_RX_LOCAL;

    /* ham content policy: relay only provably-public traffic, drop the rest */
    const mc_pub_channel_t *pub_ch = NULL;
    fwd_decision_t decision = classify_forward(m, &pkt, &pub_ch);
    if (decision == FWD_OK_GRP_PUBLIC) {
        int g = process_public_grp(m, &pkt, pub_ch, grp_sender, sizeof(grp_sender));
        if (g < 0)
            return MESH_RX_POLICY;                  /* blacklisted sender -> don't forward */
        if (g == 0)
            return MESH_RX_LOCAL;                   /* a command answered here, not re-flooded */
        m->stats.fwd_grp_public++;
    } else if (decision == FWD_OK_REGION) {
        /* region-tagged group traffic: forwarded opaquely (no key to decrypt) */
        m->stats.fwd_region++;
        if (m->cfg->verbose)
            log_info("[region] relaying type=0x%02X for a served #room (opaque)", pt);
        if (m->mon) {
            int ri = region_match_index(m, &pkt);
            if (ri >= 0)
                monitor_region(m->mon, m->cfg->rooms[ri], pt, pkt.payload_len,
                               rssi_dbm, snr_q);
        }
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
        mon_pkt_drop(m, &pkt, decision_reason(decision));
        return MESH_RX_POLICY;
    }

    /* hotspot role: scope to the personal bridge + pick direction-dependent power.
     * Applies to FLOOD and routed DIRECT alike - hotspot_decide downlinks a routed
     * reply from an affinity repeater (an mbox fetch reply) and still drops
     * anything out of the personal scope, so a stranger cannot use the hotspot as a
     * general DIRECT relay. */
    int8_t tx_power = m->cfg->tx_power;
    if (m->cfg->role == ROLE_HOTSPOT) {
        if (!hotspot_decide(m, &pkt, aname, grp_sender, &tx_power)) {
            if (m->cfg->verbose)
                log_info("[hotspot] not forwarding type=0x%02X (out of personal scope)", pt);
            mon_pkt_drop(m, &pkt, "hotspot: out of personal scope");
            return MESH_RX_POLICY;
        }
    }

    if (pkt_is_route_flood(&pkt)) {
        uint8_t n  = pkt_path_hash_count(&pkt);
        uint8_t hs = pkt_path_hash_size(&pkt);
        if (!pkt.marked_dnr && (uint16_t)((n + 1) * hs) <= MC_MAX_PATH_SIZE) {
            /* append our path hash and bump the hop count */
            mc_identity_copy_hash(m->id, &pkt.path[n * hs], hs);
            pkt_set_path_hash_count(&pkt, (uint8_t)(n + 1));

            /* closer sources = higher priority */
            if (!enqueue(m, &pkt, (uint8_t)(n + 1), flood_backoff_ms(&pkt), tx_power, false))
                return MESH_RX_LOCAL;
            m->stats.fwd_flood++;
            return MESH_RX_FORWARDED;
        }
        m->stats.fwd_dropped++;
        mon_pkt_drop(m, &pkt, pkt.marked_dnr ? "do-not-retransmit" : "path full");
        return MESH_RX_LOCAL;
    }

    /* direct */
    uint8_t n  = pkt_path_hash_count(&pkt);
    uint8_t hs = pkt_path_hash_size(&pkt);
    if (n >= 1 && mc_identity_hash_match(m->id, pkt.path, hs)) {
        /* we are the next hop: strip ourselves from the front of the path */
        memmove(pkt.path, pkt.path + hs, (size_t)(n - 1) * hs);
        pkt_set_path_hash_count(&pkt, (uint8_t)(n - 1));
        /* routed traffic is highest priority, no delay */
        if (!enqueue(m, &pkt, 0, 0, tx_power, false))
            return MESH_RX_LOCAL;
        m->stats.fwd_direct++;
        return MESH_RX_FORWARDED;
    }
    return MESH_RX_LOCAL;                           /* not addressed to us -> ignore */
}

int mesh_on_backbone(mc_mesh_t *m, const uint8_t *raw, size_t len)
{
    int saved = m->rx_src;
    m->rx_src = MESH_SRC_BACKBONE;
    int r = mesh_on_recv(m, raw, len, MON_VIA_BACKBONE, 0);
    m->rx_src = saved;
    return r;
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

/* Emit a "[tx]" monitor event for a packet we just transmitted. A group message
 * on a channel we hold is decrypted so its text shows (our own pong/help/time as
 * well as the public messages we relay); an advert shows the advertiser's name. */
static void mon_pkt_tx(mc_mesh_t *m, const mc_packet_t *pkt, int len_b,
                       int power_dbm, uint32_t airtime_ms)
{
    if (!m->mon || monitor_count(m->mon) == 0) return;   /* nobody watching: skip the decrypt */
    char detail[MC_MAX_PACKET_PAYLOAD + 48];
    detail[0] = '\0';
    uint8_t pt = pkt_payload_type(pkt);
    const mc_pub_channel_t *ch = NULL;
    if (pt == PAYLOAD_TYPE_GRP_TXT &&
        classify_forward(m, pkt, &ch) == FWD_OK_GRP_PUBLIC && ch) {
        uint8_t plain[MC_MAX_PACKET_PAYLOAD];
        if (channel_decrypt(ch, pkt, plain, sizeof(plain)) >= 5)
            snprintf(detail, sizeof(detail), "[%s] %s",
                     ch->name[0] ? ch->name : "-", (const char *)&plain[5]);
    } else if (pt == PAYLOAD_TYPE_ADVERT) {
        char name[32];
        if (mc_advert_extract(pkt, NULL, name, sizeof(name)) == 0 && name[0])
            snprintf(detail, sizeof(detail), "'%s'", name);
    }
    monitor_tx(m->mon, payload_type_name(pt), pkt_is_route_flood(pkt), (unsigned)len_b,
               pkt_path_hash_count(pkt), power_dbm, airtime_ms, detail);
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
        sx126x_set_tx_power(e->power_dbm);        /* per-packet power (hotspot asymmetry) */
        uint32_t airtime = sx126x_airtime_ms((size_t)n);
        int rc = sx126x_transmit(raw, (size_t)n, airtime + 1000);
        if (rc == 0) {
            m->stats.tx_total++;
            m->stats.tx_airtime_ms += airtime;
            if (m->cfg->verbose)
                log_info("[tx] %s %s %dB %uhop %ddBm airtime %ums",
                         payload_type_name(pkt_payload_type(&e->pkt)),
                         pkt_is_route_flood(&e->pkt) ? "flood" : "direct",
                         n, pkt_path_hash_count(&e->pkt), e->power_dbm, airtime);
            mon_pkt_tx(m, &e->pkt, n, e->power_dbm, airtime);
        } else {
            /* A healthy radio always finishes within the airtime, so a failed TX
             * means the chip is wedged - and a wedged chip is usually deaf too.
             * Reset it now rather than waiting for more failures: a deaf
             * repeater originates little (an advert per interval), so a
             * threshold could leave it stuck for hours. */
            m->stats.tx_failed++;
            m->stats.radio_resets++;
            log_warn("mesh: TX failed (rc=%d, len=%d) - resetting the radio", rc, n);
            if (sx126x_reinit() != 0)
                log_err("mesh: radio re-init failed - check the radio hardware");
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

    enqueue(m, &pkt, 0, hal_rng_int(0, 3) * 50, own_tx_power(m), true); /* small jitter */
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
