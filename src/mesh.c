/* mesh.c - MeshCore repeater forwarding logic. */
#include "mesh.h"
#include "advert.h"
#include "sx126x.h"
#include "hal.h"
#include "log.h"
#include "util.h"
#include "hmac_sha256.h"

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
static fwd_decision_t classify_forward(const mc_mesh_t *m, const mc_packet_t *pkt)
{
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
            if (h[0] == mac[0] && h[1] == mac[1])
                return FWD_OK_GRP_PUBLIC;      /* proven public content */
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

/* Returns true if the packet is allowed to forward; bumps the policy stats. */
static bool policy_permits(mc_mesh_t *m, const mc_packet_t *pkt)
{
    switch (classify_forward(m, pkt)) {
    case FWD_OK_PUBLIC:
        return true;
    case FWD_OK_GRP_PUBLIC:
        m->stats.fwd_grp_public++;
        return true;
    case FWD_DROP_DM:
        m->stats.fwd_denied++; m->stats.fwd_denied_dm++; return false;
    case FWD_DROP_GRP_UNMATCHED:
        m->stats.fwd_denied++; m->stats.fwd_denied_grp++; return false;
    case FWD_DROP_GRP_MACFAIL:
        m->stats.fwd_denied++; m->stats.fwd_denied_grp++; m->stats.grp_mac_fail++; return false;
    case FWD_DROP_OTHER:
    default:
        m->stats.fwd_denied++; m->stats.fwd_denied_other++; return false;
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
    }

    if (pt == PAYLOAD_TYPE_TRACE) {
        /* TODO: MeshCore appends our SNR to the trace path and relays it.
         * Not yet implemented to avoid corrupting trace path semantics;
         * trace packets are counted but not forwarded by this node. */
        m->stats.trace_seen++;
        return;
    }

    if (!m->cfg->forward)
        return;

    /* ham content policy: relay only provably-public traffic, drop the rest */
    if (!policy_permits(m, &pkt))
        return;

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
        if (rc == 0)
            m->stats.tx_total++;
        else
            log_warn("mesh: TX failed (rc=%d, len=%d)", rc, n);
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
