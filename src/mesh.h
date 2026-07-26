/*
 * mesh.h - the repeater core.
 *
 * Responsibilities (verified against MeshCore Mesh.cpp / Dispatcher):
 *   - dedup received packets via an 8-byte SHA256 hash ring (160 entries)
 *   - flood forwarding: append our 1-byte path hash, retransmit after a
 *     randomised airtime-based delay (CSMA), bounded by the 64-byte path
 *   - direct forwarding: if we are path[0], strip ourselves and retransmit
 *   - verify Ed25519 signatures on ADVERTs before re-flooding them
 *   - emit periodic signed self-adverts (type REPEATER)
 *   - keep stats + a neighbour table for the local CLI
 *
 * The repeater never decrypts payloads. Under the strict ham content policy it
 * forwards only what is provably NOT obscured: signed adverts, plaintext traces
 * and group messages on a configured PUBLIC channel (verified by the channel
 * MAC). Private unicast (DMs/requests) and unknown-key channels are dropped.
 */
#ifndef MC_MESH_H
#define MC_MESH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "packet.h"
#include "identity.h"
#include "config.h"

#define MESH_SEEN_SIZE      160   /* MeshCore MAX_PACKET_HASHES (128+32) */
#define MESH_TXQ_SIZE        24
#define MESH_MAX_NEIGHBORS   96

typedef struct {
    uint64_t rx_total;
    uint64_t rx_bad_parse;
    uint64_t rx_dup;
    uint64_t rx_advert;
    uint64_t rx_advert_bad;
    uint64_t fwd_flood;
    uint64_t fwd_direct;
    uint64_t fwd_dropped;     /* path full / forwarding disabled */
    uint64_t trace_seen;
    /* ham content policy (strict "forward public, drop private") */
    uint64_t fwd_grp_public;  /* group messages relayed on a public channel */
    uint64_t fwd_denied;      /* total packets dropped by the policy */
    uint64_t fwd_denied_dm;   /*   ...private unicast (req/resp/txt/anon/path) */
    uint64_t fwd_denied_grp;  /*   ...group message on a non-public channel */
    uint64_t fwd_denied_other;/*   ...ack/control/multipart/raw/unknown */
    uint64_t grp_mac_fail;    /* channel-hash matched a public chan but MAC failed */
    uint64_t ping_seen;       /* "ping" received on a public channel */
    uint64_t pong_sent;       /* "pong" answers transmitted */
    uint64_t blacklisted;     /* packets dropped from blacklisted senders */
    uint64_t tx_total;
    uint64_t tx_cad_busy;
    uint64_t tx_queue_full;
    uint64_t adverts_sent;
} mesh_stats_t;

typedef struct {
    bool     used;
    uint8_t  pub[MC_PUB_KEY_SIZE];
    char     name[32];
    uint8_t  type;
    int16_t  rssi;
    int8_t   snr_q;
    uint32_t last_seen;       /* UNIX seconds */
    uint32_t count;
} mesh_neighbor_t;

typedef struct {
    bool        used;
    mc_packet_t pkt;
    uint64_t    due_ms;       /* monotonic ms when eligible to TX */
    uint8_t     priority;     /* lower = sent first */
} mesh_tx_entry_t;

typedef struct {
    const mc_identity_t *id;
    const mc_config_t   *cfg;

    uint8_t  seen[MESH_SEEN_SIZE][MC_MAX_HASH_SIZE];
    int      seen_idx;

    mesh_tx_entry_t txq[MESH_TXQ_SIZE];
    mesh_neighbor_t neighbors[MESH_MAX_NEIGHBORS];

    mesh_stats_t stats;
    uint64_t     start_ms;

    struct mc_aprsis *aprs;   /* APRS-IS iGate (NULL = feature disabled) */
} mc_mesh_t;

void mesh_init(mc_mesh_t *m, const mc_identity_t *id, const mc_config_t *cfg);

/* Handle a freshly received raw packet (rssi/snr from the radio). */
void mesh_on_recv(mc_mesh_t *m, const uint8_t *raw, size_t len,
                  int16_t rssi_dbm, int8_t snr_q);

/* Transmit any due queue entries (handles CAD/backoff). Call every loop. */
void mesh_service_tx(mc_mesh_t *m, uint64_t now_ms);

/* Build + enqueue a signed self-advert. Returns 0 on success. */
int  mesh_send_advert(mc_mesh_t *m);

/* Count active neighbours. */
int  mesh_neighbor_count(const mc_mesh_t *m);

#endif /* MC_MESH_H */
