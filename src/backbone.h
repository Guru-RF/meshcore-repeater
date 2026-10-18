/*
 * backbone.h - optional IP fallback backbone to a central hub (UDP).
 *
 * The repeater opens a UDP session to the hub (it sits behind NAT), signs a
 * HELLO with its MeshCore Ed25519 identity, and checks a WELCOME signed by the
 * hub key pinned in the config. An X25519 exchange in that handshake gives
 * per-direction HMAC-SHA256 keys; every later datagram carries a session id, a
 * sequence number (64-wide replay window) and a 16-byte MAC.
 *
 * Two roles, enabled separately:
 *   observe - uplink every frame heard on RF (+ rssi/snr), and a periodic
 *             status + neighbour report. Read-only.
 *   bridge  - offer the frames this repeater transmits to the hub, and transmit
 *             frames the hub sends down. A frame from the hub goes through
 *             mesh_on_recv like an RF frame (dedup ring + content policy), is
 *             never offered back up, and never triggers local services.
 *
 * Fallback: when the hub is unreachable the repeater runs exactly as without
 * the backbone. Nothing here blocks the radio loop (DNS is getaddrinfo_a).
 *
 * The wire format is specified in docs/backbone.md (the contract for the hub).
 */
#ifndef MC_BACKBONE_H
#define MC_BACKBONE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netdb.h>
#include <netinet/in.h>
#include "config.h"
#include "identity.h"

#define BB_VERSION        1
#define BB_MAX_DGRAM   1200      /* fits a 1280-byte IPv6 / 4G path MTU */
#define BB_MAX_FRAME    255      /* a LoRa frame */
#define BB_HDR           12      /* session header: magic(2) ver(1) type(1) sid(4) seq(4) */
#define BB_MAC           16
#define BB_HELLO_FIXED   75      /* HELLO bytes before the name */
#define BB_WELCOME_LEN  148
#define BB_RESET_LEN     80
#define BB_NAME_MAX      32

/* datagram types (docs/backbone.md, "Datagram types") */
enum {
    BB_T_HELLO      = 0x01,     /* R->H, Ed25519-signed */
    BB_T_WELCOME    = 0x02,     /* H->R, Ed25519-signed */
    BB_T_RESET      = 0x03,     /* H->R, Ed25519-signed */
    BB_T_KEEPALIVE  = 0x10,     /* R->H, session MAC */
    BB_T_OBSERVE    = 0x11,
    BB_T_BRIDGE     = 0x12,
    BB_T_STATUS     = 0x13,
    BB_T_NEIGHBOURS = 0x14,
    BB_T_BYE        = 0x1F,
    BB_T_KEEPALIVE_ACK = 0x20,  /* H->R, session MAC */
    BB_T_FRAME      = 0x21,
    BB_T_POLICY     = 0x22,     /* H->R: central rooms and blocks */
    BB_T_BYE_DOWN   = 0x2F,
};

#define BB_ROLE_OBSERVE 0x01
#define BB_ROLE_BRIDGE  0x02

#define BB_OBS_FROM_BACKBONE 0x01   /* OBSERVE flag: frame came from the hub, not RF */

/* POLICY entry kinds and page limit */
#define BB_POL_ROOM        1
#define BB_POL_BLOCK_NAME  2
#define BB_POL_BLOCK_KEY   3
#define BB_POL_MAX_PAGES  16
#define BB_BRIDGE_OWN        0x01   /* BRIDGE flag: originated by this repeater */

/* OBSERVE disposition: 0..3 are mesh_on_recv's own results (mesh.h). */
enum { BB_DISP_FORWARDED = 0, BB_DISP_DUPLICATE = 1, BB_DISP_POLICY = 2,
       BB_DISP_LOCAL = 3, BB_DISP_LIMITED = 4 };

/* BYE reasons */
enum { BB_BYE_SHUTDOWN = 0, BB_BYE_REKEY = 1, BB_BYE_DISABLED = 2, BB_BYE_NOT_ALLOWED = 3 };

/* ---- codec (pure functions; the self-test also plays the hub with them) ---- */

typedef struct {
    uint32_t top;               /* highest sequence number accepted */
    uint64_t bits;              /* bit i = top - i already seen */
} bb_replay_t;

typedef struct {
    uint8_t  roles;
    uint32_t ts;
    uint32_t sid;
    uint8_t  eph_pub[32];
    uint16_t keepalive_s, status_s, neighbours_s;
} bb_welcome_t;

/* HELLO: returns its length, or 0 if out is too small / signing failed. */
size_t bb_build_hello(uint8_t *out, size_t cap, const mc_identity_t *id, uint8_t roles,
                      uint32_t ts, const uint8_t eph_pub[32], const char *name);
/* WELCOME, signed with the hub identity (used by the self-test's hub). */
size_t bb_build_welcome(uint8_t *out, size_t cap, const mc_identity_t *hub,
                        const bb_welcome_t *w, const uint8_t hello_hash[32]);
/* Check a WELCOME against the pinned hub key and the HELLO it answers.
 * Returns 0 and fills *w, or <0. */
int    bb_check_welcome(const uint8_t *d, size_t len, const uint8_t hub_pub[32],
                        const uint8_t hello_hash[32], uint8_t roles_asked, bb_welcome_t *w);
size_t bb_build_reset(uint8_t *out, size_t cap, const mc_identity_t *hub,
                      uint32_t sid, uint32_t seq, uint32_t ts);
/* Check a RESET's signature and fields; fills sid/seq/ts. Returns 0 or <0. */
int    bb_check_reset(const uint8_t *d, size_t len, const uint8_t hub_pub[32],
                      uint32_t *sid, uint32_t *seq, uint32_t *ts);

/* k_up / k_down from the X25519 secret and the two handshake datagrams.
 * Returns -1 if the shared secret is all zero (a low-order point). */
int    bb_derive_keys(const uint8_t shared[32], const uint8_t *hello, size_t hello_len,
                      const uint8_t *welcome, size_t welcome_len,
                      uint8_t k_up[32], uint8_t k_down[32]);

/* Session datagram: header + body + MAC. Returns its length, or 0. */
size_t bb_seal(uint8_t *out, size_t cap, uint8_t type, uint32_t sid, uint32_t seq,
               const uint8_t *body, size_t blen, const uint8_t key[32]);
/* Verify a session datagram's MAC (no replay check). Returns 0 and fills the
 * fields, or <0. */
int    bb_open(const uint8_t *d, size_t len, const uint8_t key[32], uint8_t *type,
               uint32_t *sid, uint32_t *seq, const uint8_t **body, size_t *blen);

/* Accept seq once (64-wide window). Returns true and records it, or false. */
bool   bb_replay_check(bb_replay_t *w, uint32_t seq);

/* ---- the repeater's client ---- */

struct mc_mesh;

typedef enum {
    BB_OFF = 0,     /* disabled, or misconfigured */
    BB_IDLE,        /* waiting to (re)connect (backoff) */
    BB_RESOLVING,   /* async DNS in flight */
    BB_HELLO_SENT,  /* waiting for WELCOME */
    BB_UP,          /* session established */
} bb_state_t;

typedef struct mc_backbone {
    mc_config_t         *cfg;           /* mutable: POLICY merges the hub's rooms and blocks */
    const mc_identity_t *id;
    struct mc_mesh      *mesh;      /* status/neighbours source + frame sink */
    uint8_t   hub_pub[32];
    uint8_t   roles_asked;

    bb_state_t state;
    int        fd;                  /* UDP socket connect()ed to the hub (-1 = none) */
    struct sockaddr_in addr;
    bool       have_addr;

    /* async DNS (getaddrinfo_a); the buffers must outlive the request */
    struct gaicb    gai;
    struct addrinfo gai_hints;
    char            gai_host[96];
    char            gai_port[8];
    bool            gai_busy;

    uint64_t  next_try_ms;          /* IDLE: when to start the next attempt */
    uint64_t  deadline_ms;          /* HELLO_SENT: WELCOME timeout */
    int       backoff_s;
    int       hello_tries;          /* HELLOs sent in this attempt */

    /* handshake */
    uint8_t   eph_sec[32];
    uint8_t   hello[BB_HELLO_FIXED + BB_NAME_MAX + 64];
    size_t    hello_len;
    uint8_t   hello_hash[32];
    uint32_t  last_hello_ts;        /* HELLO ts strictly increases */

    /* session */
    uint32_t  sid;
    uint8_t   roles;                /* granted */
    uint8_t   k_up[32], k_down[32];
    uint32_t  seq_out;
    bb_replay_t rwin;
    uint16_t  keepalive_s, status_s, neighbours_s;
    uint64_t  up_since_ms, last_rx_ms;
    uint64_t  next_keepalive_ms, next_status_ms, next_neighbours_ms;
    uint64_t  last_reset_ms;

    /* bridge rate limit (token bucket, frames per minute) */
    double    tokens;
    uint64_t  tokens_ms;

    /* POLICY pages being collected into one set (docs/backbone.md) */
    mc_policy_t pol;                /* the set being collected */
    uint8_t   pol_pages;            /* 0 = not collecting */
    uint16_t  pol_have;             /* bit (page-1) per page held */
    uint32_t  pol_min_seq, pol_max_seq;   /* over the pages held */
    uint32_t  pol_applied_seq;      /* lowest seq of the set last applied this session (0 = none) */

    /* counters */
    uint64_t  sessions;             /* sessions established */
    uint64_t  dgrams_out, dgrams_in;
    uint64_t  observed;             /* OBSERVE sent */
    uint64_t  offered;              /* BRIDGE sent */
    uint64_t  injected;             /* FRAME accepted and handed to the mesh */
    uint64_t  limited;              /* FRAME refused by the rate limit / queue headroom */
    uint64_t  rejected;             /* datagrams dropped: bad MAC, replay, unknown, malformed */
} mc_backbone;

/* Set up from config (off unless backbone = true). Returns 0, or -1 on a
 * misconfiguration (state forced OFF, reason logged). Never blocks. */
int  backbone_init(mc_backbone *bb, mc_config_t *cfg, const mc_identity_t *id,
                   struct mc_mesh *mesh);
/* Send BYE (if up) and close. */
void backbone_close(mc_backbone *bb);

/* fd to poll for input, or -1. */
int  backbone_pollfd(const mc_backbone *bb);
/* Advance timers, read datagrams, inject bridged frames. Call every loop. */
void backbone_service(mc_backbone *bb, uint64_t now_ms);

/* Hooks from the mesh / main loop (no-ops unless the session is up and the
 * role was granted). */
void backbone_observe(mc_backbone *bb, const uint8_t *frame, size_t len,
                      int16_t rssi, int8_t snr_q, uint8_t flags, int disposition);
void backbone_offer(mc_backbone *bb, const uint8_t *frame, size_t len, bool own);
/* Send STATUS on the next service tick instead of at its interval (a state the
 * hub acts on changed, such as a hotspot going RF silent or waking). */
void backbone_status_soon(mc_backbone *bb);

bool backbone_up(const mc_backbone *bb);
const char *backbone_state_name(const mc_backbone *bb);

#endif /* MC_BACKBONE_H */
