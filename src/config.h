/*
 * config.h - runtime configuration (loaded from a file, mutable via the CLI).
 *
 * Every radio parameter is runtime-driven: retune without recompiling.
 * Defaults follow the IARU R1 ham-MeshCore RFC
 * (github.com/Guru-RF/meshcore-rfc-iaru-r1) so the repeater joins that network
 * out of the box and interoperates with stock MeshCore nodes.
 */
#ifndef MC_CONFIG_H
#define MC_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sx126x.h"
#include "hal.h"

#define MC_MAX_PUBLIC_CHANNELS 48   /* explicit channels + room-derived (local and hub) share this */
#define MC_MAX_BLACKLIST       32
#define MC_BLACKLIST_NAME_LEN  32
#define MC_MAX_AFFINITY        16   /* several repeaters in range (redundancy / mesh) */
#define MC_MAX_HOME            8
#define MC_MAX_ROOMS           40   /* transport "hashtag rooms" (MeshCore regions), local + hub */
#define MC_ROOM_NAME_LEN       32
#define MC_MAX_PROBE_ALLOW     8    /* callsign patterns allowed to run `probe` */
#define MC_NAME_PAT_LEN        32   /* >= aname[32]/MC_BLACKLIST_NAME_LEN so exact patterns match */
#define MC_POLICY_MAX_ROOMS    32   /* backbone hub POLICY limits (docs/backbone.md) */
#define MC_POLICY_MAX_BLOCKS   256

/* The rooms and blocks the backbone hub sent (POLICY, docs/backbone.md) as one
 * set. Kept apart from the file's own lists: merged on top of them, never saved
 * to the config file, and kept across a reload. */
typedef struct {
    uint32_t version;                                     /* 0 = no set */
    int      n_rooms;
    char     rooms[MC_POLICY_MAX_ROOMS][MC_ROOM_NAME_LEN];  /* "#name", exactly as hashed */
    int      n_names;
    char     names[MC_POLICY_MAX_BLOCKS][MC_BLACKLIST_NAME_LEN];
    int      n_keys;
    uint8_t  keys[MC_POLICY_MAX_BLOCKS][32];              /* Ed25519 public keys */
    int      skipped;                                     /* entries over the limits above */
} mc_policy_t;

/* Operating role: a full licensed wide-area repeater, or a personal hotspot that
 * bridges the operator's own devices to the repeater network with direction-
 * dependent TX power (full up to the repeater, lowest down to the household). */
typedef enum { ROLE_REPEATER = 0, ROLE_HOTSPOT = 1 } mc_role_t;

/* A public MeshCore channel the operator has declared forwardable. The AES key
 * is PUBLISHED, so relaying its group messages does not obscure meaning. */
typedef struct {
    char     name[MC_ROOM_NAME_LEN]; /* friendly label; holds a full #room name */
    uint8_t  secret[32];      /* channel PSK, zero-padded (16-byte keys use [0..15]) */
    uint8_t  secret_len;      /* 16 (AES-128) or 32 */
    uint8_t  hash;            /* SHA256(secret, secret_len)[0] = on-air channel selector */
    bool     derived;         /* auto-derived from a #room name; not written back to file */
    bool     hub;             /* added for a room from the backbone hub (POLICY) */
} mc_pub_channel_t;

typedef struct {
    /* ---- radio ---- */
    double   frequency;          /* MHz */
    double   bandwidth;          /* kHz (62.5/125/250/500) */
    uint8_t  spreading_factor;   /* 5..12 */
    uint8_t  coding_rate;        /* 5..8 (=4/5..4/8) */
    int8_t   tx_power;           /* SX1268 chip dBm (-9..22) */
    uint16_t preamble;           /* symbols */
    uint16_t sync_word;          /* 2-byte LoRa sync reg; 0x1424 = MeshCore PRIVATE */
    bool     crc_on;
    bool     iq_inverted;
    bool     use_cad;            /* listen-before-talk */
    double   tcxo_voltage;       /* DIO3 TCXO control voltage (0 = none) */
    uint8_t  ocp_reg;            /* over-current protection register raw value */

    /* ---- hardware wiring ---- */
    char     spi_dev[64];
    uint32_t spi_speed;          /* Hz */
    char     gpio_chip[32];
    unsigned gpio_reset, gpio_busy, gpio_dio1, gpio_nss;
    bool     rf_switch_dio2;     /* true: chip drives DIO2 as antenna switch (no RXEN/TXEN) */
    unsigned gpio_rxen, gpio_txen;
    bool     use_leds;
    unsigned gpio_led_on;        /* status LED (solid while running) */
    unsigned gpio_led_data;      /* activity LED (pulses on RX/TX) */

    /* ---- node / mesh ---- */
    char     name[40];
    char     key_file[256];
    bool     has_location;
    double   latitude, longitude;
    uint32_t advert_interval;    /* seconds between self-adverts (0 = disabled) */
    bool     forward;            /* act as a repeater (allow packet forwarding) */
    bool     ping_pong;          /* answer "ping" on a public channel with "pong" */
    char     ping_channel[MC_ROOM_NAME_LEN]; /* only answer ping here (e.g. "#mesh"); empty = any */
    /* callsign patterns allowed to trigger `probe <secs> <count>` on the ping channel
     * (a coverage/range test). Empty list = feature off (nobody may run it). */
    char     probe_allow[MC_MAX_PROBE_ALLOW][MC_NAME_PAT_LEN];
    int      n_probe_allow;
    bool     mbox_enable;        /* enable the #mbox mailbox room (stores @mentions) */
    bool     timeofday_enable;   /* answer "time"/"date" on the ping channel (#mesh) */
    bool     verbose;            /* -v: log public messages, adverts, and drops (runtime only) */

    /* ---- ham content policy ----
     * Strict "forward public, drop private": only adverts, traces and group
     * messages on one of these declared PUBLIC channels are retransmitted. */
    mc_pub_channel_t public_channels[MC_MAX_PUBLIC_CHANNELS];
    int              n_public_channels;

    /* ---- transport "hashtag rooms" (MeshCore regions / flood-scopes) ----
     * Additive to the strict channel policy: forward group traffic tagged for a
     * region we serve, WITHOUT holding the channel key, because the operator has
     * declared that "#name" region public. A packet matches when it is a
     * TRANSPORT_FLOOD whose transport_codes[0] equals
     * HMAC-SHA256(room_key, payload_type||payload)[0..1] (little-endian). */
    char     rooms[MC_MAX_ROOMS][MC_ROOM_NAME_LEN];  /* normalised, includes leading '#' */
    uint8_t  room_key[MC_MAX_ROOMS][16];             /* SHA256(name)[0..15] */
    bool     room_hub[MC_MAX_ROOMS];                 /* added from the hub's POLICY set */
    int      n_rooms;

    /* ---- central rooms and blocks from the backbone hub ---- */
    bool        backbone_policy;       /* take POLICY from the hub (default true) */
    char        backbone_policy_file[128];  /* where the applied set is kept across restarts */
    mc_policy_t policy;                /* the applied set (version 0 = none) */
    int         policy_rooms;          /* hub rooms being served */
    int         policy_skipped;        /* entries this node couldn't hold */

    /* ---- moderation + control interface ---- */
    char     blacklist[MC_MAX_BLACKLIST][MC_BLACKLIST_NAME_LEN]; /* ignored node names */
    int      n_blacklist;
    uint16_t control_port;       /* TCP 127.0.0.1 control port (0 = disabled) */

    /* ---- split RX/TX over IP (optional; default single-node) ----
     * rx: this node only receives and relays each frame (+ its rssi/snr) over UDP
     *     to the tx node; it never transmits. tx: this node listens for relayed
     *     frames from one or more rx nodes, injects them into the mesh, and does
     *     all the forwarding/TX. Datagrams are HMAC-authenticated with link_key. */
    char     link_mode[8];       /* "off" | "rx" | "tx" */
    char     link_key[64];       /* shared secret; HMAC key = SHA256(this) */
    char     link_peer[64];      /* rx mode: TX-node host to relay frames to */
    uint16_t link_port;          /* UDP port (default 4404) */

    /* ---- IP backbone to a central hub (optional; docs/backbone.md) ----
     * observe: uplink heard frames + status; bridge: offer/transmit frames the hub
     * relays between RF islands. A fallback: with the hub down nothing changes. */
    bool     backbone_enable;
    char     backbone_host[96];  /* hub host name or IPv4 address */
    uint16_t backbone_port;      /* hub UDP port (default 4405) */
    uint8_t  backbone_hub_key[32]; /* hub Ed25519 public key (pinned) */
    bool     backbone_have_hub_key;
    bool     backbone_observe;
    bool     backbone_bridge;
    uint32_t backbone_rate;      /* max frames from the hub transmitted per minute */

    /* ---- APRS-IS RX iGate: gate adverts-with-coordinates to APRS-IS ---- */
    bool     aprs_enable;
    char     aprs_call[16];      /* login + own-beacon source SSID call (e.g. ON6URE-6) */
    char     aprs_passcode[12];  /* "auto" (compute) | decimal | -1 (receive-only) */
    char     aprs_host[96];      /* APRS-IS Tier-2 server */
    uint16_t aprs_port;
    char     aprs_tocall[12];    /* software id / destination (APRFGR) */
    char     aprs_symbol[8];     /* iGate map symbol "table+code" (R&) */
    char     aprs_node_symbol[8];/* gated-node symbol (Mn) */
    char     aprs_comment[96];   /* own-beacon comment (/A= appended) */
    double   aprs_altitude;      /* metres, for the /A= field */
    uint32_t aprs_beacon_interval; /* seconds between own beacons (0 = off) */
    uint32_t aprs_node_rate;     /* min seconds between re-gating the same node */

    /* ---- role: repeater vs personal hotspot ---- */
    mc_role_t role;
    /* real repeater callsigns this hotspot bridges to (path direction = "from mesh") */
    char     affinity[MC_MAX_AFFINITY][MC_NAME_PAT_LEN];
    int      n_affinity;
    /* own/friend device name patterns (wildcards, e.g. "ON6URE*") the hotspot uplinks */
    char     home[MC_MAX_HOME][MC_NAME_PAT_LEN];
    int      n_home;
    int8_t   hotspot_power_high; /* uplink chip dBm (household->repeater; full power to reach it) */
    int8_t   hotspot_power_low;  /* downlink chip dBm (repeater->household; lowest usable, <100 mW) */
    uint32_t hotspot_awake;      /* s on the air after a companion is heard directly; 0 = always on */

    /* ---- web admin page (web/meshcore-web.py; the daemon only keeps these) ---- */
    uint16_t web_port;           /* plain HTTP on the LAN; 0 = off */
    char     web_password[64];   /* user 'admin'; empty = web admin off */
} mc_config_t;

/* Case-insensitive name match; a trailing '*' in pattern is a prefix wildcard. */
bool config_name_matches(const char *pattern, const char *name);
bool config_is_home(const mc_config_t *cfg, const char *name);
bool config_is_affinity(const mc_config_t *cfg, const char *name);
bool config_probe_allowed(const mc_config_t *cfg, const char *name);

/* Central rooms and blocks (backbone POLICY). config_set_policy takes a new set:
 * entries that would block this node itself (its name or own_pub) are dropped
 * and logged, then the hub rooms are merged on top of the file's rooms.
 * config_load re-merges the kept set after a reload. */
void config_set_policy(mc_config_t *cfg, const mc_policy_t *p, const uint8_t own_pub[32]);
bool config_is_key_blocked(const mc_config_t *cfg, const uint8_t pub[32]);
/* Keep / restore the applied set in backbone_policy_file. 0 = ok. */
int  config_policy_save(const mc_config_t *cfg);
int  config_policy_load(mc_config_t *cfg, const uint8_t own_pub[32]);
/* ASCII-only case-insensitive equality (bytes 0x80+ compare exactly). */
bool config_ascii_eq(const char *a, const char *b);

/* Validate the node name against its role. A repeater IDs with a bare callsign;
 * a hotspot MAY append an SSID "-NN" (00..99) so one operator can run several,
 * each a distinct on-air ID. Returns true if acceptable, else false with a short
 * reason in *why. Only the "-NN" convention is enforced (the base callsign shape
 * is the operator's business - the installer checks that at setup time). */
bool config_valid_node_name(const char *name, mc_role_t role, char *why, size_t whysz);

void config_defaults(mc_config_t *cfg);

/* Load key=value lines from path over the current contents.
 * Returns 0 on success, -1 if the file could not be opened. */
int  config_load(mc_config_t *cfg, const char *path);

/* Persist the current config to path. Returns 0 on success. */
int  config_save(const mc_config_t *cfg, const char *path);

/* Set one key. Returns 0 ok, -1 unknown key, -2 invalid value. */
int  config_set(mc_config_t *cfg, const char *key, const char *val);

/* Read one key into out (human form). Returns 0 ok, -1 unknown key. */
int  config_get(const mc_config_t *cfg, const char *key, char *out, size_t outsz);

/* Blacklist (ignore a node by its advertised / public-channel name).
 * add: 0 ok, -1 full, 1 already present. remove: 0 ok, -1 not found. */
int  config_blacklist_add(mc_config_t *cfg, const char *name);
int  config_blacklist_remove(mc_config_t *cfg, const char *name);
bool config_is_blacklisted(const mc_config_t *cfg, const char *name);

/* Project config onto the radio / HAL parameter structs. */
void config_to_sx126x(const mc_config_t *cfg, sx126x_cfg_t *radio);
void config_to_hal(const mc_config_t *cfg, hal_config_t *hal);

#endif /* MC_CONFIG_H */
