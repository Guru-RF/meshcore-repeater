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

#define MC_MAX_PUBLIC_CHANNELS 16   /* explicit channels + room-derived channels share this */
#define MC_MAX_BLACKLIST       32
#define MC_BLACKLIST_NAME_LEN  32
#define MC_MAX_AFFINITY        16   /* several repeaters in range (redundancy / mesh) */
#define MC_MAX_HOME            8
#define MC_MAX_ROOMS           8    /* transport "hashtag rooms" (MeshCore regions) */
#define MC_ROOM_NAME_LEN       32
#define MC_MAX_PROBE_ALLOW     8    /* callsign patterns allowed to run `probe` */
#define MC_NAME_PAT_LEN        32   /* >= aname[32]/MC_BLACKLIST_NAME_LEN so exact patterns match */

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
    int      n_rooms;

    /* ---- moderation + control interface ---- */
    char     blacklist[MC_MAX_BLACKLIST][MC_BLACKLIST_NAME_LEN]; /* ignored node names */
    int      n_blacklist;
    uint16_t control_port;       /* TCP 127.0.0.1 control port (0 = disabled) */

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
} mc_config_t;

/* Case-insensitive name match; a trailing '*' in pattern is a prefix wildcard. */
bool config_name_matches(const char *pattern, const char *name);
bool config_is_home(const mc_config_t *cfg, const char *name);
bool config_is_affinity(const mc_config_t *cfg, const char *name);
bool config_probe_allowed(const mc_config_t *cfg, const char *name);

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
