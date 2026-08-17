/* config.c - load / save / get / set the repeater configuration. */
#include "config.h"
#include "log.h"
#include "util.h"
#include "crypto/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void config_defaults(mc_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    /* radio defaults: IARU R1 ham-MeshCore RFC (github.com/Guru-RF/meshcore-rfc-iaru-r1)
     * = MeshCore stock Europe profile with the frequency moved to the 70 cm calling QRG.
     * NB: must not emit above 435.000 MHz (protects the amateur-satellite segment). */
    cfg->frequency        = 434.890;   /* MHz - IARU R1 ham-MeshCore calling frequency */
    cfg->bandwidth        = 62.5;      /* kHz - occupied ~434.859..434.921 MHz */
    cfg->spreading_factor = 8;
    cfg->coding_rate      = 8;         /* 4/8 */
    cfg->tx_power         = 22;        /* SX1268 chip max; the hat's PA reaches +30 dBm (1 W) */
    cfg->preamble         = 16;
    cfg->sync_word        = 0x1424;    /* MeshCore default (RadioLib 0x12 expanded) */
    cfg->crc_on           = true;
    cfg->iq_inverted      = false;
    cfg->use_cad          = true;
    cfg->tcxo_voltage     = 1.6;
    cfg->ocp_reg          = 0x38;      /* 140 mA */

    /* hardware wiring (BCM numbers - defaults match the NiceRF LoRa1262F30/SX126x
     * reference schematic; NSS is a manual GPIO, antenna switch is DIO2-internal) */
    snprintf(cfg->spi_dev, sizeof(cfg->spi_dev), "%s", "/dev/spidev0.0");
    cfg->spi_speed = 2000000;          /* 2 MHz (<= 10 MHz) */
    snprintf(cfg->gpio_chip, sizeof(cfg->gpio_chip), "%s", "gpiochip0");
    cfg->gpio_reset = 18;              /* NRST */
    cfg->gpio_busy  = 20;              /* BUSY */
    cfg->gpio_dio1  = 16;              /* DIO1 */
    cfg->gpio_nss   = 21;              /* NSS (manual chip-select) */
    cfg->rf_switch_dio2 = true;        /* SX126x drives DIO2 as the antenna switch */
    cfg->gpio_rxen  = 23;              /* only used if rf_switch_dio2 = false */
    cfg->gpio_txen  = 22;
    cfg->use_leds   = true;
    cfg->gpio_led_on   = 19;           /* "ON" status LED */
    cfg->gpio_led_data = 26;           /* "DATA" activity LED */

    /* node */
    snprintf(cfg->name, sizeof(cfg->name), "%s", "HamRepeater");
    snprintf(cfg->key_file, sizeof(cfg->key_file), "%s", "repeater.key");
    cfg->has_location    = false;
    cfg->latitude        = 0.0;
    cfg->longitude       = 0.0;
    cfg->advert_interval = 1800;       /* 30 min: mandatory ham >=1 ID/hour, w/ margin */
    cfg->forward         = true;
    cfg->ping_pong       = true;       /* answer "ping" with "pong" (on the ping channel) */
    snprintf(cfg->ping_channel, sizeof(cfg->ping_channel), "%s", "#mesh"); /* built-in test channel */
    cfg->verbose         = false;      /* set at runtime by the -v flag */
    cfg->control_port    = 4403;       /* local control interface on 127.0.0.1 (0 = off) */

    /* APRS-IS RX iGate (off by default; own beacon reuses latitude/longitude) */
    cfg->aprs_enable         = false;
    cfg->aprs_call[0]        = '\0';
    snprintf(cfg->aprs_passcode, sizeof(cfg->aprs_passcode), "%s", "auto");
    snprintf(cfg->aprs_host, sizeof(cfg->aprs_host), "%s", "belgium.aprs2.net");
    cfg->aprs_port           = 14580;
    snprintf(cfg->aprs_tocall, sizeof(cfg->aprs_tocall), "%s", "APRFGR");
    snprintf(cfg->aprs_symbol, sizeof(cfg->aprs_symbol), "%s", "R&");
    snprintf(cfg->aprs_node_symbol, sizeof(cfg->aprs_node_symbol), "%s", "Mn");
    snprintf(cfg->aprs_comment, sizeof(cfg->aprs_comment), "%s", "meshcore-repeater 1.0 https://rf.guru");
    cfg->aprs_altitude       = 0.0;
    cfg->aprs_beacon_interval = 1800;  /* 30 min */
    cfg->aprs_node_rate      = 900;    /* 15 min per node */

    /* role: full repeater by default. Hotspot uplink = full power (reach the
     * repeater); downlink = lowest usable (local household delivery). */
    cfg->role               = ROLE_REPEATER;
    cfg->n_affinity         = 0;
    cfg->n_home             = 0;
    cfg->hotspot_power_high = 22;      /* uplink: chip max ~ +30 dBm / 1 W at antenna */
    cfg->hotspot_power_low  = -9;      /* downlink: chip minimum (well under 100 mW) */
}

static void trim_name(const char *in, char *out, size_t outsz);  /* fwd decl */

/* ---- name matching (role lists) ---- */
bool config_name_matches(const char *pattern, const char *name)
{
    size_t pl = strlen(pattern);
    if (pl > 0 && pattern[pl - 1] == '*')
        return strncasecmp(pattern, name, pl - 1) == 0;   /* prefix wildcard */
    return strcasecmp(pattern, name) == 0;
}

bool config_is_home(const mc_config_t *cfg, const char *name)
{
    if (!name || !name[0]) return false;
    for (int i = 0; i < cfg->n_home; i++)
        if (config_name_matches(cfg->home[i], name)) return true;
    return false;
}

bool config_is_affinity(const mc_config_t *cfg, const char *name)
{
    if (!name || !name[0]) return false;
    for (int i = 0; i < cfg->n_affinity; i++)
        if (config_name_matches(cfg->affinity[i], name)) return true;
    return false;
}

/* A repeater IDs with a bare callsign; a hotspot may append "-NN" (00..99) so
 * one operator can run several, each a distinct on-air ID. Only that suffix
 * convention is enforced here. */
bool config_valid_node_name(const char *name, mc_role_t role, char *why, size_t whysz)
{
    if (why && whysz) why[0] = '\0';
    if (!name || !name[0]) {
        if (why) snprintf(why, whysz, "node name is empty");
        return false;
    }
    const char *dash = strchr(name, '-');
    if (!dash)
        return true;                        /* bare name: fine in either role */

    if (role != ROLE_HOTSPOT) {
        if (why) snprintf(why, whysz,
            "name '%s' has an SSID suffix, but a repeater IDs with a bare "
            "callsign; the '-NN' form is only for hotspots", name);
        return false;
    }
    if (dash == name) {
        if (why) snprintf(why, whysz, "name '%s' has no callsign before the '-'", name);
        return false;
    }
    const char *ssid = dash + 1;
    size_t sl = strlen(ssid);              /* 1-2 digits => value is always 00..99 */
    if (sl < 1 || sl > 2) {
        if (why) snprintf(why, whysz,
            "name '%s': a hotspot SSID must be 1-2 digits (00..99)", name);
        return false;
    }
    for (size_t i = 0; i < sl; i++)
        if (ssid[i] < '0' || ssid[i] > '9') {
            if (why) snprintf(why, whysz,
                "name '%s': a hotspot SSID must be numeric (00..99)", name);
            return false;
        }
    return true;                            /* CALL-NN, 00..99, hotspot: good */
}

/* Append a pattern to a fixed name-list (dedup, bounded). 0 ok/dup, -2 full. */
static int list_add(char list[][MC_NAME_PAT_LEN], int *n, int max, const char *val)
{
    char clean[MC_NAME_PAT_LEN];
    trim_name(val, clean, sizeof(clean));
    if (clean[0] == '\0') return -2;
    if (!strcmp(clean, "*")) return -2;    /* a bare '*' would match everyone - reject */
    for (int i = 0; i < *n; i++)
        if (!strcasecmp(list[i], clean)) return 0;
    if (*n >= max) return -2;
    snprintf(list[*n], MC_NAME_PAT_LEN, "%s", clean);
    (*n)++;
    return 0;
}

/* ---- blacklist helpers ---- */
static void trim_name(const char *in, char *out, size_t outsz)
{
    while (*in == ' ' || *in == '\t') in++;
    snprintf(out, outsz, "%s", in);
    size_t n = strlen(out);
    while (n > 0 && (out[n-1] == ' ' || out[n-1] == '\t' || out[n-1] == '\r' || out[n-1] == '\n'))
        out[--n] = '\0';
}

int config_blacklist_add(mc_config_t *cfg, const char *name)
{
    char clean[MC_BLACKLIST_NAME_LEN];
    trim_name(name, clean, sizeof(clean));
    if (clean[0] == '\0')
        return -1;
    for (int i = 0; i < cfg->n_blacklist; i++)
        if (!strcasecmp(cfg->blacklist[i], clean))
            return 1;                              /* already present */
    if (cfg->n_blacklist >= MC_MAX_BLACKLIST)
        return -1;                                 /* full */
    snprintf(cfg->blacklist[cfg->n_blacklist], MC_BLACKLIST_NAME_LEN, "%s", clean);
    cfg->n_blacklist++;
    return 0;
}

int config_blacklist_remove(mc_config_t *cfg, const char *name)
{
    char clean[MC_BLACKLIST_NAME_LEN];
    trim_name(name, clean, sizeof(clean));
    for (int i = 0; i < cfg->n_blacklist; i++) {
        if (!strcasecmp(cfg->blacklist[i], clean)) {
            for (int j = i; j < cfg->n_blacklist - 1; j++)
                memcpy(cfg->blacklist[j], cfg->blacklist[j+1], MC_BLACKLIST_NAME_LEN);
            cfg->n_blacklist--;
            return 0;
        }
    }
    return -1;                                     /* not found */
}

bool config_is_blacklisted(const mc_config_t *cfg, const char *name)
{
    if (!name || name[0] == '\0')
        return false;
    for (int i = 0; i < cfg->n_blacklist; i++)
        if (!strcasecmp(cfg->blacklist[i], name))
            return true;
    return false;
}

/* ---- value parsers ---- */
static bool parse_bool(const char *v, bool *out)
{
    if (!strcasecmp(v, "true") || !strcasecmp(v, "1") || !strcasecmp(v, "yes") || !strcasecmp(v, "on")) { *out = true; return true; }
    if (!strcasecmp(v, "false") || !strcasecmp(v, "0") || !strcasecmp(v, "no") || !strcasecmp(v, "off")) { *out = false; return true; }
    return false;
}

static bool parse_u32(const char *v, uint32_t *out)
{
    char *end = NULL;
    long base = (strncmp(v, "0x", 2) == 0 || strncmp(v, "0X", 2) == 0) ? 16 : 10;
    unsigned long x = strtoul(v, &end, (int)base);
    if (end == v || *end != '\0')
        return false;
    *out = (uint32_t)x;
    return true;
}

static bool parse_double(const char *v, double *out)
{
    char *end = NULL;
    double x = strtod(v, &end);
    if (end == v || *end != '\0')
        return false;
    *out = x;
    return true;
}

/* Register a channel from raw key bytes. derived=true marks a key auto-derived
 * from a #room name (config_save skips it - the room line re-derives it on load).
 * Returns 0 (added or a harmless duplicate), or -2 on a bad length / full list. */
static int register_channel(mc_config_t *cfg, const char *name,
                            const uint8_t *secret, int len, bool derived)
{
    if (len != 16 && len != 32)
        return -2;
    /* dedup by secret so a reload (which re-reads the same file) is idempotent */
    for (int i = 0; i < cfg->n_public_channels; i++) {
        if (cfg->public_channels[i].secret_len == (uint8_t)len &&
            memcmp(cfg->public_channels[i].secret, secret, (size_t)len) == 0)
            return 0;
    }
    if (cfg->n_public_channels >= MC_MAX_PUBLIC_CHANNELS)
        return -2;

    mc_pub_channel_t *ch = &cfg->public_channels[cfg->n_public_channels];
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->secret, secret, (size_t)len);   /* bytes [len..31] stay zero */
    ch->secret_len = (uint8_t)len;
    ch->derived    = derived;
    snprintf(ch->name, sizeof(ch->name), "%s", name ? name : "");

    /* channel hash = SHA256(secret, len)[0]; hash EXACTLY the raw key bytes
     * (a 16-byte PSK must not be zero-padded to 32 before hashing). */
    SHA256_CTX c;
    uint8_t digest[SHA256_BLOCK_SIZE];
    sha256_init(&c);
    sha256_update(&c, ch->secret, (size_t)len);
    sha256_final(&c, digest);
    ch->hash = digest[0];

    cfg->n_public_channels++;
    return 0;
}

/* Parse a "public_channel = [name:]<base64-or-hex-psk>" value and append it.
 * Returns 0 (added or a harmless duplicate), or -2 on a bad value. */
static int add_public_channel(mc_config_t *cfg, const char *val)
{
    /* optional friendly name before the FIRST ':' */
    char name[MC_ROOM_NAME_LEN] = {0};
    const char *psk = val;
    const char *colon = strchr(val, ':');
    if (colon) {
        size_t nl = (size_t)(colon - val);
        if (nl >= sizeof(name)) nl = sizeof(name) - 1;
        memcpy(name, val, nl);
        psk = colon + 1;
    }

    /* hex if it is all hex digits and 32/64 chars (16/32 bytes); else base64 */
    size_t pl = strlen(psk);
    bool ishex = (pl == 32 || pl == 64);
    for (size_t i = 0; ishex && i < pl; i++) {
        char c = psk[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            ishex = false;
    }
    uint8_t secret[32];
    int len = ishex ? hex2bin(psk, secret, sizeof(secret))
                    : base64_decode(psk, secret, sizeof(secret));
    return register_channel(cfg, name, secret, len, false);
}

/* Parse a "room = [#]<name>" transport region and append it. The key is
 * SHA256("#name")[0..15]; MeshCore hashes the region name WITH a single leading
 * '#', so we normalise to exactly one. Names are case-sensitive (hashed verbatim).
 * Returns 0 ok/dup, -2 invalid/full. */
static int add_room(mc_config_t *cfg, const char *val)
{
    /* Trim into a buffer wider than the limit so an over-long name is REJECTED
     * below, not silently truncated into a wrong-hash region. */
    char clean[MC_ROOM_NAME_LEN * 2];
    trim_name(val, clean, sizeof(clean));
    if (clean[0] == '\0')
        return -2;

    /* normalise to exactly one leading '#' (MeshCore hashes the name with it) */
    char name[MC_ROOM_NAME_LEN * 2 + 2];
    if (clean[0] == '#')
        snprintf(name, sizeof(name), "%s", clean);
    else
        snprintf(name, sizeof(name), "#%s", clean);
    if (name[1] == '\0')                        /* a bare "#" is not a region */
        return -2;
    if (strlen(name) >= MC_ROOM_NAME_LEN)       /* must round-trip through storage */
        return -2;

    for (int i = 0; i < cfg->n_rooms; i++)      /* dedup (verbatim: hashes differ by case) */
        if (!strcmp(cfg->rooms[i], name))
            return 0;
    if (cfg->n_rooms >= MC_MAX_ROOMS)
        return -2;

    snprintf(cfg->rooms[cfg->n_rooms], MC_ROOM_NAME_LEN, "%s", name);
    uint8_t digest[32];
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)name, strlen(name));
    sha256_final(&c, digest);
    memcpy(cfg->room_key[cfg->n_rooms], digest, 16);   /* region key = SHA256(name)[0..15] */
    cfg->n_rooms++;

    /* A MeshCore hashtag channel uses the SAME key = SHA256("#name")[0..15]. Also
     * register it as a (derived) public channel so we decrypt, forward and monitor
     * its plain-flood group messages - not just match a transport code. */
    if (register_channel(cfg, name, digest, 16, true) == -2)
        log_warn("config: room '%s' added as a region, but the channel list is full "
                 "(max %d) - its plain-flood messages won't be decrypted/forwarded",
                 name, MC_MAX_PUBLIC_CHANNELS);
    return 0;
}

int config_set(mc_config_t *cfg, const char *key, const char *val)
{
    uint32_t u;
    double d;
    bool b;

    /* ---- radio ---- */
    if (!strcasecmp(key, "frequency")) {
        if (!parse_double(val, &d) || d < 137.0 || d > 1020.0) return -2;
        cfg->frequency = d; return 0;
    }
    if (!strcasecmp(key, "bandwidth")) {
        if (!parse_double(val, &d) ||
            (d != 62.5 && d != 125.0 && d != 250.0 && d != 500.0)) return -2;
        cfg->bandwidth = d; return 0;
    }
    if (!strcasecmp(key, "spreading_factor")) {
        if (!parse_u32(val, &u) || u < 5 || u > 12) return -2;
        cfg->spreading_factor = (uint8_t)u; return 0;
    }
    if (!strcasecmp(key, "coding_rate")) {
        if (!parse_u32(val, &u) || u < 5 || u > 8) return -2;
        cfg->coding_rate = (uint8_t)u; return 0;
    }
    if (!strcasecmp(key, "tx_power")) {
        char *end = NULL; long p = strtol(val, &end, 10);
        if (end == val || *end != '\0') return -2;
        /* tx_power is the SX126x CHIP setpoint (max +22 dBm). The module's PA
         * adds gain to reach ~+30 dBm at the antenna. If someone enters the
         * antenna figure (e.g. 30), clamp to the chip max with a hint. */
        if (p > 22 && p <= 40) {
            log_warn("tx_power %ld is the antenna target; the SX126x chip maxes at "
                     "+22 dBm and the module PA adds the rest (~+30 dBm). Clamping to 22.", p);
            p = 22;
        }
        if (p < -9 || p > 22) return -2;
        cfg->tx_power = (int8_t)p; return 0;
    }
    if (!strcasecmp(key, "preamble")) {
        if (!parse_u32(val, &u) || u < 6 || u > 65535) return -2;
        cfg->preamble = (uint16_t)u; return 0;
    }
    if (!strcasecmp(key, "sync_word")) {
        if (!strcasecmp(val, "private")) { cfg->sync_word = 0x1424; return 0; }
        if (!strcasecmp(val, "public"))  { cfg->sync_word = 0x3444; return 0; }
        if (!parse_u32(val, &u) || u > 0xFFFF) return -2;
        cfg->sync_word = (uint16_t)u; return 0;
    }
    if (!strcasecmp(key, "crc")) { if (!parse_bool(val, &b)) return -2; cfg->crc_on = b; return 0; }
    if (!strcasecmp(key, "iq_inverted")) { if (!parse_bool(val, &b)) return -2; cfg->iq_inverted = b; return 0; }
    if (!strcasecmp(key, "use_cad")) { if (!parse_bool(val, &b)) return -2; cfg->use_cad = b; return 0; }
    if (!strcasecmp(key, "tcxo_voltage")) {
        if (!parse_double(val, &d) || d < 0.0 || d > 3.4) return -2;
        cfg->tcxo_voltage = d; return 0;
    }
    if (!strcasecmp(key, "ocp")) { if (!parse_u32(val, &u) || u > 0x3F) return -2; cfg->ocp_reg = (uint8_t)u; return 0; }

    /* ---- hardware ---- */
    if (!strcasecmp(key, "spi_dev")) { snprintf(cfg->spi_dev, sizeof(cfg->spi_dev), "%s", val); return 0; }
    if (!strcasecmp(key, "spi_speed")) { if (!parse_u32(val, &u)) return -2; cfg->spi_speed = u; return 0; }
    if (!strcasecmp(key, "gpio_chip")) { snprintf(cfg->gpio_chip, sizeof(cfg->gpio_chip), "%s", val); return 0; }
    if (!strcasecmp(key, "gpio_reset")) { if (!parse_u32(val, &u)) return -2; cfg->gpio_reset = u; return 0; }
    if (!strcasecmp(key, "gpio_busy"))  { if (!parse_u32(val, &u)) return -2; cfg->gpio_busy = u; return 0; }
    if (!strcasecmp(key, "gpio_dio1"))  { if (!parse_u32(val, &u)) return -2; cfg->gpio_dio1 = u; return 0; }
    if (!strcasecmp(key, "gpio_nss"))   { if (!parse_u32(val, &u)) return -2; cfg->gpio_nss = u; return 0; }
    if (!strcasecmp(key, "rf_switch")) {
        if (!strcasecmp(val, "dio2"))     { cfg->rf_switch_dio2 = true;  return 0; }
        if (!strcasecmp(val, "external")) { cfg->rf_switch_dio2 = false; return 0; }
        return -2;
    }
    if (!strcasecmp(key, "gpio_rxen"))  { if (!parse_u32(val, &u)) return -2; cfg->gpio_rxen = u; return 0; }
    if (!strcasecmp(key, "gpio_txen"))  { if (!parse_u32(val, &u)) return -2; cfg->gpio_txen = u; return 0; }
    if (!strcasecmp(key, "use_leds"))     { if (!parse_bool(val, &b)) return -2; cfg->use_leds = b; return 0; }
    if (!strcasecmp(key, "gpio_led_on"))  { if (!parse_u32(val, &u)) return -2; cfg->gpio_led_on = u; return 0; }
    if (!strcasecmp(key, "gpio_led_data")){ if (!parse_u32(val, &u)) return -2; cfg->gpio_led_data = u; return 0; }

    /* ---- node ---- */
    if (!strcasecmp(key, "name")) { snprintf(cfg->name, sizeof(cfg->name), "%s", val); return 0; }
    if (!strcasecmp(key, "key_file")) { snprintf(cfg->key_file, sizeof(cfg->key_file), "%s", val); return 0; }
    if (!strcasecmp(key, "latitude"))  { if (!parse_double(val, &d)) return -2; cfg->latitude = d; cfg->has_location = true; return 0; }
    if (!strcasecmp(key, "longitude")) { if (!parse_double(val, &d)) return -2; cfg->longitude = d; cfg->has_location = true; return 0; }
    if (!strcasecmp(key, "location")) { if (!parse_bool(val, &b)) return -2; cfg->has_location = b; return 0; }
    if (!strcasecmp(key, "advert_interval")) { if (!parse_u32(val, &u)) return -2; cfg->advert_interval = u; return 0; }
    if (!strcasecmp(key, "forward")) { if (!parse_bool(val, &b)) return -2; cfg->forward = b; return 0; }
    if (!strcasecmp(key, "ping_pong")) { if (!parse_bool(val, &b)) return -2; cfg->ping_pong = b; return 0; }
    if (!strcasecmp(key, "ping_channel")) {
        char clean[MC_ROOM_NAME_LEN * 2];
        trim_name(val, clean, sizeof(clean));
        if (!strcasecmp(clean, "any") || !strcasecmp(clean, "none") ||
            !strcmp(clean, "-") || !strcmp(clean, "*")) {
            cfg->ping_channel[0] = '\0';                   /* answer on any channel */
            return 0;
        }
        if (clean[0] == '\0')
            return -2;   /* empty (e.g. a "#name" that '#'-comment-stripped) -> warn, keep default */
        char nm[MC_ROOM_NAME_LEN * 2 + 2];                 /* normalise to one leading '#' */
        if (clean[0] == '#') snprintf(nm, sizeof(nm), "%s", clean);
        else                 snprintf(nm, sizeof(nm), "#%s", clean);
        if (strlen(nm) >= MC_ROOM_NAME_LEN) return -2;
        snprintf(cfg->ping_channel, sizeof(cfg->ping_channel), "%s", nm);
        return 0;
    }
    if (!strcasecmp(key, "control_port")) { if (!parse_u32(val, &u) || u > 65535) return -2; cfg->control_port = (uint16_t)u; return 0; }
    if (!strcasecmp(key, "public_channel")) { return add_public_channel(cfg, val); }
    if (!strcasecmp(key, "room"))           { return add_room(cfg, val); }
    if (!strcasecmp(key, "blacklist")) { return config_blacklist_add(cfg, val) < 0 ? -2 : 0; }

    /* ---- APRS-IS iGate ---- */
    if (!strcasecmp(key, "aprs_enable")) { if (!parse_bool(val, &b)) return -2; cfg->aprs_enable = b; return 0; }
    if (!strcasecmp(key, "aprs_call")) { snprintf(cfg->aprs_call, sizeof(cfg->aprs_call), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_passcode")) { snprintf(cfg->aprs_passcode, sizeof(cfg->aprs_passcode), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_host")) { snprintf(cfg->aprs_host, sizeof(cfg->aprs_host), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_port")) { if (!parse_u32(val, &u) || u > 65535) return -2; cfg->aprs_port = (uint16_t)u; return 0; }
    if (!strcasecmp(key, "aprs_tocall")) { snprintf(cfg->aprs_tocall, sizeof(cfg->aprs_tocall), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_symbol")) { snprintf(cfg->aprs_symbol, sizeof(cfg->aprs_symbol), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_node_symbol")) { snprintf(cfg->aprs_node_symbol, sizeof(cfg->aprs_node_symbol), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_comment")) { snprintf(cfg->aprs_comment, sizeof(cfg->aprs_comment), "%s", val); return 0; }
    if (!strcasecmp(key, "aprs_altitude")) { if (!parse_double(val, &d)) return -2; cfg->aprs_altitude = d; return 0; }
    if (!strcasecmp(key, "aprs_beacon_interval")) { if (!parse_u32(val, &u)) return -2; cfg->aprs_beacon_interval = u; return 0; }
    if (!strcasecmp(key, "aprs_node_rate")) { if (!parse_u32(val, &u)) return -2; cfg->aprs_node_rate = u; return 0; }

    /* ---- role: repeater vs hotspot ---- */
    if (!strcasecmp(key, "role")) {
        if (!strcasecmp(val, "repeater")) cfg->role = ROLE_REPEATER;
        else if (!strcasecmp(val, "hotspot")) cfg->role = ROLE_HOTSPOT;
        else return -2;
        return 0;
    }
    if (!strcasecmp(key, "affinity")) return list_add(cfg->affinity, &cfg->n_affinity, MC_MAX_AFFINITY, val);
    if (!strcasecmp(key, "home"))     return list_add(cfg->home, &cfg->n_home, MC_MAX_HOME, val);
    if (!strcasecmp(key, "hotspot_power_high") || !strcasecmp(key, "hotspot_power_low")) {
        char *end = NULL; long p = strtol(val, &end, 10);
        if (end == val || *end != '\0' || p < -9 || p > 22) return -2;
        if (!strcasecmp(key, "hotspot_power_high")) cfg->hotspot_power_high = (int8_t)p;
        else cfg->hotspot_power_low = (int8_t)p;
        return 0;
    }

    return -1; /* unknown key */
}

int config_get(const mc_config_t *cfg, const char *key, char *out, size_t outsz)
{
    if (!strcasecmp(key, "frequency"))        { snprintf(out, outsz, "%.3f", cfg->frequency); return 0; }
    if (!strcasecmp(key, "bandwidth"))        { snprintf(out, outsz, "%g", cfg->bandwidth); return 0; }
    if (!strcasecmp(key, "spreading_factor")) { snprintf(out, outsz, "%u", cfg->spreading_factor); return 0; }
    if (!strcasecmp(key, "coding_rate"))      { snprintf(out, outsz, "%u", cfg->coding_rate); return 0; }
    if (!strcasecmp(key, "tx_power"))         { snprintf(out, outsz, "%d", cfg->tx_power); return 0; }
    if (!strcasecmp(key, "preamble"))         { snprintf(out, outsz, "%u", cfg->preamble); return 0; }
    if (!strcasecmp(key, "sync_word"))        { snprintf(out, outsz, "0x%04X", cfg->sync_word); return 0; }
    if (!strcasecmp(key, "crc"))              { snprintf(out, outsz, "%s", cfg->crc_on ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "iq_inverted"))      { snprintf(out, outsz, "%s", cfg->iq_inverted ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "use_cad"))          { snprintf(out, outsz, "%s", cfg->use_cad ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "tcxo_voltage"))     { snprintf(out, outsz, "%.2f", cfg->tcxo_voltage); return 0; }
    if (!strcasecmp(key, "ocp"))              { snprintf(out, outsz, "0x%02X", cfg->ocp_reg); return 0; }
    if (!strcasecmp(key, "spi_dev"))          { snprintf(out, outsz, "%s", cfg->spi_dev); return 0; }
    if (!strcasecmp(key, "spi_speed"))        { snprintf(out, outsz, "%u", cfg->spi_speed); return 0; }
    if (!strcasecmp(key, "gpio_chip"))        { snprintf(out, outsz, "%s", cfg->gpio_chip); return 0; }
    if (!strcasecmp(key, "gpio_reset"))       { snprintf(out, outsz, "%u", cfg->gpio_reset); return 0; }
    if (!strcasecmp(key, "gpio_busy"))        { snprintf(out, outsz, "%u", cfg->gpio_busy); return 0; }
    if (!strcasecmp(key, "gpio_dio1"))        { snprintf(out, outsz, "%u", cfg->gpio_dio1); return 0; }
    if (!strcasecmp(key, "gpio_nss"))         { snprintf(out, outsz, "%u", cfg->gpio_nss); return 0; }
    if (!strcasecmp(key, "rf_switch"))        { snprintf(out, outsz, "%s", cfg->rf_switch_dio2 ? "dio2" : "external"); return 0; }
    if (!strcasecmp(key, "gpio_rxen"))        { snprintf(out, outsz, "%u", cfg->gpio_rxen); return 0; }
    if (!strcasecmp(key, "gpio_txen"))        { snprintf(out, outsz, "%u", cfg->gpio_txen); return 0; }
    if (!strcasecmp(key, "use_leds"))         { snprintf(out, outsz, "%s", cfg->use_leds ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "gpio_led_on"))      { snprintf(out, outsz, "%u", cfg->gpio_led_on); return 0; }
    if (!strcasecmp(key, "gpio_led_data"))    { snprintf(out, outsz, "%u", cfg->gpio_led_data); return 0; }
    if (!strcasecmp(key, "name"))             { snprintf(out, outsz, "%s", cfg->name); return 0; }
    if (!strcasecmp(key, "key_file"))         { snprintf(out, outsz, "%s", cfg->key_file); return 0; }
    if (!strcasecmp(key, "latitude"))         { snprintf(out, outsz, "%.6f", cfg->latitude); return 0; }
    if (!strcasecmp(key, "longitude"))        { snprintf(out, outsz, "%.6f", cfg->longitude); return 0; }
    if (!strcasecmp(key, "location"))         { snprintf(out, outsz, "%s", cfg->has_location ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "advert_interval"))  { snprintf(out, outsz, "%u", cfg->advert_interval); return 0; }
    if (!strcasecmp(key, "forward"))          { snprintf(out, outsz, "%s", cfg->forward ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "ping_pong"))        { snprintf(out, outsz, "%s", cfg->ping_pong ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "ping_channel"))     { snprintf(out, outsz, "%s", cfg->ping_channel[0] ? cfg->ping_channel : "any"); return 0; }
    if (!strcasecmp(key, "control_port"))     { snprintf(out, outsz, "%u", cfg->control_port); return 0; }
    if (!strcasecmp(key, "public_channel"))   { snprintf(out, outsz, "%d configured", cfg->n_public_channels); return 0; }
    if (!strcasecmp(key, "room"))             { snprintf(out, outsz, "%d configured", cfg->n_rooms); return 0; }
    if (!strcasecmp(key, "blacklist"))        { snprintf(out, outsz, "%d entries", cfg->n_blacklist); return 0; }
    if (!strcasecmp(key, "aprs_enable"))      { snprintf(out, outsz, "%s", cfg->aprs_enable ? "true" : "false"); return 0; }
    if (!strcasecmp(key, "aprs_call"))        { snprintf(out, outsz, "%s", cfg->aprs_call); return 0; }
    if (!strcasecmp(key, "aprs_passcode"))    { snprintf(out, outsz, "%s", cfg->aprs_passcode); return 0; }
    if (!strcasecmp(key, "aprs_host"))        { snprintf(out, outsz, "%s", cfg->aprs_host); return 0; }
    if (!strcasecmp(key, "aprs_port"))        { snprintf(out, outsz, "%u", cfg->aprs_port); return 0; }
    if (!strcasecmp(key, "aprs_tocall"))      { snprintf(out, outsz, "%s", cfg->aprs_tocall); return 0; }
    if (!strcasecmp(key, "aprs_symbol"))      { snprintf(out, outsz, "%s", cfg->aprs_symbol); return 0; }
    if (!strcasecmp(key, "aprs_node_symbol")) { snprintf(out, outsz, "%s", cfg->aprs_node_symbol); return 0; }
    if (!strcasecmp(key, "aprs_comment"))     { snprintf(out, outsz, "%s", cfg->aprs_comment); return 0; }
    if (!strcasecmp(key, "aprs_altitude"))    { snprintf(out, outsz, "%g", cfg->aprs_altitude); return 0; }
    if (!strcasecmp(key, "aprs_beacon_interval")) { snprintf(out, outsz, "%u", cfg->aprs_beacon_interval); return 0; }
    if (!strcasecmp(key, "aprs_node_rate"))   { snprintf(out, outsz, "%u", cfg->aprs_node_rate); return 0; }
    if (!strcasecmp(key, "role"))             { snprintf(out, outsz, "%s", cfg->role == ROLE_HOTSPOT ? "hotspot" : "repeater"); return 0; }
    if (!strcasecmp(key, "affinity"))         { snprintf(out, outsz, "%d entries", cfg->n_affinity); return 0; }
    if (!strcasecmp(key, "home"))             { snprintf(out, outsz, "%d entries", cfg->n_home); return 0; }
    if (!strcasecmp(key, "hotspot_power_high")){ snprintf(out, outsz, "%d", cfg->hotspot_power_high); return 0; }
    if (!strcasecmp(key, "hotspot_power_low")) { snprintf(out, outsz, "%d", cfg->hotspot_power_low); return 0; }
    return -1;
}

/* Make sure the ping channel (default "#mesh") exists as a decryptable channel,
 * so ping/pong and monitoring always have it available even if the config file
 * never mentioned it. It is a derived channel (key = SHA256("#name")[0..15]), not
 * written back by config_save. */
static void config_ensure_ping_channel(mc_config_t *cfg)
{
    if (cfg->ping_channel[0] == '\0')
        return;
    for (int i = 0; i < cfg->n_public_channels; i++)
        if (strcmp(cfg->public_channels[i].name, cfg->ping_channel) == 0)
            return;                                  /* already present */
    uint8_t digest[32];
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, (const uint8_t *)cfg->ping_channel, strlen(cfg->ping_channel));
    sha256_final(&c, digest);
    register_channel(cfg, cfg->ping_channel, digest, 16, true);
}

int config_load(mc_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        config_ensure_ping_channel(cfg);   /* no file: still guarantee #mesh */
        return -1;
    }

    /* list-valued keys: the file is authoritative, so clear them before
     * (re)reading rather than accumulating across reloads. */
    cfg->n_public_channels = 0;
    cfg->n_rooms = 0;
    cfg->n_blacklist = 0;
    cfg->n_affinity = 0;
    cfg->n_home = 0;

    char line[1024];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* detect + skip an over-long line rather than misparsing a truncated tail */
        size_t llen = strlen(line);
        if (llen == sizeof(line) - 1 && line[llen - 1] != '\n') {
            log_warn("config %s:%d: line too long (> %zu bytes), skipped", path, lineno, sizeof(line) - 1);
            int c;
            while ((c = fgetc(f)) != '\n' && c != EOF) { /* drain rest of line */ }
            continue;
        }
        /* strip comment */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        /* trim */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = p;
        char *val = eq + 1;
        /* rtrim key */
        char *ke = key + strlen(key);
        while (ke > key && (ke[-1] == ' ' || ke[-1] == '\t')) *--ke = '\0';
        /* trim val */
        while (*val == ' ' || *val == '\t') val++;
        char *ve = val + strlen(val);
        while (ve > val && (ve[-1] == '\n' || ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t')) *--ve = '\0';
        if (*key == '\0')
            continue;

        int rc = config_set(cfg, key, val);
        if (rc == -1)
            log_warn("config %s:%d: unknown key '%s'", path, lineno, key);
        else if (rc == -2)
            log_warn("config %s:%d: invalid value for '%s': '%s'", path, lineno, key, val);
    }
    fclose(f);

    config_ensure_ping_channel(cfg);   /* guarantee the ping/test channel exists */

    /* Nudge on the callsign/SSID convention once name + role are both final.
     * Never fatal - a bad ID is a compliance nit, not a reason to refuse to run. */
    char why[128];
    if (!config_valid_node_name(cfg->name, cfg->role, why, sizeof(why)))
        log_warn("config: %s", why);
    return 0;
}

int config_save(const mc_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    char buf[128];
    static const char *KEYS[] = {
        "frequency", "bandwidth", "spreading_factor", "coding_rate", "tx_power",
        "preamble", "sync_word", "crc", "iq_inverted", "use_cad", "tcxo_voltage", "ocp",
        "spi_dev", "spi_speed", "gpio_chip", "gpio_reset", "gpio_busy", "gpio_dio1",
        "gpio_nss", "rf_switch", "gpio_rxen", "gpio_txen", "use_leds", "gpio_led_on",
        "gpio_led_data", "name", "key_file", "location", "latitude",
        "longitude", "advert_interval", "forward", "ping_pong", "control_port",
        "aprs_enable", "aprs_call", "aprs_passcode", "aprs_host", "aprs_port",
        "aprs_tocall", "aprs_symbol", "aprs_node_symbol", "aprs_comment",
        "aprs_altitude", "aprs_beacon_interval", "aprs_node_rate",
        "role", "hotspot_power_high", "hotspot_power_low", NULL
    };
    fprintf(f, "# MeshCore repeater configuration\n");
    for (int i = 0; KEYS[i]; i++) {
        if (config_get(cfg, KEYS[i], buf, sizeof(buf)) == 0)
            fprintf(f, "%-18s = %s\n", KEYS[i], buf);
    }
    /* ping_channel: emit the BARE name ('#' would start a comment on reload);
     * "any" means answer on every channel. Not in KEYS[] for that reason. */
    fprintf(f, "%-18s = %s\n", "ping_channel",
            cfg->ping_channel[0] == '\0' ? "any" :
            (cfg->ping_channel[0] == '#' ? cfg->ping_channel + 1 : cfg->ping_channel));
    /* public_channel is a repeatable list; emit one line each (hex form, so no
     * base64 encoder is needed - it round-trips through hex2bin on load). */
    for (int i = 0; i < cfg->n_public_channels; i++) {
        const mc_pub_channel_t *ch = &cfg->public_channels[i];
        if (ch->derived)
            continue;                  /* re-derived from its 'room' line on load */
        char hex[65];
        bin2hex(ch->secret, ch->secret_len, hex, sizeof(hex));
        if (ch->name[0])
            fprintf(f, "%-18s = %s:%s\n", "public_channel", ch->name, hex);
        else
            fprintf(f, "%-18s = %s\n", "public_channel", hex);
    }
    /* blacklist entries (also a repeatable list) */
    for (int i = 0; i < cfg->n_blacklist; i++)
        fprintf(f, "%-18s = %s\n", "blacklist", cfg->blacklist[i]);
    for (int i = 0; i < cfg->n_affinity; i++)
        fprintf(f, "%-18s = %s\n", "affinity", cfg->affinity[i]);
    for (int i = 0; i < cfg->n_home; i++)
        fprintf(f, "%-18s = %s\n", "home", cfg->home[i]);
    /* emit the BARE name (skip the stored leading '#'): '#' starts a comment in
     * the config file, so a "room = #x" line would be stripped to empty on load.
     * add_room re-adds the '#'. */
    for (int i = 0; i < cfg->n_rooms; i++)
        fprintf(f, "%-18s = %s\n", "room", cfg->rooms[i][0] == '#' ? cfg->rooms[i] + 1 : cfg->rooms[i]);
    fclose(f);
    return 0;
}

void config_to_sx126x(const mc_config_t *cfg, sx126x_cfg_t *radio)
{
    radio->freq_mhz     = cfg->frequency;
    radio->bw_khz       = cfg->bandwidth;
    radio->sf           = cfg->spreading_factor;
    radio->cr           = cfg->coding_rate;
    radio->power_dbm    = cfg->tx_power;
    radio->preamble     = cfg->preamble;
    radio->crc_on       = cfg->crc_on;
    radio->iq_inverted  = cfg->iq_inverted;
    /* enable Low-Data-Rate Optimize when symbol time > 16 ms (datasheet rule) */
    {
        double ts_ms = ((double)((uint32_t)1 << cfg->spreading_factor) /
                        (cfg->bandwidth * 1000.0)) * 1000.0;
        radio->ldro = (ts_ms > 16.0);
    }
    radio->tcxo_voltage   = cfg->tcxo_voltage;
    radio->sync_word      = cfg->sync_word;
    radio->ocp_reg        = cfg->ocp_reg;
    radio->use_cad        = cfg->use_cad;
    radio->dio2_rf_switch = cfg->rf_switch_dio2;
}

void config_to_hal(const mc_config_t *cfg, hal_config_t *hal)
{
    hal->spi_dev            = cfg->spi_dev;
    hal->spi_speed_hz       = cfg->spi_speed;
    hal->gpio_chip          = cfg->gpio_chip;
    hal->line_reset         = cfg->gpio_reset;
    hal->line_busy          = cfg->gpio_busy;
    hal->line_dio1          = cfg->gpio_dio1;
    hal->line_nss           = cfg->gpio_nss;
    hal->rf_switch_external = !cfg->rf_switch_dio2;
    hal->line_rxen          = cfg->gpio_rxen;
    hal->line_txen          = cfg->gpio_txen;
    hal->use_leds           = cfg->use_leds;
    hal->line_led_on        = cfg->gpio_led_on;
    hal->line_led_data      = cfg->gpio_led_data;
}
