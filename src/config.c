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

    /* radio defaults: MeshCore network params, 433 MHz ham band clear of LoRa-APRS */
    cfg->frequency        = 433.500;   /* MHz - APRS is ~433.775; 250kHz BW => no overlap */
    cfg->bandwidth        = 250;       /* kHz */
    cfg->spreading_factor = 10;
    cfg->coding_rate      = 5;         /* 4/5 */
    cfg->tx_power         = 22;        /* SX1268 chip max; module PA brings antenna near +30 dBm */
    cfg->preamble         = 16;
    cfg->sync_word        = 0x1424;    /* MeshCore PRIVATE (RadioLib 0x12 expanded) */
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
    cfg->advert_interval = 7200;       /* 2 h */
    cfg->forward         = true;
    cfg->ping_pong       = false;      /* opt-in: answer public "ping" with "pong" */
    cfg->verbose         = false;      /* set at runtime by the -v flag */
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

/* Parse a "public_channel = [name:]<base64-or-hex-psk>" value and append it to
 * the list. Returns 0 (added or a harmless duplicate), or -2 on a bad value. */
static int add_public_channel(mc_config_t *cfg, const char *val)
{
    if (cfg->n_public_channels >= MC_MAX_PUBLIC_CHANNELS)
        return -2;

    /* optional friendly name before the FIRST ':' */
    char name[24] = {0};
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
    if (len != 16 && len != 32)
        return -2;

    /* dedup by secret so a reload (which re-reads the same file) is idempotent */
    for (int i = 0; i < cfg->n_public_channels; i++) {
        if (cfg->public_channels[i].secret_len == (uint8_t)len &&
            memcmp(cfg->public_channels[i].secret, secret, (size_t)len) == 0)
            return 0;
    }

    mc_pub_channel_t *ch = &cfg->public_channels[cfg->n_public_channels];
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->secret, secret, (size_t)len);   /* bytes [len..31] stay zero */
    ch->secret_len = (uint8_t)len;
    snprintf(ch->name, sizeof(ch->name), "%s", name);

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
    if (!strcasecmp(key, "public_channel")) { return add_public_channel(cfg, val); }

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
    if (!strcasecmp(key, "public_channel"))   { snprintf(out, outsz, "%d configured", cfg->n_public_channels); return 0; }
    return -1;
}

int config_load(mc_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    /* public_channel is a list, not a scalar: the file is authoritative, so
     * clear it before (re)reading rather than accumulating across reloads. */
    cfg->n_public_channels = 0;

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
        "longitude", "advert_interval", "forward", "ping_pong", NULL
    };
    fprintf(f, "# MeshCore repeater configuration\n");
    for (int i = 0; KEYS[i]; i++) {
        if (config_get(cfg, KEYS[i], buf, sizeof(buf)) == 0)
            fprintf(f, "%-18s = %s\n", KEYS[i], buf);
    }
    /* public_channel is a repeatable list; emit one line each (hex form, so no
     * base64 encoder is needed - it round-trips through hex2bin on load). */
    for (int i = 0; i < cfg->n_public_channels; i++) {
        const mc_pub_channel_t *ch = &cfg->public_channels[i];
        char hex[65];
        bin2hex(ch->secret, ch->secret_len, hex, sizeof(hex));
        if (ch->name[0])
            fprintf(f, "%-18s = %s:%s\n", "public_channel", ch->name, hex);
        else
            fprintf(f, "%-18s = %s\n", "public_channel", hex);
    }
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
