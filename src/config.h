/*
 * config.h - runtime configuration (loaded from a file, mutable via the CLI).
 *
 * Every radio parameter is runtime-driven: change the frequency to stay clear
 * of LoRa-APRS without recompiling.  Defaults match the MeshCore network so the
 * repeater interoperates with stock MeshCore nodes.
 */
#ifndef MC_CONFIG_H
#define MC_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sx126x.h"
#include "hal.h"

#define MC_MAX_PUBLIC_CHANNELS 8

/* A public MeshCore channel the operator has declared forwardable. The AES key
 * is PUBLISHED, so relaying its group messages does not obscure meaning. */
typedef struct {
    char     name[24];        /* optional friendly label */
    uint8_t  secret[32];      /* channel PSK, zero-padded (16-byte keys use [0..15]) */
    uint8_t  secret_len;      /* 16 (AES-128) or 32 */
    uint8_t  hash;            /* SHA256(secret, secret_len)[0] = on-air channel selector */
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

    /* ---- ham content policy ----
     * Strict "forward public, drop private": only adverts, traces and group
     * messages on one of these declared PUBLIC channels are retransmitted. */
    mc_pub_channel_t public_channels[MC_MAX_PUBLIC_CHANNELS];
    int              n_public_channels;
} mc_config_t;

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

/* Project config onto the radio / HAL parameter structs. */
void config_to_sx126x(const mc_config_t *cfg, sx126x_cfg_t *radio);
void config_to_hal(const mc_config_t *cfg, hal_config_t *hal);

#endif /* MC_CONFIG_H */
