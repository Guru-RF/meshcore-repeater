/*
 * sx126x.h - plain-C SX1268 LoRa driver (no RadioLib).
 *
 * Targets the NiceRF LoRa1268F30-433 module: an SX1268 transceiver with an
 * on-board PA/LNA and an external RXEN/TXEN antenna switch (driven via the HAL).
 * The SX1268 shares the SX1262 command set; opcodes/params are from the Semtech
 * SX1261/2 datasheet.
 */
#ifndef MC_SX126X_H
#define MC_SX126X_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    double   freq_mhz;       /* e.g. 433.5 */
    double   bw_khz;         /* 62.5/125/250/500; 250 to match MeshCore */
    uint8_t  sf;             /* 5..12 (MeshCore default 10) */
    uint8_t  cr;             /* coding rate denominator 5..8 (4/5..4/8) */
    int8_t   power_dbm;      /* chip output power -9..22 */
    uint16_t preamble;       /* symbols (16) */
    bool     crc_on;         /* true */
    bool     iq_inverted;    /* false (standard IQ) */
    bool     ldro;           /* low data-rate optimize */
    double   tcxo_voltage;   /* DIO3 TCXO control voltage; 0 = no TCXO (plain crystal) */
    uint16_t sync_word;      /* 2-byte LoRa sync reg value; 0x1424 = MeshCore PRIVATE */
    uint8_t  ocp_reg;        /* over-current protection register raw (e.g. 0x38 = 140mA) */
    bool     use_cad;        /* listen-before-talk via CAD */
    bool     dio2_rf_switch; /* true: chip drives DIO2 as antenna switch (no RXEN/TXEN) */
} sx126x_cfg_t;

/* Reset + full init from cfg. Returns 0 on success, <0 on error. */
int  sx126x_init(const sx126x_cfg_t *cfg);

/* Re-tune (standby, set freq, image-calibrate). Returns 0 on success. */
int  sx126x_set_frequency(double freq_mhz);

/* Re-apply modem params (sf/bw/cr/preamble/crc). Returns 0 on success. */
int  sx126x_set_modem(const sx126x_cfg_t *cfg);

/* Enter continuous receive (RF switch -> RX). Returns 0 on success. */
int  sx126x_start_rx(void);

/*
 * Poll for a received packet (non-blocking).
 * Returns 1 and fills buf/len/rssi/snr if a CRC-good packet arrived,
 * 0 if nothing (or a CRC-error packet was discarded), <0 on error.
 * snr_q is SNR in quarter-dB (signed).
 */
int  sx126x_poll_rx(uint8_t *buf, size_t bufsz, size_t *len,
                    int16_t *rssi_dbm, int8_t *snr_q);

/*
 * Transmit a packet (blocking until TxDone or timeout_ms).
 * Drives the antenna switch to TX, then restores continuous RX.
 * Returns 0 on success, -1 on timeout, <-1 on error.
 */
int  sx126x_transmit(const uint8_t *buf, size_t len, uint32_t timeout_ms);

/* Channel Activity Detection: 1 = busy, 0 = clear, <0 = error. */
int  sx126x_channel_busy(void);

/* Estimated LoRa airtime in milliseconds for a packet of payload_len bytes. */
uint32_t sx126x_airtime_ms(size_t payload_len);

/* Put radio in standby (used on shutdown). */
void sx126x_standby(void);

#endif /* MC_SX126X_H */
