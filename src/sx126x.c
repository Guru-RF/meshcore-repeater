/*
 * sx126x.c - plain-C SX1268 LoRa driver.
 *
 * Command set / parameters per Semtech SX1261-2 datasheet (the SX1268 shares it).
 * BUSY is polled before every SPI transaction; the host drives the antenna
 * switch (RXEN/TXEN) through the HAL around every TX/RX/CAD.
 */
#include "sx126x.h"
#include "hal.h"
#include "log.h"

#include <string.h>
#include <math.h>

/* ---- opcodes ---- */
#define OP_SET_STANDBY        0x80
#define OP_SET_REGULATOR      0x96
#define OP_SET_PACKET_TYPE    0x8A
#define OP_SET_RF_FREQ        0x86
#define OP_CALIBRATE          0x89
#define OP_CALIBRATE_IMAGE    0x98
#define OP_SET_PA_CONFIG      0x95
#define OP_SET_TX_PARAMS      0x8E
#define OP_SET_MOD_PARAMS     0x8B
#define OP_SET_PKT_PARAMS     0x8C
#define OP_SET_BUF_BASE       0x8F
#define OP_WRITE_BUFFER       0x0E
#define OP_READ_BUFFER        0x1E
#define OP_WRITE_REGISTER     0x0D
#define OP_READ_REGISTER      0x1D
#define OP_SET_DIO_IRQ        0x08
#define OP_GET_IRQ_STATUS     0x12
#define OP_CLR_IRQ_STATUS     0x02
#define OP_SET_TX             0x83
#define OP_SET_RX             0x82
#define OP_SET_CAD            0xC5
#define OP_SET_CAD_PARAMS     0x88
#define OP_GET_RX_BUF_STATUS  0x13
#define OP_GET_PACKET_STATUS  0x14
#define OP_SET_DIO3_TCXO      0x97
#define OP_SET_DIO2_RF_SWITCH 0x9D
#define OP_GET_DEVICE_ERRORS  0x17
#define OP_CLR_DEVICE_ERRORS  0x07

/* device-error bits (GetDeviceErrors) */
#define ERR_XOSC_START        0x0020  /* TCXO/crystal failed to start */

/* standby modes */
#define STDBY_RC   0x00
#define STDBY_XOSC 0x01
/* regulator */
#define REG_LDO  0x00
#define REG_DCDC 0x01
/* packet type */
#define PKT_TYPE_LORA 0x01

/* registers */
#define REG_OCP            0x08E7
#define REG_LORA_SYNC_MSB  0x0740
#define REG_LORA_SYNC_LSB  0x0741

/* IRQ bits */
#define IRQ_TX_DONE       0x0001
#define IRQ_RX_DONE       0x0002
#define IRQ_PREAMBLE_DET  0x0004
#define IRQ_SYNC_VALID    0x0008
#define IRQ_HEADER_VALID  0x0010
#define IRQ_HEADER_ERR    0x0020
#define IRQ_CRC_ERR       0x0040
#define IRQ_CAD_DONE      0x0080
#define IRQ_CAD_DETECTED  0x0100
#define IRQ_TIMEOUT       0x0200
#define IRQ_ALL           0x03FF

/* LoRa bandwidth byte codes (SX126x datasheet 13.4.5.2) */
#define LORA_BW_062 0x03
#define LORA_BW_125 0x04
#define LORA_BW_250 0x05
#define LORA_BW_500 0x06

#define FXTAL_HZ   32000000.0
#define FREQ_DIV   33554432.0  /* 2^25 */

#define BUSY_TIMEOUT_US 20000  /* 20 ms - generous; covers calibration */

/* Wrap a command and fail fast with a diagnostic if SPI/BUSY errors out. */
#define SX_TRY(expr, name) do { \
    if ((expr) != 0) { log_err("sx126x: %s failed (SPI/BUSY error)", name); return -20; } \
} while (0)

static sx126x_cfg_t g_cfg;

/* ------------------------------------------------------------------ */
/* low-level SPI command helpers (each waits for BUSY low first)       */
/* ------------------------------------------------------------------ */

static int sx_write_cmd(uint8_t opcode, const uint8_t *params, size_t n)
{
    uint8_t tx[1 + 16];
    if (n > 16)
        return -1;
    if (hal_wait_busy_low(BUSY_TIMEOUT_US) != 0)
        return -2;
    tx[0] = opcode;
    if (n)
        memcpy(&tx[1], params, n);
    return hal_spi_xfer(tx, NULL, 1 + n);
}

/* Read n bytes of a Get* command response (after the 1 status byte). */
static int sx_read_cmd(uint8_t opcode, uint8_t *resp, size_t n)
{
    uint8_t tx[2 + 8] = {0};
    uint8_t rx[2 + 8] = {0};
    if (n > 8)
        return -1;
    if (hal_wait_busy_low(BUSY_TIMEOUT_US) != 0)
        return -2;
    tx[0] = opcode;
    int rc = hal_spi_xfer(tx, rx, 2 + n);
    if (rc != 0)
        return rc;
    memcpy(resp, &rx[2], n);  /* rx[1] = status, rx[2..] = data */
    return 0;
}

static int sx_write_register(uint16_t addr, const uint8_t *data, size_t n)
{
    uint8_t tx[3 + 8];
    if (n > 8)
        return -1;
    if (hal_wait_busy_low(BUSY_TIMEOUT_US) != 0)
        return -2;
    tx[0] = OP_WRITE_REGISTER;
    tx[1] = (uint8_t)(addr >> 8);
    tx[2] = (uint8_t)(addr & 0xFF);
    memcpy(&tx[3], data, n);
    return hal_spi_xfer(tx, NULL, 3 + n);
}

static int sx_write_buffer(uint8_t offset, const uint8_t *data, size_t n)
{
    uint8_t tx[2 + MC_SPI_MAX];
    if (n > MC_SPI_MAX)
        return -1;
    if (hal_wait_busy_low(BUSY_TIMEOUT_US) != 0)
        return -2;
    tx[0] = OP_WRITE_BUFFER;
    tx[1] = offset;
    memcpy(&tx[2], data, n);
    return hal_spi_xfer(tx, NULL, 2 + n);
}

static int sx_read_buffer(uint8_t offset, uint8_t *data, size_t n)
{
    uint8_t tx[3 + MC_SPI_MAX] = {0};
    uint8_t rx[3 + MC_SPI_MAX] = {0};
    if (n > MC_SPI_MAX)
        return -1;
    if (hal_wait_busy_low(BUSY_TIMEOUT_US) != 0)
        return -2;
    tx[0] = OP_READ_BUFFER;
    tx[1] = offset;
    /* tx[2] is the NOP/status byte; data follows */
    int rc = hal_spi_xfer(tx, rx, 3 + n);
    if (rc != 0)
        return rc;
    memcpy(data, &rx[3], n);
    return 0;
}

static int sx_clear_irq(uint16_t mask)
{
    uint8_t p[2] = { (uint8_t)(mask >> 8), (uint8_t)(mask & 0xFF) };
    return sx_write_cmd(OP_CLR_IRQ_STATUS, p, 2);
}

static int sx_get_irq(uint16_t *irq)
{
    uint8_t r[2] = {0};
    int rc = sx_read_cmd(OP_GET_IRQ_STATUS, r, 2);
    if (rc != 0)
        return rc;
    *irq = (uint16_t)((r[0] << 8) | r[1]);
    return 0;
}

static int sx_set_dio_irq(uint16_t irq_mask, uint16_t dio1_mask,
                          uint16_t dio2_mask, uint16_t dio3_mask)
{
    uint8_t p[8] = {
        (uint8_t)(irq_mask >> 8),  (uint8_t)(irq_mask & 0xFF),
        (uint8_t)(dio1_mask >> 8), (uint8_t)(dio1_mask & 0xFF),
        (uint8_t)(dio2_mask >> 8), (uint8_t)(dio2_mask & 0xFF),
        (uint8_t)(dio3_mask >> 8), (uint8_t)(dio3_mask & 0xFF),
    };
    return sx_write_cmd(OP_SET_DIO_IRQ, p, 8);
}

static int sx_set_standby(uint8_t mode)
{
    return sx_write_cmd(OP_SET_STANDBY, &mode, 1);
}

/* ------------------------------------------------------------------ */
/* configuration helpers                                               */
/* ------------------------------------------------------------------ */

static uint8_t bw_code(double bw_khz)
{
    /* compare in Hz to handle the fractional 62.5 kHz cleanly */
    switch ((uint32_t)(bw_khz * 1000.0 + 0.5)) {
        case 62500:  return LORA_BW_062;
        case 125000: return LORA_BW_125;
        case 250000: return LORA_BW_250;
        case 500000: return LORA_BW_500;
        default:     return LORA_BW_250;
    }
}

static uint8_t tcxo_voltage_code(double v)
{
    if (v >= 3.3) return 0x07;
    if (v >= 3.0) return 0x06;
    if (v >= 2.7) return 0x05;
    if (v >= 2.4) return 0x04;
    if (v >= 2.2) return 0x03;
    if (v >= 1.8) return 0x02;
    if (v >= 1.7) return 0x01;
    return 0x00; /* 1.6 V */
}

/* CalibrateImage params per Semtech datasheet Table 9-2. */
static void calibrate_image_params(double freq_mhz, uint8_t out[2])
{
    if (freq_mhz >= 430.0 && freq_mhz <= 440.0) { out[0] = 0x6B; out[1] = 0x6F; }
    else if (freq_mhz >= 470.0 && freq_mhz <= 510.0) { out[0] = 0x75; out[1] = 0x81; }
    else if (freq_mhz >= 779.0 && freq_mhz <= 787.0) { out[0] = 0xC1; out[1] = 0xC5; }
    else if (freq_mhz >= 863.0 && freq_mhz <= 870.0) { out[0] = 0xD7; out[1] = 0xDB; }
    else { out[0] = 0xE1; out[1] = 0xE9; } /* 902-928 / default */
}

static int set_rf_frequency(double freq_mhz)
{
    /* word = freq_hz * 2^25 / Fxtal */
    double word_d = (freq_mhz * 1e6) * FREQ_DIV / FXTAL_HZ;
    uint32_t word = (uint32_t)llround(word_d);
    uint8_t p[4] = {
        (uint8_t)(word >> 24), (uint8_t)(word >> 16),
        (uint8_t)(word >> 8),  (uint8_t)(word & 0xFF)
    };
    int rc = sx_write_cmd(OP_SET_RF_FREQ, p, 4);
    if (rc != 0)
        return rc;
    uint8_t cal[2];
    calibrate_image_params(freq_mhz, cal);
    return sx_write_cmd(OP_CALIBRATE_IMAGE, cal, 2);
}

/* SetModulationParams + the static parts of SetPacketParams. */
static int set_modem_params(const sx126x_cfg_t *cfg)
{
    uint8_t cr_code = (uint8_t)(cfg->cr - 4); /* 4/5..4/8 -> 1..4 */
    uint8_t mod[4] = {
        cfg->sf,
        bw_code(cfg->bw_khz),
        cr_code,
        (uint8_t)(cfg->ldro ? 0x01 : 0x00),
    };
    int rc = sx_write_cmd(OP_SET_MOD_PARAMS, mod, 4);
    if (rc != 0)
        return rc;

    uint8_t pkt[6] = {
        (uint8_t)(cfg->preamble >> 8), (uint8_t)(cfg->preamble & 0xFF),
        0x00,                       /* explicit header */
        0xFF,                       /* payload length (set per-TX) */
        (uint8_t)(cfg->crc_on ? 0x01 : 0x00),
        (uint8_t)(cfg->iq_inverted ? 0x01 : 0x00),
    };
    return sx_write_cmd(OP_SET_PKT_PARAMS, pkt, 6);
}

static int set_packet_params_len(uint8_t payload_len)
{
    uint8_t pkt[6] = {
        (uint8_t)(g_cfg.preamble >> 8), (uint8_t)(g_cfg.preamble & 0xFF),
        0x00,
        payload_len,
        (uint8_t)(g_cfg.crc_on ? 0x01 : 0x00),
        (uint8_t)(g_cfg.iq_inverted ? 0x01 : 0x00),
    };
    return sx_write_cmd(OP_SET_PKT_PARAMS, pkt, 6);
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

static int sx_get_device_errors(uint16_t *errs)
{
    uint8_t r[2] = {0};
    int rc = sx_read_cmd(OP_GET_DEVICE_ERRORS, r, 2);
    if (rc != 0)
        return rc;
    *errs = (uint16_t)((r[0] << 8) | r[1]);
    return 0;
}

/* Run the full bring-up sequence. Returns 0, -100 if the XOSC/TCXO failed to
 * start (caller may retry without TCXO), or another negative on SPI error. */
static int init_sequence(void)
{
    hal_rf_switch(RF_SW_OFF);

    /* hardware reset: NRST low >=100us, then release */
    hal_reset_pin(0);
    hal_delay_ms(2);
    hal_reset_pin(1);
    hal_delay_ms(10);
    if (hal_wait_busy_low(BUSY_TIMEOUT_US) != 0) {
        log_err("sx126x: BUSY stuck high after reset (check wiring/power)");
        return -1;
    }

    if (sx_set_standby(STDBY_RC) != 0) {
        log_err("sx126x: SetStandby failed (no SPI response - check SPI/NSS wiring)");
        return -2;
    }
    SX_TRY(sx_write_cmd(OP_SET_REGULATOR, (uint8_t[]){ REG_DCDC }, 1), "SetRegulatorMode");
    sx_write_cmd(OP_CLR_DEVICE_ERRORS, (uint8_t[]){ 0x00, 0x00 }, 2);

    if (g_cfg.tcxo_voltage > 0.0) {
        /* DIO3 -> TCXO: voltage code + 3-byte timeout (5 ms in 15.625us units) */
        uint8_t p[4] = { tcxo_voltage_code(g_cfg.tcxo_voltage), 0x00, 0x01, 0x40 };
        SX_TRY(sx_write_cmd(OP_SET_DIO3_TCXO, p, 4), "SetDIO3AsTCXOCtrl");
        /* recalibrate all blocks after enabling the TCXO clock */
        SX_TRY(sx_write_cmd(OP_CALIBRATE, (uint8_t[]){ 0x7F }, 1), "Calibrate");
        hal_delay_ms(5);
        hal_wait_busy_low(BUSY_TIMEOUT_US);
        SX_TRY(sx_set_standby(STDBY_RC), "SetStandby(post-cal)");

        uint16_t errs = 0;
        if (sx_get_device_errors(&errs) == 0 && (errs & ERR_XOSC_START)) {
            log_warn("sx126x: XOSC/TCXO start error (0x%04X)", errs);
            return -100; /* probably a plain-crystal module: retry without TCXO */
        }
    }

    /* DIO2 drives the on-module antenna switch (no external RXEN/TXEN). */
    if (g_cfg.dio2_rf_switch)
        SX_TRY(sx_write_cmd(OP_SET_DIO2_RF_SWITCH, (uint8_t[]){ 0x01 }, 1), "SetDIO2AsRfSwitch");

    SX_TRY(sx_write_cmd(OP_SET_PACKET_TYPE, (uint8_t[]){ PKT_TYPE_LORA }, 1), "SetPacketType");

    if (set_rf_frequency(g_cfg.freq_mhz) != 0)
        return -3;

    /* PA config for SX1262/SX1268 high power (+22 dBm). deviceSel=0x00 selects
     * the SX1262/1268 high-power PA (0x01 would be the lower-power SX1261). */
    SX_TRY(sx_write_cmd(OP_SET_PA_CONFIG, (uint8_t[]){ 0x04, 0x07, 0x00, 0x01 }, 4), "SetPaConfig");
    SX_TRY(sx_write_register(REG_OCP, &g_cfg.ocp_reg, 1), "SetOCP");

    SX_TRY(sx_write_cmd(OP_SET_TX_PARAMS,
                        (uint8_t[]){ (uint8_t)g_cfg.power_dbm, 0x04 /*160us ramp*/ }, 2),
           "SetTxParams");

    if (set_modem_params(&g_cfg) != 0)
        return -4;

    /* LoRa sync word (2-byte register). MeshCore PRIVATE = 0x1424. */
    {
        uint8_t msb = (uint8_t)(g_cfg.sync_word >> 8);
        uint8_t lsb = (uint8_t)(g_cfg.sync_word & 0xFF);
        SX_TRY(sx_write_register(REG_LORA_SYNC_MSB, &msb, 1), "SyncWordMSB");
        SX_TRY(sx_write_register(REG_LORA_SYNC_LSB, &lsb, 1), "SyncWordLSB");
    }

    SX_TRY(sx_write_cmd(OP_SET_BUF_BASE, (uint8_t[]){ 0x00, 0x00 }, 2), "SetBufferBaseAddress");
    return 0;
}

int sx126x_init(const sx126x_cfg_t *cfg)
{
    g_cfg = *cfg;

    int rc = init_sequence();
    if (rc == -100 && g_cfg.tcxo_voltage > 0.0) {
        log_warn("sx126x: retrying init with TCXO disabled (assuming plain crystal)");
        g_cfg.tcxo_voltage = 0.0;
        rc = init_sequence();
    }
    if (rc != 0) {
        log_err("sx126x: init failed (rc=%d)", rc);
        return rc;
    }

    log_info("sx126x: init ok - %.3f MHz SF%u BW%g CR4/%u %d dBm (chip) sync=0x%04X rf-switch=%s tcxo=%.2fV",
             g_cfg.freq_mhz, g_cfg.sf, g_cfg.bw_khz, g_cfg.cr, g_cfg.power_dbm,
             g_cfg.sync_word, g_cfg.dio2_rf_switch ? "DIO2" : "RXEN/TXEN", g_cfg.tcxo_voltage);
    return 0;
}

int sx126x_set_frequency(double freq_mhz)
{
    g_cfg.freq_mhz = freq_mhz;
    sx_set_standby(STDBY_RC);
    int rc = set_rf_frequency(freq_mhz);
    if (rc != 0)
        return rc;
    return sx126x_start_rx();
}

int sx126x_set_modem(const sx126x_cfg_t *cfg)
{
    /* preserve hardware wiring fields from current config */
    sx126x_cfg_t merged = g_cfg;
    merged.freq_mhz = cfg->freq_mhz;
    merged.bw_khz = cfg->bw_khz;
    merged.sf = cfg->sf;
    merged.cr = cfg->cr;
    merged.preamble = cfg->preamble;
    merged.crc_on = cfg->crc_on;
    merged.iq_inverted = cfg->iq_inverted;
    merged.ldro = cfg->ldro;
    merged.power_dbm = cfg->power_dbm;
    g_cfg = merged;

    sx_set_standby(STDBY_RC);
    sx_write_cmd(OP_SET_TX_PARAMS, (uint8_t[]){ (uint8_t)g_cfg.power_dbm, 0x04 }, 2);
    int rc = set_modem_params(&g_cfg);
    if (rc != 0)
        return rc;
    return sx126x_start_rx();
}

int sx126x_start_rx(void)
{
    sx_set_standby(STDBY_RC);
    sx_clear_irq(IRQ_ALL);
    sx_set_dio_irq(IRQ_RX_DONE | IRQ_CRC_ERR, IRQ_RX_DONE | IRQ_CRC_ERR, 0, 0);
    hal_rf_switch(RF_SW_RX);
    /* SetRx with 0xFFFFFF = continuous receive */
    return sx_write_cmd(OP_SET_RX, (uint8_t[]){ 0xFF, 0xFF, 0xFF }, 3);
}

void sx126x_standby(void)
{
    sx_set_standby(STDBY_RC);
    hal_rf_switch(RF_SW_OFF);
}

int sx126x_poll_rx(uint8_t *buf, size_t bufsz, size_t *len,
                   int16_t *rssi_dbm, int8_t *snr_q)
{
    int d = hal_dio1_read();
    if (d <= 0)
        return d; /* 0 = no irq, <0 = error */

    uint16_t irq = 0;
    if (sx_get_irq(&irq) != 0)
        return -1;

    if (irq & IRQ_RX_DONE) {
        if (irq & IRQ_CRC_ERR) {
            sx_clear_irq(IRQ_ALL);
            return 0; /* dropped: bad CRC */
        }
        uint8_t st[2] = {0};
        if (sx_read_cmd(OP_GET_RX_BUF_STATUS, st, 2) != 0) {
            sx_clear_irq(IRQ_ALL);
            return -2;
        }
        uint8_t payload_len = st[0];      /* PayloadLengthRx */
        uint8_t start_ptr   = st[1];      /* RxStartBufferPointer */
        if (payload_len > bufsz)
            payload_len = (uint8_t)bufsz;
        if (sx_read_buffer(start_ptr, buf, payload_len) != 0) {
            sx_clear_irq(IRQ_ALL);
            return -3;
        }
        *len = payload_len;

        uint8_t ps[3] = {0};
        sx_read_cmd(OP_GET_PACKET_STATUS, ps, 3); /* RssiPkt, SnrPkt, SignalRssiPkt */
        if (rssi_dbm)
            *rssi_dbm = (int16_t)(-(int)ps[0] / 2);
        if (snr_q)
            *snr_q = (int8_t)ps[1]; /* signed quarter-dB */

        sx_clear_irq(IRQ_ALL);
        return 1;
    }

    /* spurious / timeout */
    sx_clear_irq(IRQ_ALL);
    return 0;
}

int sx126x_transmit(const uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    if (len == 0 || len > 255)
        return -10;

    sx_set_standby(STDBY_RC);
    sx_clear_irq(IRQ_ALL);
    set_packet_params_len((uint8_t)len);
    sx_write_cmd(OP_SET_BUF_BASE, (uint8_t[]){ 0x00, 0x00 }, 2);
    if (sx_write_buffer(0x00, buf, len) != 0)
        return -11;
    sx_set_dio_irq(IRQ_TX_DONE | IRQ_TIMEOUT, IRQ_TX_DONE | IRQ_TIMEOUT, 0, 0);

    hal_rf_switch(RF_SW_TX);
    /* SetTx timeout in 15.625us steps; use 0 (no timeout) and police in software */
    if (sx_write_cmd(OP_SET_TX, (uint8_t[]){ 0x00, 0x00, 0x00 }, 3) != 0) {
        log_err("sx126x: SetTx failed");
        hal_rf_switch(RF_SW_OFF);
        sx126x_start_rx();
        return -12;
    }

    uint64_t start = hal_millis();
    int result = -1;
    for (;;) {
        if (hal_dio1_read() == 1) {
            uint16_t irq = 0;
            sx_get_irq(&irq);
            if (irq & IRQ_TX_DONE) { result = 0; break; }
            if (irq & IRQ_TIMEOUT) { result = -1; break; }
        }
        if (hal_millis() - start > timeout_ms) { result = -1; break; }
        hal_delay_us(500);
    }
    sx_clear_irq(IRQ_ALL);
    hal_rf_switch(RF_SW_OFF);

    sx126x_start_rx(); /* always return to RX */
    return result;
}

int sx126x_channel_busy(void)
{
    if (!g_cfg.use_cad)
        return 0; /* LBT disabled */

    /* SF-indexed CAD detection thresholds (Semtech AN1200.48, approx). */
    static const uint8_t det_peak[] = /* SF7..SF12 */ { 22, 22, 23, 24, 25, 28 };
    uint8_t sf = g_cfg.sf;
    uint8_t peak = (sf >= 7 && sf <= 12) ? det_peak[sf - 7] : 24;

    sx_set_standby(STDBY_RC);
    sx_clear_irq(IRQ_ALL);
    sx_set_dio_irq(IRQ_CAD_DONE | IRQ_CAD_DETECTED,
                   IRQ_CAD_DONE | IRQ_CAD_DETECTED, 0, 0);
    /* cadSymbolNum=0x02 (4 symb), detPeak, detMin=10, exitMode=0 (CAD only), timeout=0 */
    uint8_t cad[7] = { 0x02, peak, 0x0A, 0x00, 0x00, 0x00, 0x00 };
    sx_write_cmd(OP_SET_CAD_PARAMS, cad, 7);

    hal_rf_switch(RF_SW_RX);
    sx_write_cmd(OP_SET_CAD, NULL, 0);

    uint64_t start = hal_millis();
    uint16_t irq = 0;
    for (;;) {
        if (hal_dio1_read() == 1) {
            sx_get_irq(&irq);
            if (irq & IRQ_CAD_DONE)
                break;
        }
        if (hal_millis() - start > 100) { irq = 0; break; } /* assume clear on timeout */
        hal_delay_us(500);
    }
    sx_clear_irq(IRQ_ALL);
    hal_rf_switch(RF_SW_OFF);

    return (irq & IRQ_CAD_DETECTED) ? 1 : 0;
}

uint32_t sx126x_airtime_ms(size_t payload_len)
{
    double bw = g_cfg.bw_khz * 1000.0;
    double ts = (double)((uint32_t)1 << g_cfg.sf) / bw; /* symbol time, seconds */
    double t_preamble = (g_cfg.preamble + 4.25) * ts;

    int de = g_cfg.ldro ? 1 : 0;
    int ih = 0;                       /* explicit header */
    int crc = g_cfg.crc_on ? 1 : 0;
    double num = 8.0 * payload_len - 4.0 * g_cfg.sf + 28 + 16 * crc - 20 * ih;
    double den = 4.0 * (g_cfg.sf - 2 * de);
    double ceil_part = ceil(num / den);
    if (ceil_part < 0)
        ceil_part = 0;
    double n_payload = 8 + ceil_part * (double)g_cfg.cr; /* (CR_value+4) == cfg.cr */
    double t_payload = n_payload * ts;

    double total_ms = (t_preamble + t_payload) * 1000.0;
    return (uint32_t)ceil(total_ms);
}
