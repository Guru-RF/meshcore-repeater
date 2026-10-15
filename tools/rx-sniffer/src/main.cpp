// RX-only LoRa sniffer for LilyGO SX1262 handhelds (T-LoRa Pager, T-Deck).
//
// Pure PHY debug, no MeshCore logic: the radio sits in continuous receive on the
// repeater's settings and reports over USB serial
//   - every received packet: length, RSSI, SNR, frequency error, payload hex
//   - packets that failed their CRC, and corrupt LoRa headers (with signal)
//   - preambles detected that never produced a header
//   - the noise floor (instantaneous RSSI) once per second
// Send 's' over serial for a noise sweep of 433-436 MHz (finds spurs).
// It never transmits, and leaves the display/backlight/audio unpowered so the
// board's own noise is as low as it gets.
#include <Arduino.h>
#include <SPI.h>
#include <Wire.h>
#include <RadioLib.h>

// ---- the repeater's channel (IARU R1 ham MeshCore) ----
static const float    FREQ_MHZ  = 434.890;
static const float    BW_KHZ    = 62.5;
#ifndef SNIFF_SF
#define SNIFF_SF 8                         // build with -DSNIFF_SF=10 to test other SFs
#endif
static const uint8_t  SF        = SNIFF_SF; // RadioLib sets LDRO itself (symbol >= 16 ms)
static const uint8_t  CR        = 8;       // 4/8
static const uint8_t  SYNC      = 0x12;    // MeshCore private (0x1424)
static const uint16_t PREAMBLE  = 16;
#if defined(BOARD_TDECK)
// ---- T-Deck wiring (LilyGoLib variants/lilygo_tdeck, MeshCore variant) ----
static const char *BOARD = "T-Deck";
static const float TCXO_V = 1.8;
static const bool  DIO2_RFSW = false;
static const int PIN_SCK = 40, PIN_MISO = 38, PIN_MOSI = 41;
static const int LORA_CS = 9, LORA_IRQ = 45, LORA_RST = 17, LORA_BUSY = 13;
static const int OTHER_CS[] = { 39 /*SD*/, 12 /*display*/ };   // share the SPI bus
static const int BOARD_POWERON = 10;                           // peripheral power
#else
// ---- T-LoRa Pager wiring (arduino-esp32 variants/lilygo_tlora_pager) ----
static const char *BOARD = "T-LoRa Pager";
static const float TCXO_V = 1.6;       // RadioLib default, as LilyGoLib uses it
static const bool  DIO2_RFSW = false;  // LilyGoLib doesn't set it either
static const int PIN_SCK = 35, PIN_MISO = 33, PIN_MOSI = 34;
static const int LORA_CS = 36, LORA_IRQ = 14, LORA_RST = 47, LORA_BUSY = 48;
static const int OTHER_CS[] = { 21 /*SD*/, 39 /*NFC*/, 38 /*display*/ };
static const int I2C_SDA = 3, I2C_SCL = 2;
static const uint8_t XL9555_ADDR = 0x20;
static const uint8_t EXPANDS_LORA_EN = 3;                      // XL9555 port 0 bit 3
#endif

SX1262 radio = new Module(LORA_CS, LORA_IRQ, LORA_RST, LORA_BUSY, SPI);

// SX126x IRQ bits (RadioLib's generic RADIOLIB_IRQ_* indexes match them)
static const uint32_t IRQ_RX_DONE   = 1UL << RADIOLIB_IRQ_RX_DONE;
static const uint32_t IRQ_PREAMBLE  = 1UL << RADIOLIB_IRQ_PREAMBLE_DETECTED;
static const uint32_t IRQ_HDR_VALID = 1UL << RADIOLIB_IRQ_HEADER_VALID;
static const uint32_t IRQ_HDR_ERR   = 1UL << RADIOLIB_IRQ_HEADER_ERR;
static const uint32_t IRQ_CRC_ERR   = 1UL << RADIOLIB_IRQ_CRC_ERR;
static const uint32_t IRQ_WATCH     = IRQ_RX_DONE | IRQ_PREAMBLE | IRQ_HDR_VALID |
                                      IRQ_HDR_ERR | IRQ_CRC_ERR;

static uint32_t n_ok, n_crc, n_hdr, n_lost_preamble;

#if !defined(BOARD_TDECK)
static bool xl9555_write(uint8_t reg, uint8_t val)
{
    Wire.beginTransmission(XL9555_ADDR);
    Wire.write(reg);
    Wire.write(val);
    return Wire.endTransmission() == 0;
}

static int xl9555_read(uint8_t reg)
{
    Wire.beginTransmission(XL9555_ADDR);
    Wire.write(reg);
    if (Wire.endTransmission(false) != 0 || Wire.requestFrom(XL9555_ADDR, (uint8_t)1) != 1)
        return -1;
    return Wire.read();
}

// Power the LoRa module: XL9555 port 0 bit 3 as output, driven high.
static bool lora_power_on()
{
    int cfg = xl9555_read(0x06), out = xl9555_read(0x02);
    if (cfg < 0 || out < 0)
        return false;
    return xl9555_write(0x02, (uint8_t)(out | (1 << EXPANDS_LORA_EN))) &&
           xl9555_write(0x06, (uint8_t)(cfg & ~(1 << EXPANDS_LORA_EN)));
}
#else
static bool lora_power_on()
{
    pinMode(BOARD_POWERON, OUTPUT);
    digitalWrite(BOARD_POWERON, HIGH);
    return true;
}
#endif

static void start_rx()
{
    radio.startReceive(RADIOLIB_SX126X_RX_TIMEOUT_INF, IRQ_WATCH, IRQ_WATCH, 0);
}

// How long after a preamble detection a valid header may still arrive: the rest
// of the preamble, 4.25 sync symbols and 8 header symbols, plus margin.
static uint32_t hdr_wait_ms()
{
    float tsym = (float)(1UL << SF) / BW_KHZ;          // ms per symbol
    uint32_t t = (uint32_t)((PREAMBLE + 24) * tsym);
    return t < 200 ? 200 : t;
}

static void stamp()
{
    uint32_t ms = millis();
    Serial.printf("%7lu.%03lu ", (unsigned long)(ms / 1000), (unsigned long)(ms % 1000));
}

// Noise sweep 433.000-436.000 MHz in 25 kHz steps: average instantaneous RSSI
// per step, as a bar chart. A narrow peak is a spur (e.g. a clock harmonic);
// a raised plateau is broadband noise. Then back to the operating channel.
static void sweep()
{
    Serial.println("# sweep: freq MHz  avg RSSI dBm  (bar: -125 .. -60 dBm)");
    for (int k = 0; k <= 120; k++) {
        float f = 433.000f + k * 0.025f;
        radio.setFrequency(f);
        radio.startReceive();
        delay(4);
        float sum = 0;
        for (int i = 0; i < 16; i++) { sum += radio.getRSSI(false); delay(1); }
        float avg = sum / 16;
        int bar = (int)(avg + 125);
        if (bar < 0) bar = 0;
        if (bar > 65) bar = 65;
        Serial.printf("%8.3f %6.1f ", f, avg);
        for (int i = 0; i < bar; i++) Serial.print('#');
        Serial.println(fabsf(f - FREQ_MHZ) < 0.0126f ? "  <== channel" : "");
    }
    radio.setFrequency(FREQ_MHZ);
    radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_ALL);
    Serial.println("# sweep done - back on the channel");
}

void setup()
{
    Serial.begin(115200);
    uint32_t t0 = millis();
    while (!Serial && millis() - t0 < 3000) delay(10);

    // keep every other SPI device deselected before touching the bus
    for (int cs : OTHER_CS) {
        pinMode(cs, OUTPUT);
        digitalWrite(cs, HIGH);
    }
    pinMode(LORA_CS, OUTPUT);
    digitalWrite(LORA_CS, HIGH);
#if !defined(BOARD_TDECK)
    Wire.begin(I2C_SDA, I2C_SCL);
#endif
    bool pwr = lora_power_on();
    delay(20);
    SPI.begin(PIN_SCK, PIN_MISO, PIN_MOSI);

    Serial.printf("\n# rx-sniffer on %s: %.3f MHz BW%.1f SF%u CR4/%u sync 0x%02X preamble %u  (RX only)\n",
                  BOARD, FREQ_MHZ, BW_KHZ, SF, CR, SYNC, PREAMBLE);
    Serial.printf("# LoRa power: %s\n", pwr ? "on" : "FAILED (no expander?)");

    float tcxo = TCXO_V;
    int st = radio.begin(FREQ_MHZ, BW_KHZ, SF, CR, SYNC, 10, PREAMBLE, tcxo, false);
    if (st != RADIOLIB_ERR_NONE) {
        Serial.printf("# begin with TCXO %.1fV failed (%d), retrying as plain crystal\n", tcxo, st);
        tcxo = 0;
        st = radio.begin(FREQ_MHZ, BW_KHZ, SF, CR, SYNC, 10, PREAMBLE, tcxo, false);
    }
    if (st != RADIOLIB_ERR_NONE) {
        Serial.printf("# radio init FAILED (%d) - halting\n", st);
        for (;;) delay(1000);
    }
    radio.setDio2AsRfSwitch(DIO2_RFSW);
    radio.setRxBoostedGainMode(true);
    radio.setCRC(true);
    Serial.printf("# radio ok (TCXO %.1fV, boosted RX gain) - listening\n", tcxo);
    Serial.println("# columns: time  event  len  rssi  snr  ferr(Hz)  payload");
    start_rx();
}

void loop()
{
    static uint32_t preamble_at = 0;
    static float nf_sum = 0, nf_min = 0, nf_max = -200;
    static int nf_n = 0;
    static uint32_t last_nf = 0, last_report = 0;

    if (Serial.available() && Serial.read() == 's') {
        sweep();
        preamble_at = 0;
        start_rx();
    }

    uint32_t f = radio.getIrqFlags();

    if (f & IRQ_PREAMBLE && !preamble_at)
        preamble_at = millis();

    if (f & IRQ_HDR_ERR) {
        n_hdr++;
        stamp();
        Serial.printf("HDR-ERR  -    %4.0f %5.1f\n", radio.getRSSI(), radio.getSNR());
        radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_ALL);
        preamble_at = 0;
        start_rx();
    } else if (f & IRQ_RX_DONE) {
        uint8_t buf[256];
        size_t len = radio.getPacketLength();
        int st = radio.readData(buf, len);
        float rssi = radio.getRSSI(), snr = radio.getSNR();
        long ferr = (long)radio.getFrequencyError();
        stamp();
        if (st == RADIOLIB_ERR_CRC_MISMATCH || (f & IRQ_CRC_ERR)) {
            n_crc++;
            Serial.printf("CRC-ERR  %3u  %4.0f %5.1f %6ld\n", (unsigned)len, rssi, snr, ferr);
        } else {
            n_ok++;
            Serial.printf("RX       %3u  %4.0f %5.1f %6ld  ", (unsigned)len, rssi, snr, ferr);
            for (size_t i = 0; i < len; i++) Serial.printf("%02X", buf[i]);
            Serial.println();
        }
        radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_ALL);
        preamble_at = 0;
        start_rx();
    } else if (preamble_at && !(f & IRQ_HDR_VALID) && millis() - preamble_at > hdr_wait_ms()) {
        // a preamble was seen but no header followed: weak/partial packet
        n_lost_preamble++;
        stamp();
        Serial.println("PREAMBLE-ONLY (no header)");
        radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_ALL);
        preamble_at = 0;
        start_rx();
    }

    // noise floor: sample instantaneous RSSI every 50 ms while idle
    if (!preamble_at && millis() - last_nf >= 50) {
        last_nf = millis();
        float r = radio.getRSSI(false);
        nf_sum += r; nf_n++;
        if (nf_n == 1 || r < nf_min) nf_min = r;
        if (r > nf_max) nf_max = r;
    }
    if (millis() - last_report >= 1000 && nf_n > 0) {
        last_report = millis();
        stamp();
        Serial.printf("NOISE    avg %5.1f  min %5.1f  max %5.1f dBm   [ok %lu crc %lu hdr %lu pre %lu]\n",
                      nf_sum / nf_n, nf_min, nf_max, (unsigned long)n_ok, (unsigned long)n_crc,
                      (unsigned long)n_hdr, (unsigned long)n_lost_preamble);
        nf_sum = 0; nf_n = 0; nf_max = -200;
    }
    delay(1);
}
