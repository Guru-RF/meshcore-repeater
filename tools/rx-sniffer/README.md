# rx-sniffer

A receive-only LoRa sniffer for LilyGO SX1262 handhelds (T-LoRa Pager, T-Deck),
for debugging the repeater's downlink at the PHY level. It runs no MeshCore
logic, never transmits, and leaves the display, backlight and audio unpowered.
It listens on the repeater's channel (434.890 MHz, BW 62.5 kHz, SF8, CR 4/8,
sync 0x12, preamble 16) and reports over USB serial:

```
  25.741 RX        37   -94 -11.0    854  1500B0…   good packet: len, RSSI, SNR, freq error (Hz), hex
  68.232 CRC-ERR   37  -117 -17.8    685            heard, but the payload CRC failed
  17.400 HDR-ERR   -   -119 -11.0                   corrupt LoRa header
  42.533 PREAMBLE-ONLY (no header)                  preamble detected, no header followed
  85.000 NOISE    avg -83.2  min -84.0  max -83.0 dBm   [ok 7 crc 0 hdr 0 pre 0]
```

`NOISE` is the instantaneous RSSI (noise floor) once a second. Send `s` over
serial for a noise sweep of 433–436 MHz in 25 kHz steps; a narrow peak is a
spur, and a raised plateau is broadband noise.

## Build and flash

Flashing **replaces the device's firmware**. Reflash Ripple or MeshCore from
their web flashers afterwards.

```
pio run -e tlora-pager -t upload     # T-LoRa Pager
pio run -e tdeck -t upload           # T-Deck
pio run -e tdeck-sf10 -t upload      # T-Deck listening at SF10 (match the repeater)
pio device monitor
```

Pair it with `meshcore-cli probe 3 30` on the repeater. That sends numbered
messages on #mesh, so the counts and gaps show the delivery rate.
