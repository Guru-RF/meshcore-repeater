# LilyGO 433 MHz handhelds drown in their own noise

Measured 2026-10-15 with [`tools/rx-sniffer`](../tools/rx-sniffer/).

Both LilyGO 433 MHz SX1262 handhelds we tested, a T-LoRa Pager and a T-Deck, missed most messages from our 1 W ham MeshCore repeater ON0RFG. The repeater's signal reached them fine; their own electronics raised their noise floor by 15 to 35 dB. Our own RF.Guru pager, with half their transmit power and a 2 cm stub antenna, received every message at the same spot, even through a 20 dB attenuator: at least 20 dB more receive margin.

## Setup

The repeater sent numbered test messages on the #mesh channel every 3 s; each handheld counted what arrived. All three handhelds sat at the same spot.

| Station | Radio | Antenna | Transmit power |
| --- | --- | --- | --- |
| ON0RFG repeater | NiceRF LoRa1268F30-T (SX1268, TCXO) | Procom 0 dBd (2.15 dBi) vertical, 6 m above the roof, via a cavity filter | about 1 W |
| LilyGO T-LoRa Pager (433 MHz) | SX1262 | built-in | 22 dBm |
| LilyGO T-Deck (433 MHz) | SX1262 | LilyGO whip on SMA | 22 dBm |
| RF.Guru pager | RP2040 + RFM96W (SX1276) | 2 cm stub | about 17 dBm |

Channel: 434.890 MHz, 62.5 kHz bandwidth, SF8, coding rate 4/8, preamble 16 (the IARU R1 ham MeshCore channel, licence class 62K5F1D).

To see past the vendor firmware, we flashed both LilyGO devices with a receive-only sniffer: bare RadioLib, display and audio unpowered, never transmitting. Over USB it logs every packet with RSSI, SNR and frequency error, every CRC or header error, and the noise floor once a second.

## Results

Both LilyGO devices sat right at the SF8 decoding limit of about -10 dB SNR, the Pager despite a strong signal.

| Device | Antenna | Noise floor (dBm) | Repeater signal (dBm) | SNR (dB) | Messages decoded |
| --- | --- | --- | --- | --- | --- |
| T-LoRa Pager | built-in | -84 | -91 to -94 | -8 to -11 | 7 of 20 |
| T-Deck | LilyGO whip | -98 | -107 to -110 | -10 to -13 | 14 of 20 |
| T-Deck | RF.Guru stub | -99 | -111 | -12.8 | 1 of 10 |

A quiet receiver in 62.5 kHz bandwidth sits near -115 to -120 dBm. The missed messages left no CRC or header errors: they never rose above the noise. The RF.Guru pager decoded 30 of 30 at the same spot. Switching repeater and T-Deck to SF10 raised the T-Deck on the RF.Guru stub from 1 of 10 to 14 of 20, decoding down to -17.8 dB SNR.

## Where the noise comes from

The handhelds' own electronics radiate into their own antennas. Swapping the T-Deck's antenna for a 50 Ω load dropped its noise floor by 15 dB:

| T-Deck input | Noise floor (dBm) |
| --- | --- |
| LilyGO whip | -98 |
| RF.Guru stub | -99 |
| 50 Ω load | -113 |

The room is not the source: our pager at the same spot still received through a 20 dB attenuator. That leaves the T-Deck's ESP32-S3, display and switching regulators. The T-LoRa Pager's antenna is built in, millimetres from the same parts, so it cannot be terminated; it reads -84 dBm, about 30 dB above a quiet receiver.

A noise sweep from 433 to 436 MHz on the T-Deck was flat at -97 to -102 dBm. That is broadband noise, not a single spur, so moving the channel would not escape it.

## Our pager vs LilyGO: at least 20 dB

The RF.Guru pager keeps at least 20 dB more link margin than either LilyGO handheld. At the same spot, the LilyGO devices sat at the decoding limit with nothing added. Our pager still worked both ways with a 20 dB attenuator in its antenna line, while transmitting about 5 dB less power through a 2 cm stub.

We did not push the attenuation past 20 dB, so the true gap may be larger. The difference is not the radio chip but the board: a quiet RP2040 and OLED next to the antenna instead of an ESP32-S3, colour display and switching regulators.

## Limits and sources

- One unit of each device, one location, one evening.
- SX126x RSSI and noise readings are approximate, to within a few dB.
- During the sniffer runs the LilyGO devices were plugged into a laptop by USB. Earlier the same day, the same T-Deck on MeshCore companion firmware decoded 30 of 30, so position and cabling matter at this margin.
- Separately, Ripple firmware on both LilyGO devices stopped listening for a few seconds after each received message. The sniffer results above exclude any firmware effect.

Sources: [rx-sniffer firmware](../tools/rx-sniffer/) · [LilyGoLib pin maps](https://github.com/Xinyuan-LilyGO/LilyGoLib) · [MeshCore T-Deck variant](https://github.com/meshcore-dev/MeshCore/tree/main/variants/lilygo_tdeck)
