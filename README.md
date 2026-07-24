# meshcore-repeater

A plain-C [MeshCore](https://meshcore.co.uk) **repeater** for the
**Raspberry Pi** driving a **NiceRF LoRa1268F30-433** (Semtech **SX1268**) module.

It is a from-scratch C port, inspired by
[pyMC_Repeater](https://github.com/pyMC-dev/pyMC_Repeater), with:

- a **hand-written SX1268 driver** (no RadioLib) over `spidev` + `libgpiod`;
- the **MeshCore wire format** and **flood/direct forwarding** logic, verified
  against the upstream [MeshCore](https://github.com/meshcore-dev/MeshCore)
  source so it interoperates with stock MeshCore nodes;
- **Ed25519-signed adverts** (TweetNaCl), so the repeater is visible to MeshCore
  clients for path discovery;
- a **fully runtime-configurable radio** (frequency, SF, BW, CR, power, sync
  word) via a config file and a local CLI — change frequency without recompiling.

Built for a **70 cm ham-only MeshCore mesh**: the default frequency (433.500 MHz)
stays clear of LoRa-APRS (~433.775 MHz).

> Scope: this is a *repeater* (relay + signed advert + stats), not a client.
> It forwards by route type and never decrypts payloads, so text messages, ACKs,
> requests, etc. all relay without any keys. There is **no over-the-mesh admin
> login** (by design) — configuration is local only.

---

## What it does

For every received LoRa packet:

1. Parse the MeshCore header / path / payload.
2. **Deduplicate** via an 8-byte SHA-256 hash ring (160 entries) — already-seen
   packets are dropped (loop prevention).
3. **ADVERT** packets: verify the Ed25519 signature; forged adverts are dropped,
   valid ones update the neighbour table and are re-flooded.
4. **Flood** packets: append our 1-byte path hash, then retransmit after a
   randomised, airtime-proportional delay (CSMA), bounded by the 64-byte path.
5. **Direct** packets: if we are the next hop (`path[0]`), strip ourselves and
   retransmit at highest priority.

It also emits its own signed `REPEATER` advert periodically, does
listen-before-talk (CAD) before transmitting, and keeps live stats.

The forwarding constants match MeshCore (`Mesh.cpp`):

| Behaviour              | Value |
|------------------------|-------|
| dedup ring size        | 160 packet hashes (8 bytes each) |
| flood retransmit delay | `rand(0..5) × (airtime × 1.04 / 2)` ms |
| direct retransmit delay| 0 ms (highest priority) |
| CAD-busy backoff       | `rand(1..4) × 120` ms |
| path bound             | `(hops+1) × hash_size ≤ 64` |

---

## Hardware & wiring

The LoRa1262F30/LoRa1268F30 is an SX126x radio with an on-board PA/LNA. On this
board the antenna switch is driven **internally by the chip's DIO2** (the module
exposes no RXEN/TXEN pins), and **NSS is a plain GPIO** (not the hardware CE), so
the firmware drives chip-select manually. Logic is **3.3 V**; SPI is **mode 0**, ≤ 10 MHz.

Default wiring (matches the reference schematic — RPi 40-pin header):

| Module pin | Function           | RPi BCM | Header pin | config key |
|------------|--------------------|---------|-----------|------------|
| MOSI       | SPI MOSI           | GPIO10  | 19        | `/dev/spidev0.0` |
| MISO       | SPI MISO           | GPIO9   | 21        | |
| SCK        | SPI clock          | GPIO11  | 23        | |
| NSS        | chip select (out)  | GPIO21  | 40        | `gpio_nss` (manual GPIO) |
| NRST       | reset (out)        | GPIO18  | 12        | `gpio_reset` |
| BUSY       | busy (in)          | GPIO20  | 38        | `gpio_busy` |
| DIO1       | irq (in)           | GPIO16  | 36        | `gpio_dio1` |
| DIO2       | RF switch (chip)   | —       | —         | `rf_switch = dio2` |
| DIO3       | TCXO (chip)        | —       | —         | `tcxo_voltage` |
| VCC        | 3.0–6.5 V (here 5 V)| —      | 2/4       | **separate supply** for +30 dBm |
| GND        | ground             | GND     | many      | common with Pi |
| "ON" LED   | status (out)       | GPIO19  | 35        | `gpio_led_on` |
| "DATA" LED | activity (out)     | GPIO26  | 37        | `gpio_led_data` |

Set any of these to match your wiring in `meshcore-repeater.conf`. On a
**Raspberry Pi 5** set `gpio_chip = gpiochip4`.

- **NSS on GPIO21:** because NSS isn't on the hardware CE0, the driver opens SPI
  with `SPI_NO_CS` and toggles GPIO21 around each command. CE0 (GPIO8) is left free.
- **Antenna switch:** `rf_switch = dio2` makes the SX126x raise DIO2 during TX to
  flip the on-module RF switch. If your module instead exposes RXEN/TXEN, set
  `rf_switch = external` and wire `gpio_rxen`/`gpio_txen`.
- **TCXO vs crystal:** if the module has a plain crystal (no TCXO), init detects
  the XOSC-start error and automatically retries with the TCXO disabled. You can
  also force it with `tcxo_voltage = 0`.
- **LEDs:** the **ON** LED is solid while the repeater runs; the **DATA** LED
  pulses on each received/transmitted packet. Set `use_leds = false` to disable.

> ⚠️ Powering VCC from the Pi's 5 V rail (as in the schematic) is OK for a
> repeater's low TX duty cycle **with the decoupling shown** (47 µF + 2×2.2 µF +
> 100 nF), but a +30 dBm burst pulls ~650 mA — use a good Pi PSU and short, thick
> VCC/GND wiring, or a separate 5 V supply, to avoid brown-outs mid-transmit.

### Power (important)

At **+30 dBm the module draws ~650 mA peak at ~4 V**. **Do not** power it from the
Pi's 3.3 V rail. Use a separate regulated 4–6 V supply with bulk (100 µF) +
low-ESR ceramic (10 µF) decoupling right at the module VCC; keep droop < 0.1 V or
the SX1268 will brown out mid-transmission. Always have a 50 Ω antenna/load
connected before keying TX.

### Enable SPI on the Pi

```
sudo raspi-config        # Interface Options -> SPI -> enable   (or:)
# add 'dtparam=spi=on' to /boot/firmware/config.txt and reboot
```

---

## Build

On the Raspberry Pi:

```
sudo apt install build-essential libgpiod-dev
make                 # -> ./meshcore-repeater
make test            # host self-test (no hardware required)
```

`make test` builds and runs the protocol self-test (wire format, Ed25519,
advert sign/verify, dedup, flood/direct forwarding). It needs no radio and runs
on any POSIX host.

---

## Run

```
./meshcore-repeater -c meshcore-repeater.conf
```

On first run it generates an Ed25519 identity into `repeater.key` (keep this
file private — it is your node's secret key) and prints the node id.

Flags: `-c <file>` config, `-v` verbose, `-q` quiet, `--genkey` (write a key and
exit), `-h` help.

### Install as a service

```
sudo make install
sudoedit /etc/meshcore-repeater.conf
sudo systemctl enable --now meshcore-repeater
```

(Grant SPI/GPIO access by adding the service user to the `spi`/`gpio` groups, or
run as root.)

---

## Configuration

Everything is in `meshcore-repeater.conf` (`key = value`, `#` comments) and can
be changed live from the CLI. Radio defaults match the MeshCore network so the
repeater interoperates with stock nodes:

| key | default | meaning |
|-----|---------|---------|
| `frequency` | `433.500` | MHz — keep clear of LoRa-APRS (~433.775) |
| `bandwidth` | `250` | kHz — one of 62.5 / 125 / 250 / 500 |
| `spreading_factor` | `10` | |
| `coding_rate` | `5` | 4/5 |
| `tx_power` | `22` | SX1268 **chip** dBm (PA adds gain → ~+30 dBm) |
| `sync_word` | `private` | MeshCore `PRIVATE` (0x1424); `public` = 0x3444 |
| `use_cad` | `true` | listen-before-talk |
| `advert_interval` | `7200` | seconds between self-adverts (0 = off) |
| `name` | `HamRepeater` | advertised node name |

> To interoperate with other MeshCore nodes, **`bandwidth`, `spreading_factor`,
> `coding_rate` and `sync_word` must match them.** Only change `frequency` (and
> the matching params on your other nodes) to move your ham mesh off a busy
> channel.

### Local CLI

Type into the running process's stdin:

```
help                  list commands
status                uptime, identity, stats, neighbour count
neighbors             nodes heard (id, name, type, rssi, snr, age)
freq 434.0            retune live
set tx_power 20       change a parameter (radio keys apply immediately)
get frequency         read a value
advert                send a self-advert now
save                  write the current config back to the file
quit                  stop
```

---

## Frequency / legal notes

- Default **433.500 MHz** sits in the 70 cm band and, with 250 kHz bandwidth,
  does not overlap LoRa-APRS at ~433.775 MHz. `434.000 MHz` is another clean
  choice. Avoid 433.775 and 433.900.
- **+30 dBm (1 W) EIRP may exceed what your licence class/region permits.** The
  default `tx_power = 22` drives the chip to its maximum; confirm the actual
  antenna power and your legal limit, and lower `tx_power` if needed.
- This is an amateur-radio project; operate within your licence.

---

## Known limitations / TODO

- **TRACE** (path-discovery) packets are received and counted but not yet
  relayed (to avoid corrupting trace path semantics). Other packet types relay
  normally.
- The **NiceRF PA chip-power setpoint for exactly +30 dBm** is module-specific
  (sources suggest the chip at +19…+22 dBm). Verify against the datasheet / a
  power meter and tune `tx_power` + `ocp`.
- Single-threaded blocking TX (fine for a repeater's duty cycle).
- No over-the-mesh admin/telemetry protocol (local CLI only) — by design.

---

## Layout

```
src/
  main.c          event loop (rx -> mesh -> tx queue -> advert -> CLI)
  packet.[ch]     MeshCore wire format, path encoding, dedup hash
  mesh.[ch]       repeater core: dedup, flood/direct forward, TX queue, CSMA
  identity.[ch]   Ed25519 keys, sign/verify, path hash
  advert.[ch]     signed REPEATER self-advert build/verify
  sx126x.[ch]     plain-C SX1268 driver (opcodes, init, TX/RX, CAD, airtime)
  hal.[h]         hardware abstraction interface
  hal_linux.c     spidev + libgpiod + timing + RNG (the real HAL)
  config.[ch]     config file parse + runtime get/set
  cli.[ch]        local operator console
  log.[ch], util.[ch]
  crypto/         vendored TweetNaCl (Ed25519/SHA-512) + B-Con SHA-256
tools/
  selftest.c      host unit tests       mock_hal.c   no-hardware HAL
```

## Credits / licences

- Protocol & forwarding logic ported from
  [MeshCore](https://github.com/meshcore-dev/MeshCore) (the C++ original).
- Inspired by [pyMC_Repeater](https://github.com/pyMC-dev/pyMC_Repeater).
- Vendored crypto: [TweetNaCl](https://tweetnacl.cr.yp.to/) (public domain) and
  Brad Conte's [SHA-256](https://github.com/B-Con/crypto-algorithms) (public domain).
