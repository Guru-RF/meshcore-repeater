# meshcore-repeater

A plain-C **[MeshCore](https://meshcore.co.uk) ham-radio repeater** for the
**Raspberry Pi**, built for the **[RF.Guru](https://rf.guru) MeshCore 30 dBm
(1 W) hat** — a 70 cm Semtech **SX1268** board with a filtered, surge- and
ESD-protected, RF-shielded front end (*soon available; currently in
pre-production testing*).

It implements the **[IARU Region 1 ham-MeshCore RFC](https://github.com/Guru-RF/meshcore-rfc-iaru-r1)**:
a single dedicated 70 cm ham-only frequency — **434.890 MHz, 62.5 kHz, SF8,
CR4:8** on MeshCore's public channel — so licensed amateurs across Region 1 run
one interoperable LoRa mesh, clear of unlicensed ISM traffic. (The occupied band
is ~434.859–434.921 MHz; nothing is emitted above 435.000 MHz, protecting the
amateur-satellite segment.)

It also enforces a strict **ham content policy**: only unencrypted public-channel
traffic and signed adverts are relayed — private (encrypted) messages are dropped,
since amateur radio forbids obscuring the meaning of a transmission.

Under the hood:

- a **hand-written SX1268 driver** (no RadioLib) over `spidev` + `libgpiod`;
- the **MeshCore wire format** and **flood/direct forwarding**, verified against
  upstream [MeshCore](https://github.com/meshcore-dev/MeshCore) so it interoperates
  with stock MeshCore nodes;
- **Ed25519-signed adverts** (TweetNaCl) for path discovery;
- strict **public-only forwarding** with configurable public channels, **ping/pong**,
  a **blacklist**, and a local **`meshcore-cli`** control interface;
- a **fully runtime-configurable radio** (frequency, SF, BW, CR, power, sync word)
  via a config file and CLI — no recompile to retune.

> Scope: this is a *repeater* (relay + signed advert + stats), not a client.
> Configuration is local only (config file + `meshcore-cli`); there is **no
> over-the-mesh admin login**, by design. Originally a from-scratch C port
> inspired by [pyMC_Repeater](https://github.com/pyMC-dev/pyMC_Repeater).

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

### The RF.Guru 1 W hat

This repeater targets the **[RF.Guru](https://rf.guru) MeshCore 30 dBm (1 W)
hat** — an SX1268 Raspberry Pi HAT with a clean, protected 70 cm front end:

- a **2RL090M-5-ST5** gas discharge tube (GDT, 90 V, 5 kA, ~1 pF) on the antenna
  for surge / lightning protection — its ~1 pF capacitance barely loads the RF;
- a **TPESD5V0R1BBSFYL** bidirectional low-capacitance ESD-protection diode;
- a **Taoglas DBP.433.T.A.30** 433 MHz dielectric band-pass filter;
- housed in a **machined aluminium case for RF shielding**.

*Pre-production — soon available from [rf.guru](https://rf.guru).* The firmware
also runs on a bare SX126x module (e.g. NiceRF LoRa1268F30-433) wired as below.

### SX126x wiring

The SX126x carries an on-board PA/LNA. On this board the antenna switch is driven
**internally by the chip's DIO2** (no RXEN/TXEN pins), and **NSS is a plain GPIO**
(not the hardware CE), so the firmware drives chip-select manually. Logic is
**3.3 V**; SPI is **mode 0**, ≤ 10 MHz.

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

## Quick install (Raspberry Pi)

One line on a fresh **Raspberry Pi OS (64-bit)** image:

```bash
wget -qO /tmp/install-repeater.sh https://raw.githubusercontent.com/Guru-RF/meshcore-repeater/main/install-repeater.sh && sudo bash /tmp/install-repeater.sh
```

That is the whole install. `install-repeater.sh`:

1. **Upgrades the Pi** — `apt-get update`, `full-upgrade`, `autoremove`, `clean`.
2. **Installs the dependencies** — `build-essential`, `git`, `curl`, and
   [gum](https://github.com/charmbracelet/gum) for the prompts (distro package
   first, then Charm's apt repo; plain text prompts if neither is reachable, so
   the install never dead-ends on a cosmetic dependency). The radio build deps
   (`libgpiod-dev`, `libreadline-dev`) are pulled in by `install.sh`.
3. **Builds and installs** — compile, host self-test, then binary + default
   config + `meshcore-repeater.service` into `/opt/meshcore-repeater/`, run by a
   dedicated `meshcore` user and enabled on boot.
4. **Enables SPI and the LED GPIOs** in `/boot/firmware/config.txt` (the LED
   lines come from `gpio_led_on`/`gpio_led_data`, default `19`/`26`). The file it
   found is kept as `config.txt.meshcore.bak`.
5. **Asks for your callsign** — it becomes the repeater's node name, i.e. its
   **on-air ID** (amateur radio requires an automatic station to identify) — plus
   an optional [position](#finding-your-position) and an optional APRS-IS iGate
   (`ON0RFG` + SSID `5` → `ON0RFG-5`, passcode derived automatically). It writes
   them into `meshcore-repeater.conf`.
6. **Offers to reboot**, which SPI needs before `/dev/spidev0.x` appears.

Run it again any time to **upgrade in place**: it notices the repeater is already
installed and just refreshes the binary from the latest sources — your config,
callsign and the service's running state are left untouched, and it asks nothing
(steps 1, 2, 4, 5 and 6 above are all skipped). A running repeater is left alone.

> On a **first** install, `wget -qO- … | sudo bash` works too — the script notices
> it was piped, where stdin is the script rather than you, and re-attaches to your
> terminal so the prompts still work. (An upgrade needs no terminal at all.)

Prefer to do it from a checkout (skips the apt upgrade and the interactive
prompts — edit the config by hand afterwards)?

```
git clone https://github.com/Guru-RF/meshcore-repeater && cd meshcore-repeater
sudo ./install.sh
```

Then edit `/opt/meshcore-repeater/meshcore-repeater.conf` (callsign, frequency,
optional APRS iGate) and `sudo systemctl start meshcore-repeater`. See
[Install as a service](#install-as-a-service) for what it sets up.

### Finding your position

Nobody knows their own latitude, so the optional position step takes an address
and looks it up:

```text
Location -- a full street address gives the most accurate fix, and Belgium is
assumed if you leave the country off. Empty to type coordinates yourself:
> Grote Markt 1, Brugge

Looking up Grote Markt 1, Brugge, Belgium ...
Historium, 1, Markt, Brugge-Centrum, Brugge, West-Vlaanderen, 8000, België
Found 51.2092401, 3.2250659
Ground elevation there is about 13 m
```

Geocoding is [Nominatim](https://nominatim.openstreetmap.org) and the elevation
comes from [Open-Meteo](https://open-meteo.com) — both free, neither needs an API
key. Paste `51.2194, 4.4025` straight in and it skips the lookup. The step
soft-fails: no `curl`, no internet or no match keeps whatever the config already
holds, and the address you type is never stored, only the coordinates. Those
coordinates go out in every advert, so round them off if you would rather not
publish your doorstep.

## Build (manual)

```
sudo apt install build-essential pkg-config libgpiod-dev libreadline-dev
make                 # -> ./meshcore-repeater + ./meshcore-cli
make test            # host self-test (no hardware required)
```

`make test` builds and runs the protocol self-test (wire format, Ed25519,
advert sign/verify, dedup, forwarding, APRS passcode/position). It needs no
radio and runs on any POSIX host. `libreadline-dev` is optional (enables
`meshcore-cli` tab-completion).

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

`sudo make install` does it all in one go: creates a dedicated `meshcore` system
user, installs the binary, config and systemd unit **self-contained under
`/opt/meshcore-repeater`** (the generated `repeater.key` lands there too), and
reloads systemd. Then review the config and enable it:

```
sudo make install
sudoedit /opt/meshcore-repeater/meshcore-repeater.conf
sudo systemctl enable --now meshcore-repeater
journalctl -u meshcore-repeater -f            # watch it run
```

- Hardware access comes from the unit's `SupplementaryGroups=spi gpio`, so those
  groups must exist (they do on Raspberry Pi OS); the `meshcore` user needs no
  login and no extra setup.
- `make install` **won't overwrite** an existing `/opt/meshcore-repeater/meshcore-repeater.conf`,
  so upgrades keep your settings — rebuild and re-run `sudo make install`, then
  `sudo systemctl restart meshcore-repeater`.
- **Node identity is preserved:** if a `repeater.key` sits next to the checkout
  and `/opt` has none yet, `make install` copies it in (mode `600`), so the
  installed repeater keeps the same node id. A fresh install with no key just
  generates one on first run.
- Running as a service is **headless** — the interactive stdin CLI is unavailable
  (`StandardInput=null`); manage it with `systemctl`/`journalctl`, and
  `systemctl restart` after editing the config. Add `-v` to `ExecStart`
  (via `sudo systemctl edit meshcore-repeater`) for verbose journal logging.
- `sudo make uninstall` removes the service (leaving `/opt` data + the user).

To run in place for development instead (interactive CLI, no install), just
`./meshcore-repeater -v` from the checkout.

---

## Configuration

Everything is in `meshcore-repeater.conf` (`key = value`, `#` comments) and can
be changed live from the CLI. Defaults follow the
[IARU R1 ham-MeshCore RFC](https://github.com/Guru-RF/meshcore-rfc-iaru-r1) so
the repeater joins that network out of the box:

| key | default | meaning |
|-----|---------|---------|
| `frequency` | `434.890` | MHz — IARU R1 ham-MeshCore calling QRG (≤ 435.000) |
| `bandwidth` | `62.5` | kHz — one of 62.5 / 125 / 250 / 500 |
| `spreading_factor` | `8` | RFC |
| `coding_rate` | `8` | 4/8 (RFC) |
| `tx_power` | `22` | SX1268 **chip** dBm (the hat's PA reaches ~+30 dBm / 1 W) |
| `sync_word` | `private` | MeshCore default (0x1424); `public` = 0x3444 |
| `use_cad` | `true` | listen-before-talk |
| `advert_interval` | `1800` | seconds between self-adverts (0 = off); 30 min guarantees the mandatory ≥1 ID/hour with margin |
| `name` | `HamRepeater` | advertised node name |
| `public_channel` | *Public* | public channel key(s) to relay (repeatable) — see below |
| `room` | *(none)* | transport `#region`(s) to relay, key auto-derived (repeatable) — see below |
| `ping_pong` | `false` | answer `ping` on a public channel with `pong` |
| `control_port` | `4403` | local `meshcore-cli` port on 127.0.0.1 (0 = off) |

> To interoperate with the mesh, **`frequency`, `bandwidth`, `spreading_factor`,
> `coding_rate` and `sync_word` must match** — the defaults above already do, per
> the RFC. Keep the whole occupied band (~434.859–434.921 MHz at 62.5 kHz) below
> **435.000 MHz** to protect the amateur-satellite segment.

### Content policy — forward public, drop private

Amateur radio forbids relaying messages whose meaning is obscured, so this
repeater does **not** relay encrypted private traffic. It applies a strict
allow-list and drops anything not provably public:

| MeshCore payload | relayed? | why |
|------------------|----------|-----|
| Advert | ✅ | Ed25519-**signed** but plaintext (readable), verified before relay |
| Trace | ✅ | plaintext |
| Group message on a **configured public channel** | ✅ | key is published → not obscured |
| Group message tagged for a **served `#room` region** | ✅ | opt-in; you declared that transport region public |
| Direct/private message (DM, request, ACK, path…) | ❌ | end-to-end encrypted → obscured |
| Group message on any other channel | ❌ | unknown key → obscured |

A group message is relayed only if its channel **MAC verifies** against one of
your configured public channels (MeshCore's `HMAC-SHA256`, checked without
decrypting). Declare each public channel by its **published** key — base64 or
hex, 16- or 32-byte, optional `name:` label; repeatable:

```
public_channel = izOH6cXN6mrJ5e26oRXNcg==            # MeshCore default "Public"
public_channel = MyClub:8b3387e9c5cdea6ac9e5edbaa115cd72   # hex, named
```

With **no** `public_channel` entries the repeater relays adverts only (all group
and private traffic is dropped) — a valid ADVERT-only beacon. `channels` in the
CLI lists what's configured; `status` shows the `policy:` counters
(`grp-public`, `denied`, `mac-fail`).

> Only configure channels whose key is genuinely **published to the public** —
> that published key is what makes relaying the traffic legal. The repeater
> proves a message belongs to a configured channel, but it cannot judge whether
> *you* were entitled to call that key public.

### Hashtag rooms / channels

A MeshCore **hashtag channel** (a.k.a. hashtag room) named `#something` has a key
that is **auto-derived from the name** — `SHA256("#name")[:16]` — so you configure
one by **name only**, never a key:

```
room = sysop            # BARE name in the config file — '#' starts a comment
room = ora              # here, so the daemon adds the '#' and derives the key
```

(In the config **file** the value must be the bare name; `#` can't appear because
it starts a comment. Via `meshcore-cli`, `set room sysop` and `set room #sysop`
both work.)

That one derived key is used **two ways**, so `room = sysop` covers both shapes a
network might send:

- **As a channel key** (the common case): the repeater holds the key, so it
  **decrypts, forwards, and lets you `monitor`** the channel's plain-flood group
  messages — `meshcore-cli monitor #sysop` shows the text. It appears in
  `channels` as a derived channel and counts under the `policy: grp-public` stats.
- **As a transport region**: for networks using MeshCore **Transport**, a
  `TRANSPORT_FLOOD` whose `transport_codes[0]` matches
  `HMAC-SHA256(key, payload_type‖payload)[:2]` is also relayed (see the `rooms`
  line in `status` — `transport-flood-seen`/`region-relayed`).

This does **not** relax the content policy: the repeater holds the (name-derived,
public) key, so it can prove the message really is that public channel — DMs and
any channel/region you haven't listed are still dropped. Only list `#names` whose
key is genuinely public and that you're content to relay in the clear on the ham
band (anyone who knows the name can derive the key — it's not authentication).

### Ping/pong

With `ping_pong = true` (and at least one `public_channel`), sending `ping` on a
public channel makes the repeater reply on that same channel — a quick
liveness/coverage check. It decrypts only public-channel text (using the
published key), matches an exact `ping`, and broadcasts back the signal it heard
your ping at:

```
<name>: pong rssi -95dBm snr 7.5dB
```

so you learn both that the repeater is alive and how well it received you.

### Verbose (`-v`)

Run with `-v` to log activity as it happens: decrypted **public** messages
(`[public …]`), received **adverts** with name/type/GPS (`[advert …]`), every
packet the policy **drops** with the reason (`[ignored …]`), and every packet
the repeater **transmits** (`[tx] <type> <flood|direct> <bytes> <hops> airtime`).
Private traffic is still never decrypted — only public-channel content is shown.

### Local CLI

Commands (type into the process's stdin when run interactively, **or** drive the
service with `meshcore-cli` — see below):

```
help                  list commands
status                uptime, identity, stats, neighbour count
neighbors             nodes heard (id, name, type, rssi, snr, age)
channels              configured public channels
blacklist add|remove|list <name>   ignore a node by name
monitor [all|public|<chan>|#room]  stream live messages (meshcore-cli only)
freq 434.0            retune live
set tx_power 20       change a parameter (radio keys apply immediately)
get frequency         read a value
advert                send a self-advert now
save                  write the current config back to the file
quit                  stop
```

### Control interface (`meshcore-cli`)

Run as a service the repeater has no stdin, so it exposes the same CLI on a
**loopback-only** TCP port (`control_port`, default `4403`). The bundled
`meshcore-cli` client (installed to `/usr/local/bin` by `make install`) talks to
it:

```
meshcore-cli status                  # one-shot
meshcore-cli blacklist add ON0XYZ    # ignore a node (auto-saved to config)
meshcore-cli blacklist list
meshcore-cli set frequency 434.0
meshcore-cli                         # interactive (reads commands from stdin)
meshcore-cli -p 4403 status          # override port (or MESHCORE_PORT env)
```

The port is bound to `127.0.0.1` only (never the network); any local user can
use it, so it's meant for a single-admin repeater host. Set `control_port = 0`
to disable it.

In interactive mode `meshcore-cli` supports **tab-completion** (commands,
`blacklist` sub-commands, and `set`/`get` keys) and history when built against
GNU readline — install `libreadline-dev` before `make` for it (otherwise it
falls back to plain line input, and the build prints a note).

**Live monitor (debugging):** `meshcore-cli monitor [target]` holds the
connection open and streams messages as they pass through the repeater until you
`Ctrl-C`. Targets:

```
meshcore-cli monitor            # everything: public msgs, region hits, drops
meshcore-cli monitor public     # decrypted text on any public channel
meshcore-cli monitor MyClub     # decrypted text on the channel named "MyClub"
meshcore-cli monitor #sysop     # a transport region — opaque, so metadata only
```

A **public channel** is decrypted (you hold the key), so the message text is
shown: `12:30:01 [public MyClub] ON4XYZ: hello  (rssi -72 snr 8.0)`. A **`#room`**
region is relayed *without* the key, so only metadata is available:
`12:30:04 [room #sysop] relayed  type=0x05  len=42B  (rssi -80 snr 5.0)`. Up to
four monitors can run at once; a slow/gone client is dropped and never stalls
forwarding.

**Blacklist / moderation:** `blacklist add <name>` ignores a node by its
advertised / public-channel name — its adverts are neither relayed nor
registered as neighbours, and its public messages are dropped (and not answered
by ping/pong). Names are self-reported (spoofable), so this is lightweight
moderation, not authentication. Changes are saved to the config immediately.

---

## APRS-IS iGate

With `aprs_enable = true` the repeater becomes a **receive-only APRS iGate**: it
connects to APRS-IS, beacons its own position, and gates the position of any
MeshCore node whose advert carries GPS **and whose name is a valid amateur
callsign** onto the global APRS network (visible on [aprs.fi](https://aprs.fi)).

```
aprs_call     = ON6URE-6            # your callsign — login + beacon source
aprs_passcode = auto                # computed from aprs_call (or set the number)
aprs_altitude = 5                   # metres, for /A=
location = true, latitude/longitude # the iGate beacon reuses these
```

How it works (all verified against the APRS spec / APRS-IS docs):

- **Login** uses your callsign + passcode (`auto` runs the standard passcode
  algorithm). Injecting **requires a valid passcode** — an unverified session is
  silently dropped by the server.
- **Own beacon** — `ON6URE-6>APRFGR,TCPIP*:!<pos>` with the Rx-iGate symbol `R&`,
  every `aprs_beacon_interval` (default 30 min).
- **Gated nodes** — `<NODECALL>APRFGR,qAO,ON6URE-6:!<pos> MeshCore <type>`, symbol
  `Mn`. `qAO` honestly marks it receive-only (we can't gate APRS→RF). Rate-limited
  per node (`aprs_node_rate`), and the repeater never gates its own advert.
- **Callsign filter** — only names shaped like real ham calls (prefix+digit+suffix,
  optional `-SSID`) are gated, so free-text node names never pollute APRS-IS.

> Requires an amateur licence — you transmit onto APRS-IS under your own
> callsign. `aprs_call` must be unique on APRS-IS. The gate is receive-only
> toward APRS (MeshCore is never fed from the internet). A node gated under a
> bare callsign that is *also* active on 144.800 MHz APRS will show two
> positions on aprs.fi — that's inherent to callsign-based gating.

Networking is non-blocking and shares the main loop (no extra thread); the
APRS-IS host is resolved once at startup so DNS never stalls the radio.

---

## Roles: repeater vs personal hotspot

`role = repeater` (default) is a full licensed wide-area repeater. `role = hotspot`
turns it into a **personal bridge** for a licensed operator (same ham band, same
strict content policy) with **direction-dependent TX power**:

- Traffic heard **locally from your own devices** (`home = ON6URE*`, plus
  friends/neighbours) is relayed **up** to the repeater network at **full** power
  (to reach it). Anything else heard locally is ignored — it only bridges *your* devices.
- Traffic that arrived **via a real repeater** (`affinity = ON0XYZ`) is relayed
  back **down** to the household at the **lowest usable** power.

Direction is read straight from the packet's path: a message carrying an affinity
repeater's 1-byte path-hash came from the mesh (downlink → low power), otherwise it
was heard locally (uplink → full power). Affinity repeaters are learned from their
signed adverts. Adverts are classified by advertiser instead (a repeater's advert
goes down to the household; your device's advert goes up to the mesh).

```
role               = hotspot
name               = ON6URE-1      # a hotspot may carry an SSID (see below)
affinity           = ON0XYZ        # the real repeater(s) you bridge to (repeatable)
home               = ON6URE*       # your devices (wildcard, repeatable)
home               = ON4ABC*       # a friend's / neighbour's devices
hotspot_power_high = 22            # uplink: full power (chip dBm; PA adds gain)
hotspot_power_low  = -9            # downlink: lowest usable for local delivery
```

**Naming.** A repeater IDs with a **bare callsign** (`name = ON0RFG`). A hotspot
may append an SSID **`-NN`** (`00`–`99`, e.g. `name = ON6URE-1`) so **one operator
can run several**, each a distinct on-air ID — allowed only in hotspot mode. The
`home = ON6URE*` wildcard already covers every one of them. It is advisory: the
daemon logs a warning if a repeater name carries an SSID (or a hotspot SSID is not
`00`–`99`) but never refuses to run.

> Both roles need an amateur licence and keep the strict content policy (it's the
> ham band — no private/encrypted). The power values are **chip** dBm (the PA adds
> gain on top) — measure with a meter and **check the applicable limits with your
> local regulator** (a personal hotspot is often power-limited).

---

## Frequency / legal notes

- The defaults follow the
  [IARU R1 ham-MeshCore RFC](https://github.com/Guru-RF/meshcore-rfc-iaru-r1):
  **434.890 MHz**, 62.5 kHz, in the 70 cm amateur band. The occupied band is
  ~434.859–434.921 MHz — **keep everything below 435.000 MHz** to protect the
  amateur-satellite segment.
- Operating requires an **amateur radio licence**; fixed repeater nodes should be
  coordinated per the RFC and your national rules.
- **+30 dBm (1 W) EIRP may exceed what your licence class/region permits.** The
  default `tx_power = 22` drives the chip to its maximum; confirm the actual
  antenna power and your legal limit, and lower `tx_power` if needed.

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
  hmac_sha256.[ch] HMAC-SHA256 (public-channel MAC verify)
  aprs.[ch]       APRS base-91 compressed position/timestamp
  aprsis.[ch]     APRS-IS RX iGate (passcode, qAO gating, own beacon)
  log.[ch], util.[ch]
  crypto/         vendored TweetNaCl (Ed25519/SHA-512) + B-Con SHA-256 + tiny-AES-128
tools/
  selftest.c      host unit tests       mock_hal.c   no-hardware HAL
```

## Credits / licences

- Protocol & forwarding logic ported from
  [MeshCore](https://github.com/meshcore-dev/MeshCore) (the C++ original).
- Inspired by [pyMC_Repeater](https://github.com/pyMC-dev/pyMC_Repeater).
- Vendored crypto: [TweetNaCl](https://tweetnacl.cr.yp.to/) (public domain),
  Brad Conte's [SHA-256](https://github.com/B-Con/crypto-algorithms) (public
  domain), and [tiny-AES-c](https://github.com/kokke/tiny-AES-c) (public domain).
- **Licence:** this project's own code is [MIT](LICENSE); the vendored crypto
  above keeps its own public-domain terms.
