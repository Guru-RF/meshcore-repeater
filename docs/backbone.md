# IP backbone protocol, version 1

This is the wire contract between `meshcore-repeater` and the backbone hub
(`be.mesh73.net`, built in `meshcore-hub`). A hub built from this document alone
must interoperate with the repeater. The repeater side lives in
[`src/backbone.c`](../src/backbone.c), and `make test` checks it against the
[test vectors](#test-vectors) below.

The backbone is a **fallback**. It bridges RF islands and blind spots, and feeds
the public portal. When the hub is unreachable, a repeater behaves exactly as it
does without the backbone.

## Overview

- **Transport:** UDP. Each repeater opens the session to the hub on **UDP 4405**,
  because repeaters sit behind NAT on home lines and 4G. The hub only answers.
- **Authentication:** per repeater, with no shared network-wide key.
  - The repeater signs a HELLO with its existing MeshCore Ed25519 identity.
  - The hub answers with a WELCOME signed by the hub's own Ed25519 key, which is
    pinned in every repeater's config.
  - An X25519 exchange inside that handshake gives two HMAC-SHA256 session keys,
    one per direction.
- **After the handshake:** every datagram carries a session id, a sequence
  number and a 16-byte MAC.
- **Encryption:** none. Datagrams are authenticated, not encrypted. They carry
  public ham traffic, or MeshCore payloads that are already encrypted on air.
- **Roles:** two, each enabled separately per repeater and granted per session
  by the hub:

| Role | Direction | What it carries |
|---|---|---|
| observe | repeater → hub | Every frame heard on RF with RSSI/SNR, plus periodic status and neighbour reports. Read-only. |
| bridge | both | The repeater offers the frames it transmits; the hub sends frames for the repeater to transmit. |

A personal hotspot connects the same way, with the same messages and roles. See
[Hotspots](#hotspots) for how it uses them.

The hub also holds the network's rooms and blocked users and pushes them to every
node. See [Rooms and blocks](#rooms-and-blocks).

## Conventions

- Integers are **little-endian**, the same as MeshCore. `u8/u16/u32` are unsigned;
  `i8/i16` are two's complement.
- Times are Unix seconds (UTC) as `u32`.
- `||` is concatenation. Context strings are ASCII, with no terminating NUL.
- Primitives:
  - Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), pure, no prehash);
  - X25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748));
  - SHA-256;
  - HMAC-SHA256 ([RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)).
- A datagram is at most **1200 bytes**. A MeshCore frame is 1–255 bytes.
- "Frame" always means one raw MeshCore over-the-air packet, exactly the bytes
  the radio sends or receives: header, optional transport codes, `path_len`,
  path, payload.
- **pkt_hash** is MeshCore's packet hash, which the repeaters use for dedup: the
  first 8 bytes of
  `SHA256(payload_type || payload)`, where `payload_type = (frame[0] >> 2) & 0x0F`.
  For TRACE packets (type `0x09`) only, the 2-byte little-endian `path_len`
  goes between the two. The path is not hashed, so the same packet has the
  same pkt_hash at every hop.

## Keys

| Key | Holder | Where it comes from |
|---|---|---|
| Repeater identity (Ed25519) | each repeater | Its existing MeshCore key, `repeater.key` (`pub=` line). The same key signs its adverts. |
| Hub identity (Ed25519) | the hub | Generated once on the hub. Its public key goes into every repeater's `backbone_hub_key`. |
| Ephemeral X25519 keys | both | Fresh random key per HELLO and per WELCOME, then discarded. |
| `k_up`, `k_down` | both | Derived per session (see below). `k_up` authenticates repeater → hub, `k_down` hub → repeater. |

The hub keeps an **allowlist**: repeater public key → callsign, and the roles that
repeater may hold. A HELLO from a key that isn't on the list is dropped. A leaked
repeater key can therefore only impersonate that one repeater, and the hub
operator revokes it by removing it from the list.

## Datagram header and types

Every datagram starts with:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `0x4D 0x42` ("MB") |
| 2 | 1 | version, `0x01` |
| 3 | 1 | type |

Receivers silently drop datagrams with a wrong magic, an unknown version or an
unknown type.

| Type | Name | Direction | Authenticated by |
|---|---|---|---|
| `0x01` | HELLO | R → H | repeater Ed25519 signature |
| `0x02` | WELCOME | H → R | hub Ed25519 signature |
| `0x03` | RESET | H → R | hub Ed25519 signature |
| `0x10` | KEEPALIVE | R → H | session MAC (`k_up`) |
| `0x11` | OBSERVE | R → H | session MAC (`k_up`) |
| `0x12` | BRIDGE | R → H | session MAC (`k_up`) |
| `0x13` | STATUS | R → H | session MAC (`k_up`) |
| `0x14` | NEIGHBOURS | R → H | session MAC (`k_up`) |
| `0x1F` | BYE | R → H | session MAC (`k_up`) |
| `0x20` | KEEPALIVE_ACK | H → R | session MAC (`k_down`) |
| `0x21` | FRAME | H → R | session MAC (`k_down`) |
| `0x22` | POLICY | H → R | session MAC (`k_down`) |
| `0x2F` | BYE | H → R | session MAC (`k_down`) |

Types `0x10`–`0x1F` always flow repeater → hub and use `k_up`. Types `0x20`–`0x2F`
always flow hub → repeater and use `k_down`.

## Handshake

```
repeater                                   hub
   | HELLO (signed, eph_pub_R)  ---------->  |  check allowlist + signature + ts
   |  <----------  WELCOME (signed, eph_pub_H, session_id, hello_hash)
   |  derive k_up/k_down                      derive k_up/k_down
   | KEEPALIVE (session MAC)   ---------->   |  confirms the session
   |  <----------  KEEPALIVE_ACK              |
```

### HELLO (`0x01`), repeater → hub

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | header, type `0x01` |
| 4 | 1 | roles requested: bit 0 observe, bit 1 bridge, other bits 0 |
| 5 | 1 | reserved, 0 |
| 6 | 4 | `ts`: repeater time, u32. Strictly increases from one HELLO to the next. |
| 10 | 32 | `node_pub`: the repeater's Ed25519 public key |
| 42 | 32 | `eph_pub`: a fresh X25519 public key |
| 74 | 1 | `name_len`, 0–32 |
| 75 | n | `name`: the repeater's node name (its callsign), UTF-8 |
| 75+n | 64 | `sig` = Ed25519(node key, `"MCBB1 HELLO"` ‖ bytes[0 .. 75+n)) |

The hub accepts a HELLO only if all of the following hold:

1. The length is exactly `75 + name_len + 64`, and `name_len` ≤ 32.
2. `node_pub` is on the allowlist.
3. `sig` verifies.
4. `ts` is within ±120 s of the hub clock.
5. `ts` is greater than the `ts` of the last HELLO accepted from this `node_pub`.

If any check fails, the hub drops the HELLO with no reply.

- **Name:** the `name` is informational. The hub identifies repeaters by
  `node_pub`, and SHOULD log a name that differs from the allowlisted callsign.
- **Roles:** the hub grants the requested roles that the allowlist permits.
- **CPU cost:** checking a signature costs CPU, so the hub SHOULD rate-limit
  HELLO checks per source address (for example 1 per second).

### WELCOME (`0x02`), hub → repeater

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | header, type `0x02` |
| 4 | 1 | roles granted: a subset of the roles requested |
| 5 | 1 | reserved, 0 |
| 6 | 4 | `ts`: hub time |
| 10 | 4 | `session_id`: random, nonzero, unique among the hub's sessions |
| 14 | 32 | `eph_pub`: a fresh hub X25519 public key |
| 46 | 32 | `hello_hash` = SHA256(the whole HELLO datagram it answers) |
| 78 | 2 | `keepalive_s`: KEEPALIVE interval (recommended 25) |
| 80 | 2 | `status_s`: STATUS interval (recommended 60) |
| 82 | 2 | `neighbours_s`: NEIGHBOURS interval (recommended 300) |
| 84 | 64 | `sig` = Ed25519(hub key, `"MCBB1 WELCOME"` ‖ bytes[0 .. 84)) |

The total is 148 bytes.

The repeater accepts a WELCOME only if all of the following hold:

- `hello_hash` matches the HELLO it sent last.
- `sig` verifies against `backbone_hub_key`.
- `session_id` ≠ 0.
- The granted roles are a subset of the roles it asked for.

**Interval fields:** the repeater clamps them:

| Field | Range | Value used for 0 |
|---|---|---|
| `keepalive_s` | 10–120 | 25 |
| `status_s` | 30–3600 | 60 |
| `neighbours_s` | 60–65535 | 300 |

**Granting no roles:** a WELCOME that grants no roles is valid. The session then
carries only keepalives.

### Session keys

```
shared  = X25519(own_eph_secret, peer_eph_pub)       32 bytes; all zero -> abort
th      = SHA256(HELLO datagram || WELCOME datagram)   both complete, signatures included
k_up    = HMAC-SHA256(key = shared, msg = "MCBB1 up"   || th)
k_down  = HMAC-SHA256(key = shared, msg = "MCBB1 down" || th)
```

### Confirmation and retries

- **Pending session:** the hub keeps a new session *pending* until the first valid
  session datagram from the repeater arrives under it. The repeater sends a
  KEEPALIVE immediately after accepting a WELCOME. Until then, the hub keeps
  using the repeater's previous session, if it has one.
- **Lost WELCOME:** the repeater sends a new HELLO after 5 s, with a new
  ephemeral key and a later `ts`. The hub replaces the pending session with the
  new one.
- **Retry limit:** after 3 HELLOs without a WELCOME, the repeater backs off
  before starting a new attempt (see [Timers](#timers)).
- **Hub memory:** the hub keeps the last accepted HELLO `ts` per repeater only in
  memory. After a hub restart, a HELLO replayed within the 120 s window can at
  most create a pending session nobody can complete, because the attacker lacks
  the ephemeral secret.

### RESET (`0x03`), hub → repeater

When the hub receives a datagram of type `0x10`–`0x1F` with a `session_id` it does
not know, for example after a hub restart, it MAY answer with a RESET so the
repeater re-registers at once instead of waiting for its keepalive timeout.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | header, type `0x03` |
| 4 | 4 | `session_id` copied from the datagram |
| 8 | 4 | `seq` copied from the datagram |
| 12 | 4 | `ts`: hub time |
| 16 | 64 | `sig` = Ed25519(hub key, `"MCBB1 RESET"` ‖ bytes[0 .. 16)) |

The total is 80 bytes.

- **Hub rate limit:** at most 1 RESET per source address per 5 s.
- **What the repeater checks:** it acts on a RESET only if:
  - `sig` verifies;
  - `session_id` is its current session;
  - `seq` is one of the last 64 sequence numbers it sent;
  - `ts` is within ±120 s.
- **What it does then:** it drops the session and sends a new HELLO, at most
  once per 5 s.

## Session datagrams

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | header (type `0x10`–`0x2F`) |
| 4 | 4 | `session_id` |
| 8 | 4 | `seq`: per direction, starts at 1, +1 per datagram |
| 12 | n | body |
| 12+n | 16 | `mac` = HMAC-SHA256(k, bytes[0 .. 12+n)), first 16 bytes |

`k` is `k_up` for types `0x10`–`0x1F` and `k_down` for `0x20`–`0x2F`.

The receiver processes a session datagram in this order:

1. **Find the session** by `session_id`. If there is none, drop it. The hub may
   answer with RESET.
2. **Verify the MAC**, comparing in constant time. If it fails, drop.
3. **Replay check**, with a 64-wide window per direction: accept `seq` only if it
   is above the highest `seq` accepted so far, or within the 64 below it and not
   seen before. `seq` 0 is never valid. Drop anything else.
4. **Process the body.** Unknown types and malformed bodies are dropped.
   Receivers ignore any bytes after the fields they know, so later versions can
   append fields.

- **NAT roaming:** the hub sends to the source address and port of the most
  recent datagram from that repeater that passed steps 1–3. A repeater whose NAT
  mapping changes, which is common on 4G, keeps its session.
- **Sequence numbers:** a repeater starts a new handshake before its `seq`
  reaches 2^31. The hub MAY end a session with BYE when its own `seq` gets
  there.

## Message bodies

### KEEPALIVE (`0x10`) and KEEPALIVE_ACK (`0x20`)

- **Body:** empty. Receivers ignore anything in it.
- **Repeater:** sends KEEPALIVE every `keepalive_s`.
- **Hub:** answers every valid KEEPALIVE with a KEEPALIVE_ACK. That ack is how
  the repeater knows the hub is alive, so the hub must send it even when other
  traffic flows.

### OBSERVE (`0x11`), repeater → hub, observe role

One frame the repeater heard, and what it did with it.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | flags: bit 0 `FROM_BACKBONE` |
| 1 | 1 | `disposition` (see below) |
| 2 | 2 | `rssi`, i16, dBm |
| 4 | 1 | `snr`, i8, quarter dB (SNR × 4) |
| 5 | 1 | `frame_len`, 1–255 |
| 6 | 8 | `pkt_hash` |
| 14 | n | frame |

- **What the repeater reports:** every frame it hears on RF that parses as a
  MeshCore packet, including duplicates. This also covers frames relayed by a
  split-RX ear (`link_mode = rx`), with that ear's RSSI and SNR.
- **FRAME results:** after handling each FRAME from the hub, the repeater
  reports that frame too, with `FROM_BACKBONE` set and `rssi` = `snr` = 0. This
  is how the hub learns whether a bridged frame went out on air.

| `disposition` | Meaning |
|---|---|
| 0 forwarded | Queued for retransmission on RF. |
| 1 duplicate | Already seen (in the repeater's dedup ring). |
| 2 policy | Refused by the content policy: private message, channel not configured, bad advert signature, blacklisted sender. |
| 3 local | Accepted but not retransmitted: a direct frame for another hop, a trace, forwarding off, path full, or a command the repeater answered itself. |
| 4 limited | A FRAME the repeater refused by its rate limit or TX-queue headroom. Only with `FROM_BACKBONE`. |

**Never bridge an OBSERVE:** OBSERVE is never a bridge candidate. Private frames
(dispositions 1–3) appear here exactly as they did on air, and the hub must not
publish their payloads.

### BRIDGE (`0x12`), repeater → hub, bridge role

A frame the repeater has just queued for transmission on RF, offered for other
islands. It is sent at the moment the frame is queued, so it is not held back by
the repeater's RF flood backoff.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | flags: bit 0 `OWN` (the repeater originated it: advert, pong, help, time, probe, `#mbox` reply). 0 means relayed. |
| 1 | 1 | `frame_len`, 1–255 |
| 2 | 8 | `pkt_hash` |
| 10 | n | frame, exactly as the repeater transmits it |

- **Path:** a relayed flood therefore already ends with the repeater's own path
  hash. A relayed direct frame has the repeater already removed from the front
  of its path.
- **Never sent:**
  - for a frame that arrived from the hub;
  - for a direct frame with an empty path;
  - when the session lacks the bridge role.

### STATUS (`0x13`), repeater → hub, observe role

- **When:** sent right after the session comes up, then every `status_s`.
- **Body:** one UTF-8 JSON object, no NUL, at most 1100 bytes.
- **Counters:** cumulative since the repeater process started. A smaller
  `uptime` than last time means a restart. Rates and duty cycle are deltas
  between two reports: duty = Δ`airtime_ms.tx` ÷ Δwall time.
- **Omitted fields:** `lat`/`lon` are left out when the repeater has no position
  configured.
- **`role`:** `"repeater"` or `"hotspot"` (see [Hotspots](#hotspots)).
- **`rf_silent`:** hotspots only. `true` while the hotspot is RF silent because it
  hasn't heard a companion nearby (see [Hotspots](#hotspots)).
- **`policy`:** the [POLICY](#policy-0x22-hub--repeater-any-role) set the node
  has applied:
  - `version` of that set, 0 while it has none;
  - `rooms` and `blocks` in use from it;
  - `skipped`, the entries it could not hold.

  The field is left out when the node doesn't take central policy
  (`backbone_policy = false`).
- **Compatibility:** receivers ignore unknown fields.

```json
{
  "name": "ON0RFG", "fw": "d7dddb8", "uptime": 86400, "role": "repeater",
  "lat": 50.93, "lon": 4.21,
  "radio": {"freq": 434.890, "bw": 62.5, "sf": 8, "cr": 8, "tx_power": 22},
  "rx": {"total": 1520, "dup": 610, "bad": 2, "crc_err": 31, "hdr_err": 4,
         "adverts": 220, "adverts_bad": 0},
  "fwd": {"flood": 700, "direct": 12, "dropped": 3, "denied": 140,
          "grp_public": 410, "region": 0},
  "tx": {"total": 760, "failed": 0, "cad_busy": 25, "queue_full": 0,
         "radio_resets": 0, "adverts": 48},
  "airtime_ms": {"tx": 512000, "rx": 1210000},
  "neighbours": 12,
  "backbone": {"observed": 1530, "offered": 650, "injected": 40,
               "limited": 0, "rejected": 1},
  "policy": {"version": 1792000200, "rooms": 1, "blocks": 2, "skipped": 0}
}
```

### NEIGHBOURS (`0x14`), repeater → hub, observe role

- **What it lists:** the repeater's neighbour table, meaning every node whose
  advert it heard on RF. This shows the RF islands.
- **When:** first sent 5 s after the session comes up, then every
  `neighbours_s`.
- **Paging:** the table is split into pages that each fit in one datagram. The
  pages go out back to back.
- **Body:** one UTF-8 JSON object, at most 1100 bytes.

```json
{"page": 1, "pages": 2, "list": [
  {"pub": "03a107bf…64 hex…", "name": "OR7F-12", "type": 1, "hops": 0,
   "rssi": -107, "snr": 5.25, "age": 42, "count": 17}
]}
```

| Field | Meaning |
|---|---|
| `pub` | The node's Ed25519 public key, 64 hex characters. |
| `type` | MeshCore advert type: 1 chat, 2 repeater, 3 room, 4 sensor. |
| `hops` | Path length of that advert when last heard. **0 means heard directly, a real RF link**; more means it was relayed and `rssi`/`snr` belong to the last relay. |
| `rssi`, `snr` | The last reception, in dBm and dB. |
| `age` | Seconds since last heard. |
| `count` | Adverts heard from this node. |

An empty table is sent as one page with an empty `list`.

### FRAME (`0x21`), hub → repeater, bridge role

A frame for the repeater to transmit.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | flags, 0 |
| 1 | 1 | `frame_len`, 1–255 |
| 2 | 8 | `src`: first 8 bytes of the public key of the repeater whose BRIDGE this was, or zeros |
| 10 | n | frame, unmodified from the BRIDGE |

The repeater drops FRAME, counted as rejected, when the session lacks the bridge
role. Otherwise it applies its own [bridge rules](#repeater-rules).

### POLICY (`0x22`), hub → repeater, any role

> **Draft:** agreed with the hub, which is building its side. Not in the repeater yet.

The network's central rooms and blocked users, always as one complete set. See
[Rooms and blocks](#rooms-and-blocks) for what a node does with them.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `version`, u32, nonzero: identifies this set, and changes whenever the set changes |
| 4 | 1 | `page`, 1 to `pages` |
| 5 | 1 | `pages`, 1–16 |
| 6 | n | entries, back to back to the end of the body |

Each entry is `kind` (u8), `len` (u8), then `len` bytes of value:

| `kind` | Value | Meaning |
|---|---|---|
| 1 room | The room name exactly as hashed: UTF-8, one leading `#`, 2–31 bytes, case-sensitive. Example: `#pra`. | Serve this room: its hashtag channel and its transport region, both keyed `SHA256(name)[0..15]`. |
| 2 block name | A node name: UTF-8, 1–31 bytes, matched exactly but ignoring case. | Ignore this sender's group messages (by sender name) and adverts (by advert name). |
| 3 block key | An Ed25519 public key, 32 bytes. | Ignore adverts from this key. |

**Matching a block name:**

- **Case:** "ignoring case" means ASCII case folding only, `A`–`Z` against
  `a`–`z`. Bytes 0x80 and up compare exactly. Names are UTF-8 and may hold
  emoji.
- **Group-message sender:** the decrypted text up to the first `": "`, in the
  MeshCore plaintext `"sender: message"`. A message without `": "` has no sender
  and matches no block name.
- **Advert:** the advert's name field.

**Self-block guard:** a node ignores a block entry that matches its own name or
its own public key, and logs it. A typo by an admin can't silence a backbone
node's own adverts and replies. The hub refuses to create a block that matches an
allowlisted callsign or key.

- **Unknown kinds:** skipped using `len`, so later versions can add kinds. An
  entry whose `len` is wrong for its kind is skipped too.
- **Malformed page:** an entry that runs past the end of the body invalidates
  the whole page, and the node drops that page.
- **Paging:** the hub splits a set into pages that each fit one datagram, at
  most 1166 bytes of entries. It never splits an entry, and sends the pages back
  to back. Every page of a set carries the same `version` and `pages`.
- **Empty set:** one page with no entries. It clears the hub's earlier set.
- **No role needed:** rooms and blocks shape a node's RF forwarding whatever
  roles it holds, so the hub sends POLICY on every session.

**The node:**

1. It collects pages by `version`. A new session starts with no collection.
2. **A different set:** a page whose `version` or `pages` differs from the set
   being collected starts a new collection only if its `seq` is higher than that
   of every page in the current collection. The partial collection is then
   discarded. Otherwise the node drops the page.
3. **Stale pages:** within a session, it also drops a page whose `seq` is lower
   than that of every page of the set it last applied.

   Together, rules 2 and 3 mean an older set delayed in the network can neither
   undo a newer applied set nor break up a newer set being collected.
4. Once it holds every page from 1 to `pages`, it applies the set as a whole,
   replacing the previous hub set. It never applies part of a set.
5. It reports the applied `version` in [STATUS](#status-0x13-repeater--hub-observe-role).
   That is the acknowledgement.
6. It keeps the applied set across restarts, so the rooms and blocks stay when
   the hub is unreachable.

**The hub:**

- sends the current set right after a session is confirmed;
- sends it to every session whenever the set changes;
- sends it again when a STATUS reports a different `policy.version`, at most
  once per `status_s` per session;
- doesn't resend to a node whose STATUS has no `policy` field. That node doesn't
  take central policy: older firmware, or `backbone_policy = false`.
- sends at most 32 rooms and 256 blocks. A node applies what it can hold and
  reports the rest as `skipped`.

`version` is opaque to the node. The recommended value is the Unix time of the
change, plus one when that equals the previous version.

### BYE (`0x1F` repeater → hub, `0x2F` hub → repeater)

- **Body:** `reason`, u8.

| `reason` | Meaning |
|---|---|
| 0 | shutting down |
| 1 | starting a new handshake |
| 2 | backbone disabled |
| 3 | not allowed: removed from the allowlist, or role revoked |

- **Both sides:** forget the session on BYE.
- **Repeater:** after a hub BYE it waits before reconnecting: its normal backoff,
  or 300 s for reason 3.
- **Hub:** shows a repeater as offline as soon as its BYE arrives.

## Timers

| Who | When | Action |
|---|---|---|
| repeater | start, or session lost | Resolve `backbone_host` without blocking, then send HELLO. |
| repeater | no WELCOME within 5 s | New HELLO. After 3 tries, back off 5 s, doubling to at most 300 s, plus up to 25 % random jitter. Each new attempt resolves DNS again. |
| repeater | every `keepalive_s` | KEEPALIVE. |
| repeater | nothing valid from the hub for 3 × `keepalive_s` + 5 s | Session lost: start again at once. |
| repeater | session up, then every `status_s` | STATUS. |
| repeater | 5 s after up, then every `neighbours_s` | NEIGHBOURS (all pages). |
| hub | each KEEPALIVE | KEEPALIVE_ACK. |
| hub | nothing valid from a repeater for 3 × `keepalive_s` + 5 s | Drop the session; the portal shows the repeater offline. |

The repeater keeps all backbone work inside its single radio loop. DNS lookups
are asynchronous (`getaddrinfo_a`), sockets are non-blocking, and a broken or
slow hub can only delay the backbone, never the radio.

## Bridging

### Path handling

The backbone is an invisible zero-hop link between repeaters. It **adds no path
hash of its own**. Each repeater appends its own hash exactly as it does on RF:

- the uplinking repeater has already appended its hash to a relayed flood before
  offering it;
- the receiving repeater appends its own hash when it transmits.

Reverse paths therefore stay routable across the backbone. In the example below,
x and y are in repeater A's RF island and z is in repeater B's. Paths are shown
as `[first hop … last hop]`:

1. x floods a message. y relays it, and A hears it with path `[y]`.
2. A relays it on RF as `[y, A]`, and offers that frame to the hub as BRIDGE.
3. The hub sends FRAME `[y, A]` to B.
4. B appends itself and transmits `[y, A, B]`. z receives it.
5. z answers x with a direct frame on the reversed path, `[B, A, y]`.
6. B removes itself, giving `[A, y]`. It transmits on RF as usual and offers the
   frame as BRIDGE.
7. The hub sees that `[A, …]` starts with A's hash and sends FRAME `[A, y]` to A.
8. A removes itself and transmits `[y]`. y delivers it to x.

**Repeater-originated floods** (`OWN`), such as its adverts and pongs, have no
hash of the originator in the path, so no direct route back to that repeater
over the backbone can be learned from them. This repeater does not answer
direct messages anyway: it has no over-the-air admin.

### Repeater rules

A FRAME from the hub is handled like a frame heard on RF, with these differences:

1. **Rate limit first:** a token bucket refills at `backbone_rate` frames per
   minute and holds at most `backbone_rate / 3`, minimum 1. The repeater also
   keeps at least 8 of its 24 TX-queue slots for RF traffic. A frame over either
   limit is not processed and is reported as `limited`.
2. **Same path as RF:** the frame goes through the same dedup ring and the same
   content policy as an RF frame:
   - public channels proven by their MAC;
   - signed adverts;
   - served regions;
   - blacklist.

   Nothing that would be dropped from RF is ever transmitted from IP. Floods get
   this repeater's hash appended; a direct frame is transmitted only if this
   repeater is the next hop.
3. **No local services:**
   - no reply to `ping`, `help`, `time`, `date` or `probe`;
   - no `#mbox` storage or replies;
   - no APRS-IS gating;
   - no neighbour-table entry.

   The repeater that heard the frame on RF handles those.
4. **Never sent back up:** the frame is never offered back as BRIDGE. A later RF
   echo of it is a duplicate in the dedup ring, so that is not offered either.
5. **Reported:** the result is reported as OBSERVE with `FROM_BACKBONE`, when
   the observe role is granted.

### Hub rules

The hub decides what goes where. It does not flood everything to everyone.

1. **Only BRIDGE is a candidate.** Never bridge from OBSERVE, and never bridge a
   frame back to the repeater that offered it.
2. **Dedup by `pkt_hash`.** For each hash, the hub remembers for at least 10
   minutes:
   - which repeaters reported it (BRIDGE or OBSERVE);
   - which repeaters it was sent to.

   It sends a hash to a given repeater at most once, and never to a repeater
   that reported it. With the repeaters' own dedup rings, this breaks loops
   between islands that overlap on RF.
3. **Hold briefly.** After the first BRIDGE for a hash, wait about 1 s for other
   repeaters' reports before fanning out. A repeater that heard the frame on RF
   has it already, so skipping it saves airtime.
4. **Floods** (route type 0 or 1, `frame[0] & 3`): send to every connected
   repeater with the bridge role that has not reported the hash. The hub may
   narrow this by its own policy, for example by region, channel, or skipping
   `OWN` pongs and probes.
5. **Direct frames** (route type 2 or 3): route by path only, never fan out.
   - Let hs be the path hash size, `(path_len >> 6) + 1`, and n the hop count,
     `path_len & 0x3F`. The path starts after the header byte, after the 4
     transport-code bytes for route types 0 and 3, and after the `path_len`
     byte. If n = 0, drop the frame.
   - Candidates are the connected bridge repeaters R, other than the sender,
     whose public key starts with the frame's first path hash, `path[0 .. hs)`.
   - **Path-tail rule:** send to candidate R only if the hub has, within the
     last 24 h, received a relayed (not `OWN`) flood BRIDGE from R whose path
     *before R's own hash* equals the reverse of this frame's remaining path,
     `path[hs ..)`, compared hash by hash.

     This is the rule that handles **1-byte path-hash collisions**. A local
     direct frame whose next hop merely shares a first byte with a backbone
     repeater is never sent. If two backbone repeaters share a first byte, only
     the one the route actually went through gets the frame.
   - If several candidates pass, send to each. Their dedup rings and the
     content policy keep this safe.
6. **Never modify frame bytes.**
7. **Rate-limit each repeater below its own limit,** which defaults to 30 frames
   per minute. The repeater's limit is the authoritative one.
8. **Warn about shared first bytes:** on HELLO, warn the operator when two
   allowlisted repeaters share their first public-key byte. The path-tail rule
   still copes, but a shared byte is worth knowing about.

### Hotspots

A personal hotspot (`role = hotspot`) relays only its operator's own devices
(`home`) up to a repeater it trusts (`affinity`), and the mesh's traffic back
down to the household at low power. On the backbone the **hub stands in for that
repeater**, so a hotspot with no repeater in RF range still reaches the mesh.
When a repeater is in range, the hub is a fallback for the hotspot, exactly as it
is for a repeater.

- **On the wire:** nothing differs. HELLO does not carry the role, so the hub
  records it per key in the allowlist; STATUS reports it as `"role": "hotspot"`.
  A hotspot's name may carry an SSID, such as `OR7F-4`.
- **Up:** the hotspot offers what it relays from its home devices as BRIDGE, like
  any repeater. Those floods carry the hotspot's hash, so replies route back over
  the backbone with the [path handling](#path-handling) above.
- **Down:** a FRAME passes the [repeater rules](#repeater-rules) and is then
  handled like traffic that came in through an affinity repeater:
  - transmitted at the hotspot's low (household) power, whatever the sender;
  - an advert goes down only when the advertiser is one of the hotspot's
    affinity repeaters, as on RF;
  - nothing from the hub is ever transmitted at the hotspot's uplink power.
- **RF silent:** a hotspot is an attended station.
  - It transmits nothing until it hears a companion directly on RF, meaning a
    non-repeater at 0 hops, and keeps transmitting until `hotspot_awake`
    seconds after the last one.
  - While silent it still observes. Each FRAME it gets is reported as
    disposition 3 (local), and it offers nothing as BRIDGE.
  - STATUS shows the state as `rf_silent`, and the hotspot sends a STATUS at once
    whenever the state changes. The hub may skip FRAMEs to a silent hotspot, but
    doesn't have to.
- **Hub:** no special rules. A hotspot that shares no RF neighbour with other
  backbone nodes is an island of its own. When it is in range of a backbone
  repeater, the dedup and hold rules above apply as between two repeaters, and
  the hotspot's own dedup ring drops whatever reaches it both ways. The hub may
  narrow what it sends a hotspot by its own policy, for example by channel.

## Rooms and blocks

> **Draft:** see [POLICY](#policy-0x22-hub--repeater-any-role).

The hub's room admins manage the network's rooms and blocked users on the portal.
The hub pushes them with POLICY to every node on the backbone, repeaters and
hotspots alike.

- **Rooms:** a node serves its own `room` lines plus the hub's rooms.
  - The hub adds rooms but can never remove a node's own. A room in both lists
    is served once.
  - A hub room works exactly like a `room` line. Plain group messages on its
    hashtag channel are forwarded, after the same MAC check as every public
    channel. Transport floods tagged for its region are relayed.
- **Blocks:** a node ignores its own `blacklist` entries plus the hub's blocks.
  - A blocked sender is handled like a local blacklist entry: not relayed
    (disposition 2), not answered, and no neighbour-table entry. FRAMEs from the
    hub get the same check. The [self-block guard](#policy-0x22-hub--repeater-any-role)
    keeps a node from blocking itself.
  - `blacklist remove` on the node removes only local entries.
- **The hub applies blocks too:**
  - it doesn't bridge a blocked sender's group messages, on the channels it can
    decode;
  - it doesn't bridge their adverts, matched by name or key;
  - the portal doesn't show their messages.
- **Reach:** blocks work only at the hub and on nodes on the backbone. Repeaters
  that are only on RF still relay a blocked sender. When that traffic reaches a
  backbone node over RF, the node drops it.
- **Name blocks are weak:** a group message carries only the name the sender
  chose, and they can change it. A key block stops the adverts of one identity.
- **Hub unreachable:** the node keeps using the last set it applied, also
  across a restart.
- **Opting out:** `backbone_policy = false` makes a node ignore POLICY and forget
  the stored set. It then serves only its own rooms and blacklist.

## Repeater configuration

All keys are off by default. The backbone only starts with `backbone = true`
and a hub key.

```
backbone          = true             # master switch (default false)
backbone_host     = be.mesh73.net    # hub host name or IPv4 address
backbone_port     = 4405             # hub UDP port
backbone_hub_key  = <64 hex chars>   # the hub's Ed25519 public key (required)
backbone_observe  = true             # uplink heard frames + status (default true)
backbone_bridge   = false            # offer/transmit bridged frames (default false)
backbone_rate     = 30               # max FRAMEs transmitted per minute
backbone_policy   = true             # take rooms and blocks from the hub (default true; draft)
```

- **Allowlisting a repeater:** the hub operator needs the repeater's public key.
  It is the `pub=` line of `repeater.key`, and the repeater logs it at start-up.
- **Restart:** the backbone keys take effect on a restart, not on `reload`.
- **`meshcore-cli status`** shows a `backbone` line: state, session, and the
  counters above.
- **Hub firewall:** allow inbound **UDP 4405** from anywhere, because repeaters
  have dynamic addresses. The hub needs nothing outbound beyond its replies.
- **IP version:** IPv4 only in version 1.

## Security notes

- **Datagram authentication:** every datagram is authenticated. The handshake
  binds both ephemeral keys and both identities. Session keys are fresh per
  session (forward secrecy), and replays are rejected by the sequence window.
- **Leaked repeater key:** it can only impersonate that repeater. Remove it from
  the allowlist.
- **Leaked hub key:** it can impersonate the hub towards repeaters. Even then,
  anything injected is limited to what each repeater's content policy and rate
  limit allow. To rotate, change `backbone_hub_key` on the repeaters.
- **Leaked hub key and POLICY:** it can also block users on every backbone node,
  or add rooms. It can't remove a node's own rooms or blacklist. It can't make
  private traffic forwardable either, because a room is a hashtag channel whose
  key anyone can derive from its name.
- **No confidentiality:** the backbone carries what was or will be on air. Don't
  put anything else in it.

## Test vectors

These are deterministic. The keys come from fixed seeds:

| Key | Seed (32 bytes, hex) |
|---|---|
| Repeater Ed25519 | `000102…1f` (bytes 0x00 to 0x1f) |
| Hub Ed25519 | `202122…3f` |
| Repeater X25519 ephemeral secret | `404142…5f` |
| Hub X25519 ephemeral secret | `606162…7f` |

The other inputs:

- HELLO: roles 3, `ts` 1792000000, name `ON0RFG`;
- WELCOME: roles 3, `ts` 1792000001, `session_id` `0x1a2b3c4d`, intervals 25/60/300.

`make test` checks these exact bytes. They were also reproduced independently
from this document with Python's `cryptography` package.

```
repeater Ed25519 public key
03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
hub Ed25519 public key
29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7
repeater X25519 ephemeral public key
79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a
hub X25519 ephemeral public key
675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f

HELLO (145 bytes)
4d420101030000c0cf6a03a107bff3ce10be1d70dd18e74bc09967e4d6309ba5
0d5f1ddc8664125531b879a631eede1bf9c98f12032cdeadd0e7a079398fc786
b88cc846ec89af85a51a064f4e3052464772325767d90b5585b5c869ce17adc0
e8f74e92f152d3477ff99a441b2db0efd18ccd7110639f44ea3c211d4c9c1783
bae163f4d80503c556271a1ce798c1020f
hello_hash = SHA256(HELLO)
6c96f061289bab91bf5fd637e4a1220deafbe2efb728e115f6f749965b9c4e7e

WELCOME (148 bytes)
4d420102030001c0cf6a4d3c2b1a675dd574ed7789310b3d2e7681f3790b466c
773b1521fecf36577958371ea52f6c96f061289bab91bf5fd637e4a1220deafb
e2efb728e115f6f749965b9c4e7e19003c002c01b611bef646242ce91a5de9ae
16c95aeefb334cf94e8dab058e8c35062fad386758ee6d8ef90d3006e2199afd
eb1316dd522ae4ac8948d0b6f6cf6c4c507b8001

X25519 shared secret
d6fb939511b2381bc8599b4b8edc5968829450dfd7a87aebe78a703cd04cd54e
k_up
141922284ac65dafe1f28d9af212229728a9a949d3d6301bd83ae2cb73455ce5
k_down
be484977837de2e5315ff41d3bf7b7cd3d4b7bb1af1dde564c29849822df7fae

KEEPALIVE, repeater -> hub, seq 1 (28 bytes)
4d4201104d3c2b1a0100000095909f12cd7628661a2ba746b8a8e276
KEEPALIVE_ACK, hub -> repeater, seq 1 (28 bytes)
4d4201204d3c2b1a0100000008b340d0bfeb875470dd700794c28f87

OBSERVE, repeater -> hub, seq 2 (49 bytes): flags 0, disposition 0,
rssi -107, snr 21 (5.25 dB), frame 15 00 b0 01 02 03 04 (a GRP_TXT flood)
4d4201114d3c2b1a02000000000095ff150795bb58de03d4fb371500b0010203
04789982ea2e4f120a35a9e324ab0c46b7

RESET, session 0x1a2b3c4d, seq 7, ts 1792000100 (80 bytes)
4d4201034d3c2b1a0700000064c0cf6ad0b442eaf3ddd0afa74708d9026a7eae
4305e0026173c660ec68a875ccfa60912ed4a62aaa9b5cd3240240bfdd930a0f
f8cb58c032415be8666c6764abc8040a

POLICY, hub -> repeater, seq 2 (83 bytes; draft, not yet in make test):
version 1792000200, page 1 of 1, entries: room "#pra", block name "Spammer",
block key = the repeater Ed25519 public key above
4d4201224d3c2b1a02000000c8c0cf6a010101042370726102075370616d6d65
72032003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc866412
5531b8dfa5bd382036fa2862cbb243ebf7e7a5
```

## Versioning

- **Incompatible changes:** they get a new version byte. A receiver drops
  versions it does not speak.
- **Compatible changes, within version 1:**
  - new datagram types;
  - fields appended after the known ones in binary bodies;
  - new JSON fields.

  Receivers ignore all three.
