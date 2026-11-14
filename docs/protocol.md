# LANChat wire protocol (version 1)

The protocol version is independent of the application version. This build
speaks protocol v1 and accepts v1 (`buildinfo.ProtocolVersion`,
`MinProtocolVersion`). Implementation: `internal/protocol`,
`internal/network/transport`, `internal/node`.

## Transport

- TCP, default port 47777. One listening socket (dual-stack when both address
  families are enabled).
- TLS 1.3 only, ALPN `lanchat/1`, mutual authentication. Each side presents
  exactly one self-signed X.509 certificate whose public key is its Ed25519
  identity key. Chain validation and validity periods are not used; the
  certificate must be well formed and self-signed by that key, and TLS 1.3's
  CertificateVerify proves possession of the private key.
- **Peer ID** = lowercase unpadded base32 of the first 20 bytes of
  SHA-256(DER SubjectPublicKeyInfo) — 32 characters. **Fingerprint** = hex
  SHA-256 of the same SPKI, shown in groups of four.
- The sender of every message is the peer authenticated by the TLS session.
  No message field can claim a different sender.

## Framing

```text
+--------------------+--------+-------------------------+
| length (uint32 BE) | kind   | payload (length-1 bytes)|
+--------------------+--------+-------------------------+
```

| kind | payload | limit |
|---|---|---|
| `1` | UTF-8 JSON **envelope** | 512 KiB |
| `2` | **file chunk**: 16-byte transfer ID, uint64 BE offset, data | 1–65536 data bytes |

`length` counts the kind byte and payload. A zero length, an unknown kind, an
oversized frame or invalid JSON is a protocol violation: the receiver sends an
`error` envelope (`protocol_violation`) and closes the session. Sizes are
checked before memory is allocated. TCP segment boundaries are never relied on.

## Envelope

```json
{"v": 1, "type": "chat.message", "id": "…32 hex…", "ts": 1763116200000, "body": { … }}
```

| field | meaning |
|---|---|
| `v` | protocol version used for this message |
| `type` | message type, `[a-z._]{1,32}` |
| `id` | optional request ID (32 lowercase hex) |
| `ts` | sender wall clock, UTC Unix milliseconds — informational only |
| `body` | type-specific object, validated strictly (lengths, UTF-8, formats) |

Unknown fields are ignored; unknown message types from a newer peer are
ignored (forward compatibility). Validation failures of known types are
protocol violations.

## Session establishment

1. TCP connect, TLS 1.3 handshake. The dialer may require a specific peer ID
   (from discovery); a different authenticated ID aborts with
   `identity_mismatch` and the dialer tries the next advertised address.
2. Both sides immediately send `hello`:

   ```json
   {"protocol_version":1,"min_version":1,"peer_id":"…","display_name":"Milad",
    "device_name":"Milad-MacBook","listen_port":47777,"app":"LANChat/1.0.0",
    "capabilities":["chat","rooms","groups","files"]}
   ```

   `peer_id` must equal the TLS-derived ID. The negotiated version is the
   highest version both ranges contain; if none exists the side that notices
   sends `error{code:"incompatible_version"}` and closes.
3. Both sides send `presence`. Paired peers then resend undelivered messages
   and exchange group state (see below).

Duplicate sessions between the same two peers are resolved deterministically
(see [architecture.md](architecture.md#connections)); the closed session
receives `error{code:"duplicate_session"}`.

## Message types

| type | body | direction / rules |
|---|---|---|
| `hello` | see above | first message only |
| `error` | `{code, message}` | before closing or refusing; codes: `incompatible_version`, `identity_mismatch`, `protocol_violation`, `not_trusted`, `too_many_connections`, `shutting_down`, `duplicate_session` |
| `ping` / `pong` | `{nonce}` (32 hex) | keepalive every heartbeat interval; RTT for `/ping` |
| `presence` | `{display_name, device_name, status, rooms[]}` | on connect and on change; `rooms` (≤ 32) only sent to paired peers |
| `pair.request` | `{display_name, commit}` | starts pairing; `commit` = SHA-256 over the initiator nonce (64 hex) |
| `pair.nonce` | `{nonce}` (64 hex) | responder's nonce |
| `pair.reveal` | `{nonce}` (64 hex) | initiator reveals its committed nonce |
| `pair.accept` | `{}` | the sender's user approved after comparing codes |
| `pair.reject` | `{reason}` | aborts pairing |
| `pair.revoke` | `{reason}` | informational: the sender no longer trusts us |
| `chat.message` | `{message_id, kind, room?, group_id?, body, sent_at}` | paired peers only; `kind` = `room` \| `direct` \| `group`; body ≤ 64 KiB UTF-8 |
| `chat.ack` | `{message_id, status, reason?}` | `delivered` (stored) or `rejected` |
| `group.update` | `{group_id, salt, name, owner_id, version, state, members[]}` | owner-authored snapshot |
| `group.leave` | `{group_id}` | member → owner |
| `group.sync` | `{groups:[{group_id, version, status}]}` | on connect, member → owner |
| `file.offer` | `{transfer_id, name, size}` | paired peers only |
| `file.accept` / `file.reject` / `file.cancel` | `{transfer_id, reason?}` | |
| chunk frames | kind 2 | after `file.accept`, in order, from offset 0 |
| `file.done` | `{transfer_id, size, sha256}` | sent on the bulk queue after the last chunk |
| `file.result` | `{transfer_id, ok, error?}` | receiver's verdict after verification |

Messages that require a paired peer (`chat.*` except acks, `group.*`,
`file.*`) are validated and then refused when the sender is not paired: chat
messages are answered with `chat.ack{status:"rejected"}`, file offers with
`file.reject`, other types are dropped.

## Pairing exchange

```text
initiator                                   responder
pair.request {commit = H(Ni)}  ───────────►  store commit, choose Nr
                               ◄───────────  pair.nonce {Nr}
pair.reveal {Ni}               ───────────►  verify H(Ni) == commit, else pair.reject
code = SAS(Ni, Nr)                            code = SAS(Ni, Nr)
       (users compare the six digits)
pair.accept  ◄────────────────────────────►  pair.accept
```

`H(N) = SHA-256("LANChat pairing commit v1" ‖ N)`; nonces are 32 random
bytes. `SAS = SHA-256("LANChat SAS v2" ‖ len‖SPKI_lo ‖ len‖SPKI_hi ‖
len‖exporter ‖ len‖Ni ‖ len‖Nr)`, first 8 bytes as an integer mod 10⁶, shown as
`ddd ddd`; `exporter` is 32 bytes of TLS keying material with label
`EXPORTER-LANChat-SAS-v1`. All pairing messages must arrive on the session
the exchange started on; trust is stored only after both `pair.accept`s.
Simultaneous `pair.request`s are resolved by the smaller peer ID keeping the
initiator role.

## Delivery and resend

- A recipient acknowledges `chat.message` after storing it (or after finding
  it already stored). Duplicate suppression key: (authenticated sender,
  `message_id`).
- On every session establishment the sender resends all unacknowledged
  messages for that peer, oldest first; every 10 s it resends queued messages
  and those unacknowledged for 2 minutes. Retries stop after the TTL or the
  attempt limit (configuration), leaving the message marked failed.
- A recipient may drop messages beyond its per-peer quota without
  acknowledging; the sender's normal resend delivers them later.
- Per-sender order is preserved on a session; there is no global order.

## Groups

`group_id` must equal `hex(SHA-256("LANChat group id v1" ‖ owner SPKI ‖ salt)[:16])`
for the owner's authenticated key. A `group.update` is applied only when it
comes from `owner_id` over that peer's own session, matches the stored owner
and has a strictly higher `version`. Members send `group.sync` on connect; the
owner answers with current snapshots for members it removed.

## File transfer

`file.offer` → user decision → `file.accept` → chunk frames (64 KiB, strictly
increasing contiguous offsets, never beyond `size`) → `file.done{sha256}` →
`file.result`. The receiver writes to a temporary file and renames it only
after size and SHA-256 match. Either side may send `file.cancel` at any time.
Chunks for unknown or finished transfers are ignored.

## Flow control and limits

- Envelope rate per session: token bucket, burst 2000, 500/s. Beyond it the
  receiver stops reading (TCP backpressure); it does not disconnect.
- Per peer: 50 stored messages, group updates or file offers per second,
  burst 1000.
- Heartbeat: `ping` every `heartbeat_interval_seconds`; no frame for three
  intervals closes the session.

## Versioning rules

- New optional fields and new message types may be added within v1; receivers
  ignore what they do not know.
- Changing the meaning of a field, removing a type or changing framing
  requires a new protocol version. Peers negotiate the highest common version
  during `hello`.
