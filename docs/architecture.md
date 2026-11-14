# Architecture

This document describes how LANChat is built and records the design
decisions (ADRs) and their trade-offs. It describes implemented behaviour.

## Overview

```text
 ┌──────────────── lanchat process ─────────────────────────────────────────┐
 │  cmd/lanchat ─► internal/cli ─► internal/tui (Bubble Tea)                │
 │                      │                │ commands (async)  ▲ events       │
 │                      ▼                ▼                   │              │
 │                internal/node  (application core)  ────────┘              │
 │      ┌──────────────┬───────────┼─────────────┬──────────────┐           │
 │      ▼              ▼           ▼             ▼              ▼           │
 │  discovery      transport    storage       rooms /       transfer        │
 │ (mDNS, static,  (TLS 1.3     (SQLite,      groups        (file names,    │
 │  managed)       sessions)    migrations)   rules         verification)   │
 │      │              │                                                    │
 │      └── netif ─────┴── security/identity, security/tlsconf, protocol    │
 └──────────────────────────────────────────────────────────────────────────┘
```

| Package | Responsibility |
|---|---|
| `internal/node` | lifecycle, peer registry, connection management, pairing/trust, messaging, groups, file transfer, network monitoring, events |
| `internal/tui` | setup wizard and chat screen; talks to the core only through the `Backend` interface |
| `internal/cli` | command line, process lifecycle, single-instance lock, logging setup |
| `internal/network/transport` | TLS handshake, `hello` exchange, framed reader/writer, heartbeats, rate limiting |
| `internal/network/discovery` | mDNS/DNS-SD, static peers, managed-discovery client |
| `internal/network/netif` | interface enumeration, classification, recommendation, change detection |
| `internal/protocol` | wire format, message schemas and validation |
| `internal/security/identity`, `tlsconf` | Ed25519 identity, peer IDs, fingerprints, certificates, pairing codes, TLS configs |
| `internal/storage` | SQLite schema, migrations and queries |
| `internal/rooms` | pure group-membership rules |
| `internal/transfer` | safe file names and verified incoming files |
| `internal/textsafe` | sanitizing untrusted text for the terminal |
| `internal/doctor` | diagnostics |
| `internal/discoverysrv`, `cmd/lanchat-discovery` | optional managed discovery server |

### Concurrency model

- The UI never performs I/O on its event loop: database queries and network
  actions run as Bubble Tea commands (goroutines) and return messages.
- The core publishes `node.Event`s on a bounded channel. Events are hints
  ("peers changed", "conversation X changed"); the UI re-queries state. If the
  UI falls behind, events are dropped instead of blocking the network, and the
  UI's next refresh catches up.
- `Node.mu` guards in-memory state only. Database calls and network writes are
  never made while holding it.
- Each session has one reader goroutine. Frames from a peer are handled
  sequentially on it, which preserves per-peer ordering.
- Writes go to two bounded queues per session: control (chat, acks, presence)
  and bulk (file chunks). The writer always drains control first, so file
  transfers never delay chat. The end-of-file marker travels on the bulk queue
  so it cannot overtake the last chunk.
- Concurrency is bounded everywhere: 16 concurrent inbound handshakes, 4
  concurrent outbound dials, `network.max_connections` sessions,
  `security.max_untrusted_sessions` unpaired sessions, 8 active transfers.

## Lifecycle

1. `lanchat` resolves the per-user directories, takes an exclusive lock on
   `lanchat.lock` (one running instance per profile; the OS releases the lock
   if the process dies), loads and validates `config.toml` (or runs the
   wizard), sets up logging to a rotated file, and loads or creates the
   identity.
2. The SQLite database is opened and migrated.
3. The node binds one TCP listener, selects interfaces, starts discovery and
   its background loops, and the TUI starts.
4. On quit (`Ctrl+C`, `/quit`, SIGTERM) the node withdraws its mDNS
   announcement (goodbye packets), tells connected peers it is shutting down,
   aborts transfers, waits a bounded time for goroutines, and the terminal is
   restored by Bubble Tea.

## Discovery

Discovery only produces *adverts*: unverified hints that "peer X may be
reachable at these addresses". Identity is proven by TLS, and trust by the
user.

- **mDNS / DNS-SD** — service `_lanchat._tcp.local.`, instance name
  `LANChat-<first 12 characters of the peer ID>`. TXT keys: `v` (protocol
  version), `id` (peer ID), `name`, `dev`, `caps`. The service is announced
  only on the selected interfaces. Browsing follows the continuous-querying
  schedule of RFC 6762 §5.2: queries after 1 s, 2 s, 4 s … doubling up to
  `discovery.refresh_interval_seconds` (30 s), and restarting at 1 s after a
  manual refresh or a network change. Adverts expire after three refresh
  intervals plus 15 s without being seen again; goodbye packets remove them
  immediately.
- **Static peers** — `discovery.static_peers` host:port entries, re-resolved
  every refresh interval. Their identity is learned during the handshake.
- **Managed discovery** — see [managed-discovery.md](managed-discovery.md).

**Interface selection.** `network.interface = "auto"` selects every
interface that is up, supports multicast, has addresses and is not classified
as virtual (Docker, VPN tunnels, VM adapters, AWDL, …). A named interface is
used as given, even if virtual. The network monitor polls every 5 s; when
addresses or interfaces change (Wi-Fi reconnect, DHCP renewal) it restarts
discovery and immediately retries every peer.

## Connections

- One listener: a dual-stack `[::]:port` socket when IPv4 and IPv6 are both
  enabled, so the families never compete for the port; `tcp4`/`tcp6` when only
  one is enabled; or `listen_address` if set.
- Discovered peers are dialed automatically, including unpaired ones (bounded
  by `max_untrusted_sessions`), so that reachability can be shown and pairing
  is possible. Addresses are tried in order: private IPv4, other IPv4, IPv6,
  link-local IPv6 (with zone).
- **Backoff**: after a failure, the delay is 1 s × 2ⁿ with ±20 % jitter, capped
  at 60 s; after 8 consecutive failures, 5 minutes. A peer that reappears in
  discovery, a network change and `Ctrl+R` reset the backoff.
- **Liveness**: each session sends a ping every
  `network.heartbeat_interval_seconds` (15 s); a session that receives nothing
  for three intervals is closed and the peer is shown offline (about 45 s for
  an abruptly disappearing laptop). TCP keepalive is also enabled.
- **Duplicate connections** (ADR-5): if two sessions exist between the same
  pair, both sides keep the one dialed by the peer with the lexicographically
  smaller ID; if both were dialed by the same side, the newer wins. Both ends
  apply the same rule, so they converge without coordination. To make
  duplicates rare, the peer with the larger ID waits 1.5 s before dialing a
  newly discovered peer.
- **Flow control**: inbound envelopes are limited per session by a token
  bucket (burst 2000, 500/s). A peer above the rate is *throttled* — the
  session stops reading and TCP backpressure slows the sender — rather than
  disconnected, so legitimate bursts lose nothing.

## Messaging

### Conversations

| Conversation | ID | Recipients | Accepted from |
|---|---|---|---|
| Public room | `room:<name>` | paired, connected peers who announced the room | paired peers, if we joined the room |
| Direct | `dm:<peer-id>` | that peer (must be paired) | that paired peer |
| Group | `group:<group-id>` | members of the local snapshot | paired members of the local snapshot |

Room membership is announced in `presence` messages (up to 32 rooms) and
kept in memory per session. `#general` always exists and cannot be left.

### Dissemination (ADR-6)

Every message is sent **directly** from its author to each recipient over the
pair's authenticated session. Nothing is relayed or forwarded. Consequences:

- no propagation loops and no duplicate copies created by forwarding;
- confidentiality between two devices equals the TLS session's;
- trust is pairwise: in a group, you only exchange messages with members you
  have paired with. Members you are not paired with get a delivery row marked
  failed ("not paired with this member") so the UI shows it honestly.

### Delivery states

Each outgoing message has one delivery row per recipient:

`pending` (queued) → `sent` (written to the session) → `delivered` (recipient
acknowledged that it **stored** the message) or `failed`.

- Acknowledgements only change the row of the acknowledging peer.
- On every (re)connection, the sender resends all `pending` and `sent` rows to
  that peer. The maintenance loop (every 10 s) resends `pending` rows and
  `sent` rows that have waited more than 2 minutes.
- Recipients de-duplicate by `(sender ID, message ID)` (a unique key in
  SQLite) and acknowledge duplicates again, so retries never create copies.
- Rows expire to `failed` after `chat.offline_queue_ttl_hours` (default 7
  days) or `chat.max_retry_attempts` sends (default 20). The message itself is
  never deleted; `/retry` re-queues failed rows.
- Public-room messages are addressed to members online at send time only;
  they are not queued for room members who are offline. Direct and group
  messages are queued for offline recipients (unless
  `chat.queue_offline_messages = false`; then they fail immediately). A peer
  queue holds at most `chat.max_queued_per_peer` messages.
- Offline delivery requires both devices to be online at the same time at some
  point; there is no store-and-forward server.

### Ordering and clocks

There is no global order in a decentralized system. LANChat guarantees FIFO
order per sender over a session and displays messages in **local arrival
order** (SQLite sequence numbers), which is deterministic per device.
Timestamps are the sender's clock and are display-only; a timestamp more than
one minute in the future is replaced by the receive time. No security decision
depends on wall-clock time; certificates are verified by key, not by validity
period.

## Groups (ADR-7)

Groups are **owner-authoritative**. The creator is the owner for the group's
lifetime and the only writer of membership. Each change increments a version
and produces a complete snapshot (`group.update`). A snapshot is applied only
if it arrives from the owner over the owner's authenticated session, names the
same owner as the local copy, and has a strictly higher version. With a single
writer, conflicting concurrent updates cannot occur.

- Invite: owner adds a paired peer → snapshot to all members. A peer that is
  offline receives it when it next connects to the owner.
- Remove: owner removes → snapshot to remaining members and to the removed
  member (who marks the group "removed" and can no longer send to it).
- Leave: a member marks the group "left" and sends `group.leave` to the owner,
  or reports it in `group.sync` on the next connection if the owner was
  offline. The owner publishes the new snapshot. Leaving as owner disbands the
  group.
- `group.sync` (sent on every trusted connection) lists groups owned by the
  peer with their known versions; the owner answers with a current snapshot
  for members it no longer lists (so removals reach members that were offline).
- Limitation: membership changes propagate only through the owner. If the
  owner never comes online again, the membership is frozen (messages between
  existing paired members still work).

## File transfer

1. The sender offers a regular file (`file.offer`: ID, name, size). The
   recipient sees a dialog; large offers above `transfer.max_file_size_mb` are
   declined automatically.
2. On acceptance, the recipient creates a hidden temporary file
   (`.<name>.<random>.lanchat-part`, mode 0600) in the download directory and
   sends `file.accept`.
3. The sender streams 64 KiB chunk frames on the session's bulk queue and
   hashes the data; then sends `file.done` with the size and SHA-256.
4. The recipient accepts only in-order chunks that do not exceed the
   announced size, verifies size and hash, and only then renames the file to
   a collision-free name (`report (1).pdf`). On any failure the temporary file
   is deleted. `file.result` tells the sender the verdict.
5. Either side can cancel; a lost connection fails the transfer. Unanswered
   offers expire after 5 minutes. Interrupted transfers are not resumed
   (stale temporary files are removed at startup).

Remote file names are reduced to a single safe path component: directory
parts, drive letters, control and bidi characters, characters invalid on
Windows, leading dots and reserved device names are neutralised.

## Persistence

SQLite (pure Go, `modernc.org/sqlite`), WAL journal, foreign keys on, busy
timeout 5 s, `BEGIN IMMEDIATE` transactions, parameterised queries only.
Tables: `peers`, `conversations`, `groups`, `group_members`, `messages`,
`deliveries`, `transfers`, `schema_migrations`. Migrations are embedded,
numbered and applied in transactions; before migrating an existing database
a `VACUUM INTO` backup (`lanchat.db.bak-v<from>-<time>`) is written. A newer
schema than the binary understands is refused rather than modified. With
`chat.save_history = false` messages are kept only for the session and deleted
on exit (trust and peers are always persisted).

## Architecture decision records

**ADR-1 Go + Bubble Tea v2 + Lip Gloss v2.** Single static binaries for six
targets; a mature TUI stack with keyboard enhancements (Shift+Enter where
supported), layer compositing for dialogs and colour downsampling for limited
terminals.

**ADR-2 Pure-Go SQLite (`modernc.org/sqlite`).** No CGO, so every target is a
simple cross-compile and there is no system library dependency. Trade-off:
somewhat slower than the C library, which is irrelevant at chat volumes.

**ADR-3 Identity = Ed25519 key = TLS certificate key.** The self-signed
certificate presented in TLS 1.3 carries the identity key, so the TLS
handshake itself proves possession of the identity; the peer ID is a hash of
the public key and cannot be claimed by another key. No separate signing
layer or certificate authority is needed. Trade-off: no PKI, so trust must be
established by people (ADR-4).

**ADR-4 Explicit mutual pairing with a short authentication string.** A
six-digit code derived from both public keys and the TLS exporter of the
session is shown on both screens. A man-in-the-middle necessarily terminates
two different TLS sessions and keys, so the codes would differ. Trust is
granted only by local user action (request or accept); an unsolicited
acceptance from the network never grants trust. Trade-off: one manual step per
pair of users; chosen over trust-on-first-use because the specification
forbids silent trust.

**ADR-5 Deterministic duplicate-connection resolution** (see Connections).
Chosen over "only the smaller ID dials", which fails when only one direction
is reachable through a firewall.

**ADR-6 Direct fan-out without relaying** (see Messaging). Simple, loop-free
and keeps the security property "only the author and recipients handle the
plaintext". Trade-off: no store-and-forward through third parties; members
must be pairwise paired.

**ADR-7 Owner-authoritative groups** (see Groups). Single-writer versioned
snapshots avoid CRDTs and conflict resolution. Trade-off: the owner is a
coordination point for membership changes.

**ADR-8 Length-prefixed frames with JSON envelopes.** Explicit framing with
hard size limits before allocation; JSON keeps the protocol inspectable and
needs no code generation. File data uses a binary frame kind to avoid base64
overhead. Trade-off: JSON is larger than Protocol Buffers, irrelevant for
chat-sized messages.

**ADR-9 Managed discovery is discovery only.** The optional server never
carries messages, so enabling it does not change the confidentiality model;
it cannot bridge networks that are not routable to each other.

**ADR-10 Background daemon not implemented.** The specification makes it
optional. LANChat runs while the terminal session runs; the single-instance
lock prevents two processes from using the same identity concurrently.

**ADR-11 Throttle, don't disconnect, on rate limits** (see Connections).
