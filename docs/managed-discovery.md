# Managed discovery server (`lanchat-discovery`)

LANChat normally finds peers with mDNS, which only works within one network
segment (one broadcast domain). `lanchat-discovery` is an **optional** server
for networks where peers sit on different VLANs or routed subnets that mDNS
cannot cross. Clients register with it and receive the list of other online,
authorized clients and their candidate addresses. They then connect to each
other directly, exactly as they would after an mDNS discovery.

Most deployments do not need it. Use it only when mDNS cannot reach between
users and you do not want to maintain `static_peers` lists by hand.

## What it does and what it does not do

The server does:

- authenticate each client by its LANChat identity certificate (mutual TLS)
  and check it against an allowlist of peer IDs;
- keep an in-memory directory of online peers: peer ID, display name, device
  name, protocol version and candidate addresses, with a presence timeout;
- give each authorized client the list of the *other* online authorized
  peers.

The server does **not**:

- carry, store or relay chat messages, files, typing indicators or any other
  peer-to-peer traffic. It never sees chat content;
- traverse NAT or firewalls. There is no relaying, hole punching or TURN-like
  fallback. **Peers must still be able to open direct TCP connections to each
  other on the LANChat port (default 47777)**, so the routers and firewalls
  between your VLANs must allow that traffic;
- make peers trusted. A peer found through the server is treated like any
  other discovered peer: its identity is verified in the peer-to-peer TLS
  handshake and the user still has to approve it;
- persist anything. The directory lives in memory and is rebuilt from client
  announcements after a restart.

## How it works

- Transport: HTTPS with TLS 1.3 only and HTTP/1.1. Clients present their
  LANChat identity certificate, and the server derives the caller's peer ID
  from that certificate's public key. Clients authenticate the server by
  pinning its public-key fingerprint, or with a CA certificate.
- `POST /v1/announce`: sent by each client every
  `discovery.refresh_interval_seconds` (30 s by default). It registers or
  refreshes the caller and returns the other online peers (at most 1000,
  most recently seen first), the presence TTL and the address the server
  observed.
- `POST /v1/withdraw`: sent when a client shuts down. It removes the caller
  immediately.
- `GET /healthz`: liveness. It works without a client certificate and returns
  only `{"status":"ok","peers":N}`.
- Presence: an entry expires if it is not refreshed within `presence_ttl`
  (90 s by default).
- Candidate addresses: the source address the server observed comes first.
  The addresses the client reported follow. Loopback, unspecified, multicast,
  link-local and broadcast addresses are dropped, duplicates are removed and
  the list is capped at 16. Each address is combined with the client's
  LANChat port (`ip:port`). An entry with no usable address is not shown to
  others.

## Ports

| Port      | Protocol | Direction          | Purpose                                                    |
|-----------|----------|--------------------|------------------------------------------------------------|
| 47780     | TCP      | clients → server   | Discovery API (HTTPS). Configurable with `listen`.         |
| 47777     | TCP      | peer ↔ peer        | LANChat connections between peers. Must be routable between segments. |
| 5353      | UDP      | local segment only | mDNS. Not used by the server.                              |

## Quick start (binary)

```sh
go build -trimpath -o lanchat-discovery ./cmd/lanchat-discovery

# 1. Create the server identity and print the fingerprint clients will pin.
lanchat-discovery fingerprint --identity-file /var/lib/lanchat-discovery/identity.key

# 2. List the authorized peer IDs (see "Authorization" below).
cp deploy/discovery/authorized_peers.example /etc/lanchat-discovery/authorized_peers
$EDITOR /etc/lanchat-discovery/authorized_peers

# 3. Run the server.
lanchat-discovery serve \
  --identity-file /var/lib/lanchat-discovery/identity.key \
  --authorized-peers-file /etc/lanchat-discovery/authorized_peers
```

The server refuses to start without an authorization policy. You must set
either `authorized_peers_file` or, explicitly, `allow_any = true`.

## Commands

| Command                            | Purpose |
|------------------------------------|---------|
| `lanchat-discovery [serve]`        | Run the server until SIGINT/SIGTERM, then shut down gracefully. `serve` is the default command. |
| `lanchat-discovery fingerprint`    | Print the SHA-256 fingerprint of the server certificate's public key (SPKI). It prints the raw 64-hex form, a grouped form for reading aloud, and the `managed_server_fingerprint = "..."` line for clients. If the identity does not exist yet, it is created. `--quiet` prints only the 64-hex value. |
| `lanchat-discovery healthcheck`    | GET `/healthz` on a server (default `127.0.0.1` plus the port from `LANCHAT_DISCOVERY_LISTEN`, else 47780; override with `--addr host:port`). It does not verify the server certificate and is meant for local liveness probes only. |
| `lanchat-discovery version`        | Print version information. |
| `lanchat-discovery help [command]` | Show help and the flags of a command. |

Exit codes: `0` success (healthy), `1` runtime failure (unhealthy), `2` invalid
command line or configuration.

Sample `fingerprint` output:

```text
Server certificate fingerprint (SHA-256 of the public key, SPKI)
source: /var/lib/lanchat-discovery/identity.key

  d64e7ae2c5f7019e5db90fa7bb896c09be218c104756187ef914904f9e9d34eb
  d64e 7ae2 c5f7 019e 5db9 0fa7 bb89 6c09 be21 8c10 4756 187e f914 904f 9e9d 34eb

Add to each LANChat client's config.toml, in the [discovery] section:

  managed_server_fingerprint = "d64e7ae2c5f7019e5db90fa7bb896c09be218c104756187ef914904f9e9d34eb"

Compare it with the operator over a trusted channel before using it.
```

## Configuration

Settings are applied in this order, with later sources overriding earlier
ones: built-in defaults, then the TOML file given with `--config` (or
`LANCHAT_DISCOVERY_CONFIG`), then `LANCHAT_DISCOVERY_*` environment variables,
then command-line flags. Each key has a matching flag, with underscores
replaced by dashes, and an environment variable, in upper case with the
prefix. For example, `authorized_peers_file` is also
`--authorized-peers-file` and `LANCHAT_DISCOVERY_AUTHORIZED_PEERS_FILE`.
Empty environment variables are ignored. Relative paths inside the config
file are resolved against the file's own directory. Unknown keys are an
error. See [`deploy/discovery/discovery.example.toml`](../deploy/discovery/discovery.example.toml).

| Key                     | Default | Meaning |
|-------------------------|---------|---------|
| `listen`                | `:47780` | TCP listen address. |
| `identity_file`         | `<user config dir>/lanchat-discovery/identity.key` | Persistent Ed25519 server identity, created on first use with owner-only permissions. Ignored when `tls_cert_file` is set. |
| `tls_cert_file`, `tls_key_file` | unset | PEM certificate and key to serve instead of the identity, for example from an internal CA. Both must be set together. |
| `authorized_peers_file` | unset | Allowlist of peer IDs (see below). |
| `allow_any`             | `false` | Accept any valid LANChat identity. Explicit opt-in. |
| `allowed_cidrs`         | empty (any) | Source prefixes or addresses allowed to use `/v1/*`. TOML array, or a comma-separated list in flags and environment variables. |
| `presence_ttl`          | `90s` | Expiry without a refresh (`"90s"`, `"2m"` or seconds). Keep it at least 3× the clients' refresh interval. Allowed range: 1 s to 24 h. |
| `max_peers`             | `10000` | Maximum registered peers. New registrations beyond this get HTTP 503. |
| `rate_limit`, `rate_burst` | `5`, `20` | Token bucket per source address (requests per second, burst). IPv6 sources are grouped by /64. Raise these if many clients share one NATed address. |
| `log_level`             | `info` | `debug`, `info`, `warn` or `error`. |
| `log_file`              | stderr | Size-rotated log file (0600) instead of stderr. |

## TLS and server authentication

Clients must authenticate the server, and LANChat refuses a managed server
configuration that has neither a fingerprint nor a CA file. There are two
options.

1. **Built-in identity with fingerprint pinning (default, recommended).**
   The server generates a persistent Ed25519 key in `identity_file` and
   serves a self-signed certificate for it. Run `lanchat-discovery fingerprint`
   and give the 64-hex fingerprint to users over a channel they trust. Keep
   and back up the identity file: if it is lost or regenerated, the
   fingerprint changes and every client must be updated.

2. **Your own CA.** Set `tls_cert_file` and `tls_key_file`, and give clients
   the CA certificate as `managed_ca_file`. The certificate must be valid for
   the host name or IP address that clients use in `managed_server`. An IP
   address requires an IP SAN. Restart the server after replacing the files.
   Clients can also pin a CA-issued certificate's fingerprint. That pin
   survives a renewal only if the key is reused.

The server accepts TLS 1.3 only. HTTP/2 is disabled.

## Configuring clients

In each client's `config.toml`:

```toml
[network]
mode = "managed"

[discovery]
managed_server = "discovery.example.lan:47780"   # host:port of the server
managed_server_fingerprint = "d64e7ae2c5f7019e5db90fa7bb896c09be218c104756187ef914904f9e9d34eb"
# or, with your own CA instead of a fingerprint:
# managed_ca_file = "/etc/ssl/certs/internal-ca.pem"
```

Notes:

- `managed_server` enables managed discovery. `mode = "managed"` declares
  the intent, and the configuration check then requires `managed_server`.
- mDNS and `static_peers` keep working alongside the server unless you
  disable them (`mdns_enabled = false`).
- The fingerprint may be written with spaces or colons. The grouped form
  printed by `fingerprint` is accepted.
- Clients announce every `refresh_interval_seconds` (default 30) and withdraw
  when LANChat exits.

## Authorization

Every request to `/v1/*` must carry a LANChat identity certificate. The
server derives the caller's **peer ID** from it, so a client cannot claim
another peer's ID.

### Authorized peers file (recommended)

Each user prints their peer ID with:

```sh
lanchat identity show
```

The administrator adds one peer ID per line to `authorized_peers_file`.
A peer ID is 32 characters, `a`–`z` and `2`–`7`, and is case-insensitive.
Everything after `#` is a comment, and blank lines are ignored. See
[`deploy/discovery/authorized_peers.example`](../deploy/discovery/authorized_peers.example).

- The file is re-read automatically when its modification time or size
  changes. The server checks at most every 3 seconds and also during its
  periodic expiry sweep. No restart is needed.
- Removing a peer ID revokes access. The peer gets HTTP 403 on its next
  refresh, is removed from the directory and is no longer shown to others.
- If the file is deleted, every peer is refused (fail closed) until the file
  is restored.
- If the file becomes invalid while the server is running, the previous list
  stays in effect and a warning is logged. At startup, a missing or invalid
  file stops the server with an error that names the offending line.
- Peer IDs are identifiers, not secrets, but the list does show who uses the
  service.

### `allow_any`

`allow_any = true` accepts every valid LANChat identity. Anyone who can reach
the port can then register and read the whole directory. Use it only on
networks where that is acceptable, ideally combined with `allowed_cidrs`.

### `allowed_cidrs`

This optionally restricts which source addresses may use `/v1/*`. Other
sources get HTTP 403. `/healthz` is always reachable from loopback, and from
other sources only if they are allowed.

## Docker

The build context is the repository root:

```sh
docker build -f deploy/discovery/Dockerfile -t lanchat-discovery .
```

The image is a static `CGO_ENABLED=0`, `-trimpath` binary on
`gcr.io/distroless/static-debian12:nonroot`:

- It runs as the unprivileged user 65532 and contains no shell.
- It exposes `47780/tcp` and uses a `/data` volume for the persistent
  identity at `/data/lanchat-discovery/identity.key`.
- Its `HEALTHCHECK` runs `lanchat-discovery healthcheck`. If you change the
  port with a flag or config file rather than `LANCHAT_DISCOVERY_LISTEN`,
  override the health check with `--addr`.
- The default command is `serve`.

```sh
docker volume create lanchat-discovery-data

# Print (and on first run create) the fingerprint.
docker run --rm -v lanchat-discovery-data:/data lanchat-discovery fingerprint

# Run. /etc/lanchat-discovery holds authorized_peers (readable by uid 65532).
docker run -d --name lanchat-discovery --restart unless-stopped \
  --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v lanchat-discovery-data:/data \
  -v /etc/lanchat-discovery:/config:ro \
  -e LANCHAT_DISCOVERY_AUTHORIZED_PEERS_FILE=/config/authorized_peers \
  lanchat-discovery
```

A Compose sample is in
[`deploy/discovery/docker-compose.yml`](../deploy/discovery/docker-compose.yml):

```sh
docker compose -f deploy/discovery/docker-compose.yml up -d --build
```

Notes:

- **Host networking is recommended** on Linux. With bridge networking and a
  published port, Docker may present a gateway address instead of the
  client's real address. The server would then advertise that wrong address
  first. Clients' self-reported addresses are still listed after it.
- Mount the directory that contains `authorized_peers`, not the single file.
  Many editors replace the file on save, and a single-file bind mount would
  keep showing the old contents.
- Keep the `/data` volume. Losing it changes the fingerprint.
- Do not put the server behind a TLS-terminating reverse proxy. The server
  needs the client certificate and the real source address. Plain TCP
  forwarding works but hides the source address.

## Operations

- **Logs** go to stderr by default, or to `log_file`. Registrations,
  withdrawals and expirations are logged at `info` with the peer ID and
  source address. Refusals and errors are logged at `warn`. Refreshes and
  TLS handshake failures are logged at `debug`. Request bodies are never
  logged, and display names are not logged.
- **Restarts** lose the in-memory directory. Clients re-register on their
  next refresh. Until every client has done so (up to one refresh interval,
  30 s by default), peers can briefly drop out of each other's discovered
  list.
- **Limits**: request bodies are capped at 64 KiB (HTTP 413) and headers at
  16 KiB. Read, write and idle timeouts are 15 s, 15 s and 120 s. Responses
  list at most 1000 peers.

| Status | Meaning |
|--------|---------|
| 200 | Announcement accepted; the body is the directory. |
| 204 | Withdrawal accepted. |
| 400 | Malformed or invalid request. |
| 401 | No (valid) client certificate on `/v1/*`. |
| 403 | Peer ID not authorized, or source address outside `allowed_cidrs`. Clients report "discovery server refused this identity: …". |
| 404 / 405 | Unknown path / wrong method (`/v1/*` accepts only POST). |
| 413 | Request body over 64 KiB. |
| 429 | Rate limit exceeded for the source address. |
| 503 | `max_peers` reached; existing peers can still refresh. |

Errors are returned as `{"error": "..."}`.

## Security properties

- **Content**: the server never receives chat messages or files. All chat
  traffic flows directly between peers over their own mutually authenticated
  TLS 1.3 sessions.
- **What the server learns**: which authorized peers are online and when,
  their display and device names, their LANChat port, observed and reported
  IP addresses, and protocol version. Treat the operator as trusted with this
  presence metadata.
- **What authorized peers learn**: every authorized peer sees every other
  online authorized peer's peer ID, names and addresses. There is no
  per-group or per-user visibility. Do not authorize people who should not
  see that list.
- **Server compromise**: a malicious server can hide peers, invent peer
  entries or list wrong addresses for a peer ID. It cannot impersonate a
  peer or read traffic: peers verify each other's identity keys in the
  peer-to-peer TLS handshake, and unknown peers still need the user's
  approval. Entries from the server are hints, never proof of identity.
- **Client-reported addresses** are not verified. A malicious authorized
  client can list arbitrary addresses for itself. This causes at most failed
  connection attempts, and the observed source address is always listed
  first.
- **Server impersonation** is prevented by fingerprint pinning or CA
  verification. Distribute the fingerprint over a trusted channel.
- **Hardening**: restrict port 47780 with a firewall or `allowed_cidrs`.
  Prefer `authorized_peers_file` over `allow_any`. Keep the identity file
  private (0600; the server warns if it is not) and backed up. Run as an
  unprivileged user, as the Docker image does.

## Troubleshooting

| Symptom (client log or status) | Likely cause |
|--------------------------------|--------------|
| `discovery server refused this identity: this LANChat identity is not authorized …` | The peer ID is not in `authorized_peers_file`. Compare it with `lanchat identity show`. |
| `discovery server refused this identity: source address is not allowed …` | The client's address is outside `allowed_cidrs`. |
| `discovery server fingerprint mismatch` | Wrong pin, or the server identity was regenerated (for example, a lost `/data` volume). Re-run `lanchat-discovery fingerprint`. |
| `certificate signed by unknown authority` / host name mismatch | CA mode: wrong `managed_ca_file`, or the certificate does not cover the `managed_server` host or IP. |
| `HTTP 429` | Many clients share one source address. Raise `rate_limit` and `rate_burst`. |
| `HTTP 503` | `max_peers` reached. |
| Peers appear in the list but cannot connect | TCP 47777 (or the configured LANChat port) is blocked between segments, or Docker bridge networking is advertising the wrong observed address. |
