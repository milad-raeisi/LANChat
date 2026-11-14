# Troubleshooting

Start with:

```sh
lanchat doctor --verbose
```

It checks, in order: configuration, identity, network interfaces, the TCP
listener, the database, the multicast socket, whether a test announcement is
published and received back, which other LANChat instances answer, and — when
LANChat itself is not running — whether an authenticated TLS connection to
them succeeds. Each stage is reported separately, so you can see where things
stop. Logs are in the log directory (`lanchat config path` shows the
configuration directory; see [configuration.md](configuration.md)); run with
`--debug` for detailed logs.

## Nobody appears under NEARBY

| Check | Fix |
|---|---|
| Are you on the same network segment? | mDNS does not cross routers or VLANs. Use `static_peers` or managed discovery. |
| Guest/hotel/conference Wi-Fi | Client isolation blocks device-to-device traffic. Use a different network. |
| macOS | Allow your terminal app under System Settings › Privacy & Security › **Local Network**. Without it, multicast silently fails. |
| Windows | The network profile must be **Private** (Settings › Network & Internet › your network). Allow `lanchat` on private networks in the firewall prompt (or Windows Security › Firewall › Allow an app). |
| Linux | Allow UDP 5353 and TCP 47777: `sudo ufw allow 5353/udp && sudo ufw allow 47777/tcp`, or `sudo firewall-cmd --permanent --add-service=mdns --add-port=47777/tcp && sudo firewall-cmd --reload`. |
| VPN active | Some VPN clients capture all traffic. Choose the LAN interface explicitly: `lanchat network interfaces`, then `network.interface = "en0"` (example). |
| Docker / VM | Containers on bridge networks are not on your LAN. Use host networking or static peers. |

Press `Ctrl+R` in LANChat to re-query immediately.

## Someone is listed but "unreachable"

Discovery works but the TCP/TLS connection does not. The sidebar entry shows
the reason (`/users` lists it):

- **connection refused** — LANChat is not listening there (closed, other
  port) or a firewall rejects TCP 47777.
- **timed out** — a firewall drops the connection, or the address is not
  routable from your network.
- **identity mismatch** — the advertised address answered with a different
  key. Someone may be spoofing announcements; LANChat refuses the connection.
- **incompatible LANChat version** — update both sides.

## Pairing

- The codes on both screens must be identical. If they differ, cancel —
  something is intercepting the connection — and try again on a trusted
  network.
- "Waiting for X to answer…" — X needs LANChat open; the request shows up on
  their screen (or under NEARBY with "wants to pair").
- A new identity with a known person's name is flagged with ⚠. If they
  reinstalled or ran `lanchat identity reset`, verify the code in person and
  pair again; revoke the old identity with `/unpair`.

## Messages stay "◷ queued" or "✓ sent"

- **queued** — the recipient is offline; LANChat retries when they reconnect
  (both must be online at the same time).
- **sent** — written to the network but not yet acknowledged. It is resent
  after reconnects and every two minutes.
- **✗ failed** — expired, revoked, or not paired with that group member.
  `/retry` re-queues failed messages of the conversation.

## Errors at startup

| Message | Meaning |
|---|---|
| `the LANChat port is already in use` | Another program (or another LANChat profile) uses the port. Choose another `network.port`. |
| `another LANChat instance is already running with this profile` | One instance per profile. Use `--home DIR` for a second profile. |
| `invalid configuration` | Fix the listed keys (`lanchat config edit`) or rerun `lanchat --setup`. |
| `database is corrupted` | Move the database file aside (LANChat creates a new one) or restore a backup made with `lanchat data backup`. Peers will need to pair again if you start fresh. |
| `needs an interactive terminal` | Run `lanchat` in a terminal window, not through a pipe. |
| `identity key … permissions` | `chmod 600` the key file as shown. |

## Terminal problems

- Layout looks broken: use a terminal with UTF-8 and at least 40×10
  characters; below 72×16 LANChat switches to a compact layout without the
  sidebar (open conversations with `Ctrl+L`).
- No colours or odd colours: try `/theme monochrome` or `/theme minimal`.
- `Shift+Enter` sends instead of inserting a new line: your terminal does not
  report it; use `Alt+Enter` or `Ctrl+J`, or change `[keys] newline`.
- tmux/screen: enable `set -g extended-keys on` (tmux) for better key support.

## Managed discovery

See [managed-discovery.md](managed-discovery.md). `lanchat doctor` reports
whether registration succeeded and the address the server observed. A
fingerprint mismatch means you are not talking to the expected server.

## Platform-specific limitations

- **macOS**: the Local Network permission is granted to the terminal app, not
  to `lanchat`; each terminal app (Terminal, iTerm2, VS Code) asks separately.
- **Windows**: discovery requires the *Private* network profile; on *Public*
  networks Windows blocks inbound connections and multicast.
- **Linux**: some distributions run `avahi-daemon`; it coexists with LANChat
  (both share UDP 5353). Container hosts may have many virtual interfaces;
  they are excluded automatically.
- **All**: LANChat does not run in the background after you quit; a
  background service mode is not implemented.
