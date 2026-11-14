# Security Policy

## Reporting a vulnerability

Please report security problems privately through GitHub's
**Security › Report a vulnerability** form on this repository rather than in
a public issue. Include the LANChat version (`lanchat --version`), your
operating system, and steps to reproduce. You should receive an
acknowledgement within a week.

## Supported versions

Security fixes are made on the latest release. LANChat is pre-1.0 until the
first tagged release is published.

## Security model in brief

- All peer connections use TLS 1.3 with mutual authentication. Each
  installation has a persistent Ed25519 identity; the peer ID is derived from
  the public key, so it cannot be claimed by another key.
- Discovery (mDNS, static peers, managed server) only produces hints. A
  discovered peer is never trusted automatically. Trust is granted only by the
  local user after comparing a six-digit code bound to both keys and the TLS
  session.
- Chat, group and file messages are accepted only from paired peers, and the
  sender of every message is the authenticated TLS peer — never a field in
  the message.
- Messages are encrypted in transit between the two devices that exchange
  them. They are stored unencrypted in the local SQLite database, protected by
  operating-system file permissions. LANChat does not relay messages, so there
  is no intermediate party.
- Untrusted text is sanitized before it reaches the terminal; received files
  are written only inside the download directory and are never opened.
- No telemetry and no internet access are used.

See [docs/security.md](docs/security.md) for the full threat model, known
limitations (for example, discovery metadata is visible to everyone on the
local network) and the design rationale.
