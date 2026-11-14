# Changelog

All notable changes to LANChat are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The wire protocol is versioned
separately (currently protocol v1).

## [Unreleased]

### Added
- Terminal user interface (Bubble Tea v2) with first-run setup wizard,
  responsive/compact layouts, four themes, command palette, search,
  conversation picker and keyboard-only operation.
- Peer discovery via mDNS/DNS-SD (`_lanchat._tcp.local.`), static peers and an
  optional managed discovery server (`lanchat-discovery`).
- TLS 1.3 mutual authentication with persistent Ed25519 identities, explicit
  pairing with six-digit verification codes, revocation, impersonation and
  identity-mismatch warnings.
- Public rooms, private messages and owner-managed private groups with
  acknowledged delivery states, offline queueing and retries.
- Peer-to-peer file transfer with recipient approval, progress, cancellation
  and SHA-256 verification.
- SQLite persistence with migrations, search, export, backup and purge.
- `lanchat` CLI: config, network, peers, identity, data and doctor commands.
- One-line installers for macOS/Linux (`scripts/install.sh`) and Windows
  (`scripts/install.ps1`) with checksum verification.
- GoReleaser packaging, GitHub Actions CI and tag-only release workflow.
