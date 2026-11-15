# Changelog

All notable changes to LANChat are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The wire protocol is versioned
separately (currently protocol v1).

## [Unreleased]

## [0.1.1] - 2026-11-15

### Changed
- Refreshed terminal interface: rounded, titled panels for the chat list,
  the conversation and the message box, with the focused panel highlighted;
  a gradient LANChat logo and status pill in the header; coloured per-sender
  gutter bars; unread badges; key-cap hints in the footer that drop whole
  hints when space runs out; and a progress bar for file transfers.
- Short conversations sit at the bottom next to the input, and an empty
  room shows a welcome card with the first steps.
- The setup wizard has a block-letter logo and step progress dots, and its
  checks use ✓/⚠/✗ markers.
- The README shows real screenshots of the chat screen, the setup wizard and
  a pairing request (`make screenshots` regenerates them).
- Releases: the Release workflow now runs on every push to `main` and
  publishes whenever `VERSION` names a version that is not released yet, so
  a release is no longer missed when the path filter does not fire or when
  the changelog section lands after the version bump.

### Fixed
- Dialogs (pairing, command palette, help, confirmations) are drawn centred
  over the screen again; previously they appeared in the top-left corner and
  blanked the rest of the screen.

## [0.1.0] - 2026-11-15

First public release.

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

### Fixed
- A recipient's rejection could be overwritten by the sender's own "sent"
  update when the acknowledgement arrived first (fast networks), so a
  rejected message showed "✓ sent" instead of "✗ failed".
- Windows: the lock holder's PID is readable (shown by `lanchat doctor`).
- Sending on a session that had just closed could report success (a Go
  `select` picks randomly between a free queue slot and the closed signal),
  so messages to a peer that had gone offline could show "✓ sent" instead
  of "◷ queued". Sends now fail with ErrClosed once a session is closed.

### Security
- Pairing codes use commit-then-reveal nonces so they cannot be ground by a
  man-in-the-middle; trust requires approval by both users on one session.
- Pairing and file-offer dialogs default to "Later", have no single-key
  accept and ignore input briefly after opening.
- Group IDs are bound to the owner's key (database schema version 2).
- Unpaired identities are not persisted; caps on unknown peers, dials,
  handshakes per IP and transfers; per-peer storage quota.
- Remote text is sanitized in all outputs including `lanchat doctor`;
  colliding or spoofed display names are shown with the short peer ID.
- Received files carry the macOS quarantine attribute / Windows
  Mark-of-the-Web.
- Go toolchain pinned to 1.26.11 and `golang.org/x/net` v0.62.0 (govulncheck
  clean).
