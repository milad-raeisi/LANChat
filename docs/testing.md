# Testing and verification status

## Test suites

| Layer | Where | What it covers |
|---|---|---|
| Unit | `internal/*/…_test.go` | configuration validation; directory resolution per OS; file locking; identity generation, storage and verification; TLS mutual auth, forged/foreign certificates, TLS 1.2 refusal; framing, limits and message validation; SQLite migrations, dedup, delivery state, search, backup, corruption detection; group rules incl. ID hijack; safe file names and verified downloads; interface classification; terminal sanitisation; mDNS advert parsing and a real mDNS loopback test (skips when multicast is unavailable) |
| Fuzz | `internal/protocol` (`FuzzReader`, `FuzzChatBody`), `internal/textsafe` (`FuzzText`) | arbitrary bytes into the frame reader and body decoders; sanitiser invariants |
| UI | `internal/tui` | rendering at several sizes and after resizes, all themes, escape-sequence neutralisation, long-word wrapping, sending vs. local commands, ambiguous names, pairing dialog input guard and safe defaults, spoofed names |
| Integration | `tests/integration` | several real nodes over TCP + TLS 1.3 on loopback: pairing with codes, one-sided approval, commitment mismatch, unsolicited trust, direct/room/group messaging, group removal and leave, offline queue across restart with exactly-once delivery, duplicate-connection races, file transfer (multi-MiB, collisions, reject, cancel, size limit), malformed traffic, identity-mismatch adverts, impersonation warning, revocation, export, search |
| End-to-end | `tests/e2e` | builds the `lanchat` binary and runs every non-interactive command with exit codes |
| Discovery server | `internal/discoverysrv`, `cmd/lanchat-discovery` | real HTTPS/mTLS with the real client: authorisation, pinning, expiry, limits, fail-closed allowlist |

Commands: `make test`, `make race`, `make integration`, `make e2e`, `make fuzz`,
`make bench`, `make lint`, `make vuln`.

## What was verified, and where

Verified on **macOS 27 (Apple Silicon, arm64)**:

- `go test -race ./...` — all packages pass.
- staticcheck clean; govulncheck: no known vulnerabilities (Go 1.26.11).
- Cross-compilation of `lanchat` and `lanchat-discovery` for darwin, linux
  and windows on amd64 and arm64; GoReleaser snapshot produced all archives,
  `.deb`/`.rpm` packages, checksums and Homebrew/WinGet manifests.
- **Two separate `lanchat` processes** (separate profiles and ports) driven
  through their real TUIs with `expect`: discovery via real mDNS, identical
  verification code on both screens after commit-then-reveal, explicit
  approval on both sides, a room message and a private message delivered,
  clean exit; afterwards both databases contained the trusted peer and both
  messages (checked with `lanchat peers list` and `lanchat data export`).
- `lanchat doctor` on a real network (multicast socket, self-observed
  advertisement, honest "no peers" warning).
- `scripts/install.sh` against the real snapshot artifacts served locally:
  checksum verification, installation, PATH set-up, idempotent re-run,
  rejection of a tampered checksum.
- The discovery server's Docker image was built and run (by the developer
  who wrote it): health check, persistence of its identity, clean stop.

**Not yet verified** (no hardware or runner was available during
development):

- Running on Linux and Windows machines, and on Intel Macs. CI runs the full
  test suite on `ubuntu-latest`, `macos-latest` and `windows-latest` once the
  repository is pushed; results will appear there.
- Communication between two **physically separate** computers (Scenario A:
  macOS ↔ Windows over Wi-Fi). Same-host tests use real sockets and real
  mDNS but not a physical network.
- `scripts/install.ps1` (PowerShell was not available) and installation from a
  published GitHub release (none has been published yet).
- Behaviour behind specific enterprise firewalls and VLAN setups with the
  managed discovery server across real network segments.
- Screen readers and very limited terminals (only colour downsampling and the
  monochrome theme were exercised).

Please report results from other platforms in an issue.
