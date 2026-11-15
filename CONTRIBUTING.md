# Contributing to LANChat

Thank you for helping. LANChat aims to stay small, dependable and secure, so
changes should be focused and well tested.

## Development setup

Requirements: Go (the toolchain version in `go.mod` is downloaded
automatically by the `go` command), Git, and `make`. No C compiler is needed;
SQLite is a pure-Go implementation.

```sh
git clone https://github.com/milad-raeisi/LANChat.git
cd LANChat
make build
make test race lint vuln
```

`make build` puts the binaries in `./bin`; `test`/`race` run all tests
without/with the race detector; `lint` runs gofmt, go vet, staticcheck and the
invisible-Unicode guard; `vuln` runs govulncheck. `make help` lists all
targets.

Run a development profile that does not touch your real data:

```sh
LANCHAT_HOME=/tmp/lanchat-a ./bin/lanchat
LANCHAT_HOME=/tmp/lanchat-b ./bin/lanchat
```

For the second profile choose another port in the wizard (Advanced network
configuration).

## Code layout

See [docs/architecture.md](docs/architecture.md). In short: `internal/node`
is the application core, `internal/tui` the interface, `internal/network`
discovery and sessions, `internal/protocol` the wire format,
`internal/storage` persistence, `internal/security` identity and TLS.

## Guidelines

- Keep the dependency list short; prefer the standard library.
- Never trust data from the network: validate in `internal/protocol`, check
  authorization in `internal/node`, sanitize text with `internal/textsafe`
  before rendering.
- Do not log message bodies or key material.
- Do not write literal invisible or bidirectional Unicode characters in
  source; use `\uXXXX` escapes (`make invisible` enforces this).
- Add tests for every behaviour change: unit tests next to the code,
  multi-node tests in `tests/integration`, CLI tests in `tests/e2e`.
- Wire protocol changes must stay compatible with protocol v1 peers or bump
  the protocol version and document it in `docs/protocol.md`.
- Update `CHANGELOG.md` and the relevant documentation in the same change.

## Releasing

Releases are automatic. To publish version `X.Y.Z`:

1. In a pull request, set the `VERSION` file to `X.Y.Z` (semantic versioning;
   `X.Y.Z-rc.1` publishes a pre-release).
2. Move the entries under `## [Unreleased]` in `CHANGELOG.md` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section. Its text becomes the release notes.
3. Run `make release-check`. CI runs the same check on the pull request.
4. Merge. The Release workflow tests the merged commit, creates the tag
   `vX.Y.Z` and publishes the binaries, packages, checksums and SBOMs.

The version must be higher than the latest release and the tag must not
exist yet. Pull requests that do not change `VERSION` never publish anything.
A maintainer can also release by pushing a `vX.Y.Z` tag manually.

## Pull requests

1. Open an issue first for larger changes.
2. Make sure `make lint race` passes.
3. Describe what you tested, on which operating systems.

By contributing you agree that your work is licensed under the MIT License.
