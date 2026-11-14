# Installing LANChat

LANChat is a single executable named `lanchat` (plus the optional
`lanchat-discovery` server for managed networks). It needs no runtime, no
administrator rights and no internet connection after installation.

## One-line install (recommended)

**macOS and Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/milad-raeisi/LANChat/main/scripts/install.sh | sh
```

**Windows (PowerShell 5.1 or later)**

```powershell
irm https://raw.githubusercontent.com/milad-raeisi/LANChat/main/scripts/install.ps1 | iex
```

What the installer does:

1. Detects your operating system and CPU (`amd64` or `arm64`).
2. Asks the GitHub API for the latest published release (or uses `LANCHAT_VERSION`).
3. Downloads `lanchat_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) and the
   release's `checksums.txt`, and **refuses to install unless the SHA-256
   checksum matches**.
4. Installs the binary for the current user:
   - macOS/Linux: `/usr/local/bin` if you can write to it, otherwise `~/.local/bin`.
   - Windows: `%LOCALAPPDATA%\Programs\LANChat`.
5. Makes sure that directory is on your `PATH`:
   - macOS/Linux: appends one marked line to `~/.zshrc`, `~/.bashrc` (Linux) or
     `~/.bash_profile` (macOS) for zsh/bash, and only once. Other shells get
     printed instructions.
   - Windows: adds the folder to your *user* `PATH`.
6. Runs `lanchat --version` to confirm the binary works.

It does not use `sudo`, does not change firewall rules and does not modify
network settings. If no release has been published yet, it falls back to
`go install` when Go is installed, and otherwise tells you what to do.

Installer options (environment variables):

| Variable | Meaning |
|---|---|
| `LANCHAT_VERSION=v1.2.3` | install a specific release instead of the latest |
| `LANCHAT_INSTALL_DIR=/path` | install into this directory |
| `LANCHAT_NO_MODIFY_PATH=1` | never edit shell profiles / user PATH |
| `LANCHAT_DOWNLOAD_BASE=URL` | download from a mirror (same layout as GitHub Releases) |

Example: `curl -fsSL …/install.sh | LANCHAT_INSTALL_DIR=$HOME/bin sh`

Prefer to read before running? Download the script, inspect it, then run
`sh install.sh`.

## With Go

```sh
go install github.com/milad-raeisi/LANChat/cmd/lanchat@latest
```

The binary lands in `$(go env GOPATH)/bin`. Builds from source report the
module version in `lanchat --version`.

## Release archives

Every tagged release on the [Releases page](https://github.com/milad-raeisi/LANChat/releases)
contains archives for `darwin`, `linux` and `windows` on `amd64` and `arm64`,
`.deb` and `.rpm` packages for Linux, `checksums.txt` and an SPDX SBOM per
archive. Verify and install manually:

```sh
sha256sum -c checksums.txt --ignore-missing        # shasum -a 256 -c on macOS
tar -xzf lanchat_<version>_linux_amd64.tar.gz
install -m 755 lanchat ~/.local/bin/
```

Debian/Ubuntu: `sudo apt install ./lanchat_<version>_linux_amd64.deb`.
Fedora/RHEL: `sudo dnf install ./lanchat_<version>_linux_amd64.rpm`.
(Installing a system package is the only installation path that needs
administrator rights.)

## Homebrew and WinGet

The release pipeline generates a Homebrew cask and a WinGet manifest, but they
are **not published yet**: publishing requires a `homebrew-tap` repository and a
pull request to `microsoft/winget-pkgs`. Until then `brew install lanchat` and
`winget install LANChat` do not work — use the one-line installer.
Maintainers: the generated files are in `dist/homebrew` and `dist/winget`
after `goreleaser release`; set `skip_upload: false` in `.goreleaser.yaml` once
the tap/fork and credentials exist.

## After installing

```sh
lanchat            # first run starts the setup wizard
lanchat doctor     # checks network, identity and discovery
```

- **macOS:** allow your terminal to "find devices on local networks" when asked
  (System Settings › Privacy & Security › Local Network).
- **Windows:** allow `lanchat` on *Private* networks in the firewall prompt and
  make sure your network profile is *Private*.
- **Linux:** allow UDP 5353 and TCP 47777 if a host firewall is active.

## Upgrading and uninstalling

Run the installer again to upgrade; your configuration, identity and history
are kept (they live in your user data directories, not next to the binary).
Database schema changes are applied automatically, and a backup copy of the
old database is written next to it first.

To uninstall, delete the `lanchat` binary and, if you also want to remove all
data, these directories:

| OS | Configuration | Data (identity, database) | Logs |
|---|---|---|---|
| macOS | `~/Library/Application Support/LANChat` | same | `~/Library/Logs/LANChat` |
| Linux | `~/.config/lanchat` | `~/.local/share/lanchat` | `~/.local/state/lanchat` |
| Windows | `%APPDATA%\LANChat` | `%LOCALAPPDATA%\LANChat` | `%LOCALAPPDATA%\LANChat\logs` |

Remove the PATH line marked `# added by the LANChat installer` from your shell
profile if the installer added one.
