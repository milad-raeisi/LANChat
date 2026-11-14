#!/bin/sh
# LANChat installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/milad-raeisi/LANChat/main/scripts/install.sh | sh
#
# It downloads the latest release for this OS/architecture from GitHub,
# verifies its SHA-256 checksum against the release's checksums.txt, and
# installs the `lanchat` binary for the current user. No administrator
# rights are needed and no firewall or network settings are changed.
#
# Environment variables:
#   LANCHAT_VERSION          install a specific tag, e.g. v1.0.0 (default: latest release)
#   LANCHAT_INSTALL_DIR      install directory (default: /usr/local/bin if writable, else ~/.local/bin)
#   LANCHAT_NO_MODIFY_PATH=1 never edit shell profile files
#   LANCHAT_DOWNLOAD_BASE    alternative download base URL (mirrors and testing)
set -eu

REPO="milad-raeisi/LANChat"
API="https://api.github.com/repos/${REPO}/releases/latest"
BASE="${LANCHAT_DOWNLOAD_BASE:-https://github.com/${REPO}/releases/download}"

info() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

fetch() { # fetch URL OUTFILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,http' --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

fetch_stdout() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -H 'Accept: application/vnd.github+json' "$1"
	else
		wget -q -O - "$1"
	fi
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		die "no SHA-256 tool found (sha256sum, shasum or openssl)"
	fi
}

case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) die "unsupported operating system $(uname -s); on Windows use scripts/install.ps1" ;;
esac
case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) die "unsupported CPU architecture $(uname -m); supported: amd64, arm64" ;;
esac

go_install_fallback() {
	if command -v go >/dev/null 2>&1; then
		info "Building LANChat from source with 'go install' instead…"
		go install "github.com/${REPO}/cmd/lanchat@${1:-latest}"
		gobin="$(go env GOBIN)"
		[ -n "$gobin" ] || gobin="$(go env GOPATH)/bin"
		info "Installed to ${gobin}/lanchat. Make sure ${gobin} is on your PATH, then run: lanchat"
		exit 0
	fi
	die "$2"
}

version="${LANCHAT_VERSION:-}"
if [ -z "$version" ]; then
	info "Looking up the latest LANChat release…"
	version="$(fetch_stdout "$API" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)" || true
	if [ -z "$version" ]; then
		go_install_fallback latest "no published LANChat release was found on GitHub yet. Install Go (https://go.dev/dl) and run: go install github.com/${REPO}/cmd/lanchat@latest"
	fi
fi
case "$version" in
	v[0-9]*) ;;
	*) die "invalid version '$version' (expected a tag such as v1.0.0)" ;;
esac
num="${version#v}"
archive="lanchat_${num}_${os}_${arch}.tar.gz"

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t lanchat)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "Downloading LANChat ${version} for ${os}/${arch}…"
fetch "${BASE}/${version}/${archive}" "$tmp/$archive" ||
	go_install_fallback "$version" "could not download ${archive} for ${version}"
fetch "${BASE}/${version}/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt"

expected="$(awk -v f="$archive" '$2 == f || $2 == "*"f {print $1}' "$tmp/checksums.txt" | head -n 1)"
[ -n "$expected" ] || die "checksums.txt has no entry for ${archive}"
actual="$(sha256_of "$tmp/$archive")"
[ "$expected" = "$actual" ] || die "checksum mismatch for ${archive} (expected ${expected}, got ${actual}); the download may be corrupted or tampered with"
info "Checksum verified (SHA-256)."

tar -xzf "$tmp/$archive" -C "$tmp"
[ -f "$tmp/lanchat" ] || die "the archive does not contain the lanchat binary"

dir="${LANCHAT_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
	if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
		dir=/usr/local/bin
	else
		dir="$HOME/.local/bin"
	fi
fi
mkdir -p "$dir" || die "cannot create ${dir}"
[ -w "$dir" ] || die "${dir} is not writable; set LANCHAT_INSTALL_DIR to a directory you own"
install_path="$dir/lanchat"
cp "$tmp/lanchat" "$install_path.new"
chmod 755 "$install_path.new"
mv -f "$install_path.new" "$install_path"
info "Installed ${install_path}"

# Make sure the directory is on PATH for future shells.
case ":${PATH}:" in
	*":${dir}:"*) on_path=1 ;;
	*) on_path=0 ;;
esac
if [ "$on_path" -eq 0 ]; then
	line="export PATH=\"${dir}:\$PATH\" # added by the LANChat installer"
	profile=""
	case "$(basename "${SHELL:-sh}")" in
		zsh) profile="$HOME/.zshrc" ;;
		bash) if [ "$os" = darwin ]; then profile="$HOME/.bash_profile"; else profile="$HOME/.bashrc"; fi ;;
	esac
	if [ "${LANCHAT_NO_MODIFY_PATH:-0}" != 1 ] && [ -n "$profile" ]; then
		if ! grep -qs "added by the LANChat installer" "$profile"; then
			printf '\n%s\n' "$line" >>"$profile"
			info "Added ${dir} to PATH in ${profile}. Open a new terminal, or run:"
		else
			info "${profile} already adds ${dir} to PATH. Open a new terminal, or run:"
		fi
	else
		info "${dir} is not on your PATH. Add this line to your shell profile:"
	fi
	info "  export PATH=\"${dir}:\$PATH\""
fi

info ""
"$install_path" --version || warn "the installed binary did not run on this system"
info ""
info "Start LANChat with:  lanchat"
info "Diagnose networking: lanchat doctor"
if [ "$os" = darwin ]; then
	info "macOS will ask whether your terminal may find devices on the local network: allow it."
fi
