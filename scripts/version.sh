#!/bin/sh
# Release version helper used by CI and maintainers.
#
#   scripts/version.sh current          print the version in VERSION
#   scripts/version.sh status           "release" if tag vVERSION does not exist yet, else "exists"
#   scripts/version.sh check            validate VERSION for a new release
#   scripts/version.sh notes [VERSION]  print the CHANGELOG.md section for VERSION
#
# A release is valid when VERSION is a semantic version, the tag does not
# exist yet, it is not lower than the latest released version, and
# CHANGELOG.md has a non-empty "## [VERSION]" section.
set -eu
cd "$(dirname "$0")/.."

semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

current() {
	[ -f VERSION ] || die "VERSION file not found"
	v=$(tr -d ' \t\r\n' <VERSION)
	printf '%s\n' "$v" | grep -Eq "$semver" ||
		die "VERSION '$v' is not a semantic version (examples: 1.2.3, 1.2.3-rc.1)"
	printf '%s\n' "$v"
}

# Released versions without the leading "v": local tags plus, when the
# remote is reachable, the remote's tags (works with shallow clones).
released() {
	{
		git tag -l 'v*' 2>/dev/null
		git ls-remote --tags --refs origin 'v*' 2>/dev/null | sed 's#.*refs/tags/##'
	} | sed 's/^v//' | grep -E "$semver" | sort -u
}

sort_core() { sort -t. -k1,1n -k2,2n -k3,3n; }

notes() {
	v=${1:-$(current)}
	out=$(awk -v hdr="## [$v]" '
		index($0, hdr) == 1 { found = 1; next }
		found && /^## \[/ { exit }
		found { print }
	' CHANGELOG.md)
	[ -n "$(printf '%s' "$out" | tr -d '[:space:]')" ] ||
		die "CHANGELOG.md has no non-empty '## [$v]' section"
	printf '%s\n' "$out"
}

check() {
	v=$(current)
	if released | grep -qx "$v"; then
		die "v$v is already released; bump VERSION"
	fi
	core=${v%%-*}
	latest=$(released | sed 's/-.*//' | sort_core | tail -n 1)
	if [ -n "$latest" ]; then
		highest=$(printf '%s\n%s\n' "$latest" "$core" | sort_core | tail -n 1)
		[ "$highest" = "$core" ] || die "VERSION $v is lower than the latest release $latest"
		if [ "$core" = "$latest" ] && released | grep -qx "$latest"; then
			die "$latest is already released; use a higher version"
		fi
	fi
	notes "$v" >/dev/null
	printf 'VERSION %s is ready to release (latest released: %s)\n' "$v" "${latest:-none}"
}

case "${1:-}" in
current) current ;;
status)
	v=$(current)
	if released | grep -qx "$v"; then echo exists; else echo release; fi
	;;
check) check ;;
notes) notes "${2:-}" ;;
*)
	echo "usage: scripts/version.sh current|status|check|notes [VERSION]" >&2
	exit 2
	;;
esac
