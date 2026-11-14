#!/bin/sh
# Fails if tracked source files contain invisible or bidirectional Unicode
# control characters ("Trojan Source", CVE-2021-42574). Use \uXXXX escapes
# in string literals instead.
set -eu

files=$(git ls-files '*.go' '*.md' '*.toml' '*.yml' '*.yaml' '*.sh' 2>/dev/null || true)
[ -z "$files" ] && exit 0

# shellcheck disable=SC2086
if printf '%s\n' $files | xargs perl -CSD -ne '
    if (/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}\x{061C}]/) {
        print "$ARGV:$.: invisible or bidirectional control character\n";
        $found = 1;
    }
    close ARGV if eof;
    END { exit($found ? 1 : 0) }'; then
    echo "OK: no invisible or bidirectional control characters"
else
    echo "Replace these characters with \\uXXXX escapes." >&2
    exit 1
fi
