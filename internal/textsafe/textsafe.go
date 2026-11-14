// Package textsafe sanitizes untrusted text before it is rendered in the
// terminal. Peers control message bodies, display names, device names, room
// names and file names; none of them may be able to emit terminal control
// sequences, reorder text with bidirectional overrides or break the layout.
package textsafe

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	zwj  = '\u200d' // zero-width joiner: required for emoji sequences
	zwnj = '\u200c' // zero-width non-joiner: required by several scripts
)

// isBidiControl reports bidirectional formatting characters that can visually
// reorder text ("Trojan Source" style spoofing).
func isBidiControl(r rune) bool {
	switch {
	case r >= '\u202a' && r <= '\u202e': // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= '\u2066' && r <= '\u2069': // LRI, RLI, FSI, PDI
		return true
	case r == '\u200e' || r == '\u200f' || r == '\u061c': // LRM, RLM, ALM
		return true
	}
	return false
}

// Text sanitizes a multi-line untrusted string for display:
//   - invalid UTF-8 is replaced with U+FFFD
//   - CRLF and CR become LF
//   - tabs become four spaces
//   - ESC, every other C0 control, DEL and C1 controls are removed
//   - bidirectional override/isolate controls are removed
//   - other invisible format characters are removed, except ZWJ/ZWNJ which
//     legitimate emoji and scripts need
func Text(s string) string {
	if isPlainASCII(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prevCR := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			b.WriteRune('�')
			prevCR = false
			continue
		}
		switch {
		case r == '\r':
			b.WriteByte('\n')
			prevCR = true
			continue
		case r == '\n':
			if !prevCR {
				b.WriteByte('\n')
			}
		case r == '\t':
			b.WriteString("    ")
		case unsafeRune(r):
			// dropped
		default:
			b.WriteRune(r)
		}
		prevCR = false
	}
	return b.String()
}

// Line sanitizes an untrusted single-line value such as a display name: in
// addition to Text, line breaks and tabs become spaces, runs of whitespace
// collapse, the result is trimmed and truncated to maxRunes (0 = no limit).
func Line(s string, maxRunes int) string {
	s = Text(s)
	var b strings.Builder
	b.Grow(len(s))
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			if maxRunes > 0 && n+1 >= maxRunes {
				break
			}
			b.WriteByte(' ')
			n++
		}
		space = false
		if maxRunes > 0 && n >= maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// ContainsUnsafe reports whether s contains anything Text would remove or
// rewrite (other than line-ending normalisation and tabs).
func ContainsUnsafe(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			continue
		}
		if unsafeRune(r) {
			return true
		}
	}
	return false
}

func unsafeRune(r rune) bool {
	if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	if isBidiControl(r) {
		return true
	}
	if r == zwj || r == zwnj {
		return false
	}
	if unicode.Is(unicode.Cf, r) { // e.g. U+FEFF BOM, U+200B ZWSP, U+2060 WJ, soft hyphen
		return true
	}
	if unicode.Is(unicode.Co, r) || unicode.Is(unicode.Cs, r) { // private use / surrogates
		return true
	}
	return false
}

func isPlainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// FileName sanitizes an untrusted file name for display only. Use the
// transfer package for names that touch the filesystem.
func FileName(s string) string {
	return Line(s, 120)
}
