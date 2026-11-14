package textsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTextRemovesEscapeSequences(t *testing.T) {
	cases := map[string]string{
		"hello":                        "hello",
		"\x1b[2J\x1b[Hfake prompt":     "[2J[Hfake prompt",
		"title\x1b]0;pwned\x07":        "title]0;pwned",
		"bell\x07":                     "bell",
		"c1\u009b31m red":              "c131m red",
		"crlf\r\nline":                 "crlf\nline",
		"cr\roverwrite":                "cr\noverwrite",
		"tab\tx":                       "tab    x",
		"bidi \u202egnp.exe":           "bidi gnp.exe",
		"iso\u2067late\u2069":          "isolate",
		"zero\u200bwidth":              "zerowidth",
		"bom\ufeff":                    "bom",
		"family 👨\u200d👩\u200d👧 emoji": "family 👨\u200d👩\u200d👧 emoji",
		"del\x7f":                      "del",
	}
	for in, want := range cases {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTextInvalidUTF8(t *testing.T) {
	got := Text("a\xffb")
	if !utf8.ValidString(got) || !strings.Contains(got, "�") {
		t.Fatalf("invalid UTF-8 not replaced: %q", got)
	}
}

func TestLine(t *testing.T) {
	if got := Line("  Maryam \n\t Admin  ", 0); got != "Maryam Admin" {
		t.Fatalf("got %q", got)
	}
	if got := Line("abcdefghij", 4); got != "abcd" {
		t.Fatalf("truncate got %q", got)
	}
	if got := Line("ab cd ef", 5); utf8.RuneCountInString(got) > 5 {
		t.Fatalf("truncate with spaces got %q", got)
	}
	if got := Line("\x1b[31mRed\x1b[0m", 32); strings.ContainsRune(got, 0x1b) {
		t.Fatalf("escape survived: %q", got)
	}
}

func TestContainsUnsafe(t *testing.T) {
	if ContainsUnsafe("plain text\nwith newline") {
		t.Fatal("plain text flagged")
	}
	for _, s := range []string{"\x1b[0m", "a\u202eb", "\xff"} {
		if !ContainsUnsafe(s) {
			t.Fatalf("%q not flagged", s)
		}
	}
}

func FuzzText(f *testing.F) {
	for _, s := range []string{"hello", "\x1b[2J", "\u202e", "a\r\nb", "\xff\xfe"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := Text(s)
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 output for %q", s)
		}
		for _, r := range out {
			if r == '\n' {
				continue
			}
			if unsafeRune(r) {
				t.Fatalf("unsafe rune %U survived in %q", r, out)
			}
		}
		if Text(out) != out {
			t.Fatalf("Text is not idempotent for %q", s)
		}
	})
}
