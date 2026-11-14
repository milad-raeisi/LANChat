package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	w, err := NewRotatingWriter(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 60) + "\n"
	for i := 0; i < 10; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	for _, name := range []string{p, p + ".1", p + ".2"} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
	}
	if _, err := os.Stat(p + ".3"); !os.IsNotExist(err) {
		t.Fatalf("retention exceeded: %v", err)
	}
}

func TestRedaction(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.log")
	l, c, err := Setup(Options{Level: "debug", File: p})
	if err != nil {
		t.Fatal(err)
	}
	l.Info("msg", slog.String("body", "top secret chat"), slog.String("peer", "abc"))
	_ = c.Close()
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "top secret") {
		t.Fatalf("message body leaked into log: %s", b)
	}
	if !strings.Contains(string(b), "peer=abc") {
		t.Fatalf("non-sensitive attribute missing: %s", b)
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "WARN": slog.LevelWarn, "error": slog.LevelError, "": slog.LevelInfo} {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q)=%v want %v", in, got, want)
		}
	}
}
