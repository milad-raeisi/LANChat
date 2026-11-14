// Package e2e_test builds the real lanchat binary and exercises its
// non-interactive command line against an isolated LANCHAT_HOME.
package e2e_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lanchat-e2e-*")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "lanchat")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "../../cmd/lanchat")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic("build lanchat: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type result struct {
	out, err string
	code     int
}

func lanchat(t *testing.T, home, stdin string, args ...string) result {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "LANCHAT_HOME="+home)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{out.String(), errb.String(), code}
}

func writeConfig(t *testing.T, home, extra string) {
	t.Helper()
	cfg := "[user]\ndisplay_name = \"Milad\"\ndevice_name = \"Milad-MacBook\"\n[network]\nport = 0\n" + extra
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVersionHelpAndUsage(t *testing.T) {
	home := t.TempDir()
	r := lanchat(t, home, "", "--version")
	if r.code != 0 || !strings.Contains(r.out, "LANChat") || !strings.Contains(r.out, "protocol v1") {
		t.Fatalf("--version: %+v", r)
	}
	r = lanchat(t, home, "", "--help")
	if r.code != 0 || !strings.Contains(r.out, "doctor [--verbose]") {
		t.Fatalf("--help: %+v", r)
	}
	if r := lanchat(t, home, "", "frobnicate"); r.code != 2 {
		t.Fatalf("unknown command exit = %d", r.code)
	}
	if r := lanchat(t, home, "", "--no-such-flag"); r.code != 2 {
		t.Fatalf("bad flag exit = %d", r.code)
	}
}

func TestInteractiveModeNeedsTerminal(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, home, "")
	r := lanchat(t, home, "")
	if r.code != 5 || !strings.Contains(r.err, "interactive terminal") {
		t.Fatalf("expected exit 5 without a TTY, got %+v", r)
	}
}

func TestConfigCommands(t *testing.T) {
	home := t.TempDir()
	if r := lanchat(t, home, "", "config", "validate"); r.code != 3 {
		t.Fatalf("missing config should exit 3: %+v", r)
	}
	writeConfig(t, home, "")
	r := lanchat(t, home, "", "config", "validate")
	if r.code != 0 || !strings.Contains(r.out, "valid") {
		t.Fatalf("validate: %+v", r)
	}
	r = lanchat(t, home, "", "config", "show")
	if r.code != 0 || !strings.Contains(r.out, `display_name = "Milad"`) || !strings.Contains(r.out, "heartbeat_interval_seconds = 15") {
		t.Fatalf("show: %+v", r)
	}
	if r := lanchat(t, home, "", "config", "path"); strings.TrimSpace(r.out) != filepath.Join(home, "config.toml") {
		t.Fatalf("path: %q", r.out)
	}
	writeConfig(t, home, "[security]\ntls_enabled = false\n[mystery]\nkey = 1\n")
	r = lanchat(t, home, "", "config", "validate")
	if r.code != 3 || !strings.Contains(r.err, "cannot be disabled") || !strings.Contains(r.err, "mystery.key") {
		t.Fatalf("invalid config: %+v", r)
	}
}

func TestIdentityLifecycle(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, home, "")
	if r := lanchat(t, home, "", "identity", "show"); r.code != 1 || !strings.Contains(r.err, "no identity") {
		t.Fatalf("identity before creation: %+v", r)
	}
	// Reset without confirmation is refused.
	r := lanchat(t, home, "no\n", "identity", "reset")
	if r.code != 0 || !strings.Contains(r.out, "Cancelled") {
		t.Fatalf("unconfirmed reset: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(home, "data", "identity.key")); err == nil {
		t.Fatal("identity created without confirmation")
	}
	r = lanchat(t, home, "reset\n", "identity", "reset")
	if r.code != 0 || !strings.Contains(r.out, "must verify and pair again") || !strings.Contains(r.out, "New identity created") {
		t.Fatalf("confirmed reset: %+v", r)
	}
	fp1 := strings.TrimSpace(lanchat(t, home, "", "identity", "fingerprint").out)
	if !regexp.MustCompile(`^([0-9a-f]{4} ){15}[0-9a-f]{4}$`).MatchString(fp1) {
		t.Fatalf("fingerprint format %q", fp1)
	}
	show := lanchat(t, home, "", "identity", "show")
	if show.code != 0 || !strings.Contains(show.out, "Ed25519") || strings.Contains(strings.ToLower(show.out), "private key:") {
		t.Fatalf("identity show: %+v", show)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(home, "data", "identity.key"))
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("identity key permissions %v", st.Mode().Perm())
		}
	}
	lanchat(t, home, "", "identity", "reset", "--yes")
	fp2 := strings.TrimSpace(lanchat(t, home, "", "identity", "fingerprint").out)
	if fp1 == fp2 {
		t.Fatal("reset did not change the identity")
	}
}

func TestDataAndPeersCommands(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, home, "")
	r := lanchat(t, home, "", "peers", "list")
	if r.code != 0 || !strings.Contains(r.out, "No peers yet") {
		t.Fatalf("peers list: %+v", r)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if r := lanchat(t, home, "", "data", "backup", backup); r.code != 0 {
		t.Fatalf("backup: %+v", r)
	}
	if st, err := os.Stat(backup); err != nil || st.Size() == 0 {
		t.Fatal("backup file missing")
	}
	if r := lanchat(t, home, "", "data", "backup", backup); r.code == 0 {
		t.Fatal("backup overwrote an existing file")
	}
	export := filepath.Join(t.TempDir(), "export.json")
	if r := lanchat(t, home, "", "data", "export", export, "--format", "json"); r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
	var arr []any
	b, _ := os.ReadFile(export)
	if err := json.Unmarshal(b, &arr); err != nil {
		t.Fatalf("export is not valid JSON: %v\n%s", err, b)
	}
	if r := lanchat(t, home, "nope\n", "data", "purge"); !strings.Contains(r.out, "Cancelled") {
		t.Fatalf("unconfirmed purge: %+v", r)
	}
	if r := lanchat(t, home, "", "data", "purge", "--yes"); r.code != 0 || !strings.Contains(r.out, "Deleted") {
		t.Fatalf("purge: %+v", r)
	}
	if r := lanchat(t, home, "", "peers", "revoke", "nobody"); r.code != 2 {
		t.Fatalf("revoke unknown: %+v", r)
	}
}

func TestNetworkAndDoctor(t *testing.T) {
	home := t.TempDir()
	writeConfig(t, home, "")
	lanchat(t, home, "", "identity", "reset", "--yes")
	r := lanchat(t, home, "", "network", "interfaces")
	if r.code != 0 || !strings.Contains(r.out, "INTERFACE") {
		t.Fatalf("interfaces: %+v", r)
	}
	r = lanchat(t, home, "", "network", "status")
	if r.code != 0 || !strings.Contains(r.out, "not running") {
		t.Fatalf("network status: %+v", r)
	}
	// Doctor may legitimately report failures in sandboxed CI (no LAN, no
	// multicast); it must still produce a structured report.
	r = lanchat(t, home, "", "doctor", "--timeout", "1s")
	if r.code != 0 && r.code != 1 {
		t.Fatalf("doctor exit %d: %s", r.code, r.err)
	}
	for _, want := range []string{"[PASS] Configuration valid", "[PASS] Local identity loaded", "Firewall notes:"} {
		if !strings.Contains(r.out, want) {
			t.Fatalf("doctor output lacks %q:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "PRIVATE KEY") {
		t.Fatal("doctor leaked key material")
	}
}
