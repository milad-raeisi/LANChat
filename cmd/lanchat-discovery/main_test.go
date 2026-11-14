package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/discoverysrv"
	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

func envFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "discovery.toml")
	content := `listen = "127.0.0.1:1234"
max_peers = 100
authorized_peers_file = "authorized_peers"
allowed_cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
presence_ttl = "2m"
allow_any = false
`
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	resolve := func(args []string, env map[string]string) discoverysrv.Config {
		t.Helper()
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		cf := registerConfigFlags(fs, nil)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		cfg, err := cf.resolve(envFrom(env))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	c := resolve([]string{"--config", cfgFile}, nil)
	if c.MaxPeers != 100 || c.Listen != "127.0.0.1:1234" || c.PresenceTTL != 2*time.Minute {
		t.Fatalf("file values not applied: %+v", c)
	}
	if want := filepath.Join(dir, "authorized_peers"); c.AuthorizedPeersFile != want {
		t.Errorf("relative path resolved to %q, want %q", c.AuthorizedPeersFile, want)
	}
	if strings.Join(c.AllowedCIDRs, ",") != "10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("allowed_cidrs = %v", c.AllowedCIDRs)
	}
	if c.RateBurst != discoverysrv.DefaultRateBurst {
		t.Errorf("default not kept: rate_burst = %d", c.RateBurst)
	}

	env := map[string]string{envConfig: cfgFile, envPrefix + "MAX_PEERS": "200", envPrefix + "ALLOW_ANY": "true", envPrefix + "LOG_FILE": ""}
	c = resolve(nil, env)
	if c.MaxPeers != 200 || !c.AllowAny || c.Listen != "127.0.0.1:1234" {
		t.Fatalf("environment did not override the file: %+v", c)
	}
	c = resolve([]string{"--max-peers", "300", "--allow-any=false", "--presence-ttl", "45"}, env)
	if c.MaxPeers != 300 || c.AllowAny || c.PresenceTTL != 45*time.Second {
		t.Fatalf("flags did not override the environment: %+v", c)
	}
}

func TestConfigFileErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte("listen = \":1\"\nunknown_key = 1\nmax_peers = \"many\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := run([]string{"serve", "--config", bad}, io.Discard, &stderr, envFrom(nil))
	if code != exitUsage || !strings.Contains(stderr.String(), `unknown key "unknown_key"`) || !strings.Contains(stderr.String(), "max_peers") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	code = run([]string{"serve", "--identity-file", filepath.Join(dir, "id.key")}, io.Discard, &stderr, envFrom(nil))
	if code != exitUsage || !strings.Contains(stderr.String(), "authorization") {
		t.Fatalf("missing policy: exit %d, stderr %q", code, stderr.String())
	}
	if code := run([]string{"nonsense"}, io.Discard, io.Discard, envFrom(nil)); code != exitUsage {
		t.Fatalf("unknown command: exit %d", code)
	}
}

func TestFingerprintCommand(t *testing.T) {
	idFile := filepath.Join(t.TempDir(), "identity.key")
	var out, errOut bytes.Buffer
	if code := run([]string{"fingerprint", "--identity-file", idFile}, &out, &errOut, envFrom(nil)); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "created a new server identity") {
		t.Errorf("creation not reported: %q", errOut.String())
	}
	srv, err := discoverysrv.New(discoverysrv.Config{IdentityFile: idFile, AllowAny: true}, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	fp := srv.Fingerprint()
	text := out.String()
	for _, want := range []string{
		"\n  " + fp + "\n",
		"\n  " + identity.FormatFingerprint(fp) + "\n",
		`managed_server_fingerprint = "` + fp + `"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	out.Reset()
	if code := run([]string{"fingerprint", "--quiet"}, &out, io.Discard, envFrom(map[string]string{envPrefix + "IDENTITY_FILE": idFile})); code != exitOK {
		t.Fatalf("quiet: exit %d", code)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}\n$`).MatchString(out.String()) || strings.TrimSpace(out.String()) != fp {
		t.Fatalf("quiet output %q, want %s", out.String(), fp)
	}
}

func TestHealthcheckCommand(t *testing.T) {
	srv, err := discoverysrv.New(discoverysrv.Config{
		Listen: "127.0.0.1:0", IdentityFile: filepath.Join(t.TempDir(), "id.key"), AllowAny: true,
	}, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	var out bytes.Buffer
	if code := run([]string{"healthcheck", "--addr", addr}, &out, io.Discard, envFrom(nil)); code != exitOK || !strings.HasPrefix(out.String(), "ok") {
		t.Fatalf("healthy server: exit %d, output %q", code, out.String())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if code := run([]string{"healthcheck", "--addr", addr, "--timeout", "2s"}, io.Discard, io.Discard, envFrom(nil)); code != exitFailure {
		t.Fatalf("stopped server: exit %d, want %d", code, exitFailure)
	}
}

func TestDefaultHealthAddr(t *testing.T) {
	for listen, want := range map[string]string{
		"":               "127.0.0.1:47780",
		":47780":         "127.0.0.1:47780",
		"0.0.0.0:9000":   "127.0.0.1:9000",
		"[::]:9001":      "127.0.0.1:9001",
		"10.1.2.3:47780": "10.1.2.3:47780",
	} {
		env := map[string]string{}
		if listen != "" {
			env[envPrefix+"LISTEN"] = listen
		}
		if got := defaultHealthAddr(envFrom(env)); got != want {
			t.Errorf("listen %q: got %q, want %q", listen, got, want)
		}
	}
}
