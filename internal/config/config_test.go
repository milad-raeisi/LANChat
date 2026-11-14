package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() Config {
	c := Default()
	c.User.DisplayName = "Milad"
	c.User.DeviceName = "Milad-MacBook"
	return c
}

func TestDefaultIsValidOnceNamed(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
	empty := Default()
	if err := empty.Validate(); err == nil {
		t.Fatal("default without a display name must not validate")
	}
}

func TestValidationProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"port", func(c *Config) { c.Network.Port = 80 }, "network.port"},
		{"tls", func(c *Config) { c.Security.TLSEnabled = false }, "tls_enabled"},
		{"approval", func(c *Config) { c.Security.RequirePeerApproval = false }, "require_peer_approval"},
		{"mode", func(c *Config) { c.Network.Mode = "cloud" }, "network.mode"},
		{"managed needs server", func(c *Config) { c.Network.Mode = ModeManaged }, "requires discovery.managed_server"},
		{"managed needs pin", func(c *Config) { c.Discovery.ManagedServer = "10.0.0.1:47780" }, "managed_server_fingerprint"},
		{"bad static", func(c *Config) { c.Discovery.StaticPeers = []string{"nohost"} }, "static_peers[0]"},
		{"message size", func(c *Config) { c.Chat.MaxMessageBytes = MaxMessageBytesLimit + 1 }, "max_message_bytes"},
		{"theme", func(c *Config) { c.UI.Theme = "neon" }, "ui.theme"},
		{"no families", func(c *Config) { c.Network.EnableIPv4 = false; c.Network.EnableIPv6 = false }, "enable_ipv4"},
		{"control char name", func(c *Config) { c.User.DisplayName = "Mal\x1b[2Jlory" }, "display_name"},
		{"bidi name", func(c *Config) { c.User.DisplayName = "abc\u202edef" }, "display_name"},
		{"long name", func(c *Config) { c.User.DisplayName = strings.Repeat("x", 33) }, "at most 32"},
		{"no discovery", func(c *Config) { c.Discovery.MDNSEnabled = false }, "all discovery methods are disabled"},
		{"empty key", func(c *Config) { c.Keys.Send = nil }, "keys.send"},
		{"log level", func(c *Config) { c.Logging.Level = "verbose" }, "logging.level"},
		{"listen family", func(c *Config) { c.Network.ListenAddress = "10.0.0.2"; c.Network.EnableIPv4 = false }, "listen_address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(&c)
			err := c.Validate()
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("expected ValidationError, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	c := validConfig()
	c.Network.Port = 50000
	c.Discovery.StaticPeers = []string{"192.168.1.20:47777", "[fe80::1%en0]:47777"}
	c.UI.Theme = "light"
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, res, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.UnknownKeys) != 0 {
		t.Fatalf("unexpected unknown keys %v", res.UnknownKeys)
	}
	if got.Network.Port != 50000 || got.UI.Theme != "light" || len(got.Discovery.StaticPeers) != 2 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseKeepsDefaultsAndReportsUnknownKeys(t *testing.T) {
	c, res, err := Parse([]byte(`
[user]
display_name = "Maryam"
device_name = "Maryam-PC"
[network]
port = 48000
[mystery]
x = 1
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Network.Port != 48000 || c.Network.HeartbeatIntervalSeconds != 15 || !c.Discovery.MDNSEnabled {
		t.Fatalf("defaults not preserved: %+v", c.Network)
	}
	if len(res.UnknownKeys) != 1 || res.UnknownKeys[0] != "mystery.x" {
		t.Fatalf("unknown keys = %v", res.UnknownKeys)
	}
}

func TestLoadMissing(t *testing.T) {
	_, _, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	if _, _, err := Parse([]byte("[user\nname=")); err == nil {
		t.Fatal("expected parse error")
	}
}
