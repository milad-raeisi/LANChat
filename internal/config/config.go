// Package config defines, loads, validates and saves the LANChat TOML
// configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/milad-raeisi/LANChat/internal/platform"
)

// CurrentVersion is the configuration schema version written by this build.
const CurrentVersion = 1

// Hard limits that configuration cannot exceed.
const (
	MaxMessageBytesLimit = 64 * 1024
	DefaultPort          = 47777
	MaxDisplayNameRunes  = 32
	MaxDeviceNameRunes   = 64
)

// Network modes.
const (
	ModeAuto    = "auto"
	ModeManaged = "managed"
)

// Themes supported by the TUI.
var Themes = []string{"dark", "light", "minimal", "monochrome"}

// Config is the complete LANChat configuration.
type Config struct {
	ConfigVersion int                `toml:"config_version"`
	User          UserConfig         `toml:"user"`
	Network       NetworkConfig      `toml:"network"`
	Discovery     DiscoveryConfig    `toml:"discovery"`
	Security      SecurityConfig     `toml:"security"`
	Chat          ChatConfig         `toml:"chat"`
	Transfer      TransferConfig     `toml:"transfer"`
	Notifications NotificationConfig `toml:"notifications"`
	UI            UIConfig           `toml:"ui"`
	Keys          KeyConfig          `toml:"keys"`
	Storage       StorageConfig      `toml:"storage"`
	Logging       LoggingConfig      `toml:"logging"`
}

// UserConfig describes the local user as presented to peers.
type UserConfig struct {
	DisplayName string `toml:"display_name"`
	DeviceName  string `toml:"device_name"`
}

// NetworkConfig controls the TCP listener and connection behaviour.
type NetworkConfig struct {
	Mode                     string `toml:"mode"`
	Interface                string `toml:"interface"`
	ListenAddress            string `toml:"listen_address"`
	Port                     int    `toml:"port"`
	EnableIPv4               bool   `toml:"enable_ipv4"`
	EnableIPv6               bool   `toml:"enable_ipv6"`
	ConnectionTimeoutSeconds int    `toml:"connection_timeout_seconds"`
	HeartbeatIntervalSeconds int    `toml:"heartbeat_interval_seconds"`
	MaxConnections           int    `toml:"max_connections"`
}

// DiscoveryConfig controls how peers are found.
type DiscoveryConfig struct {
	MDNSEnabled              bool     `toml:"mdns_enabled"`
	RefreshIntervalSeconds   int      `toml:"refresh_interval_seconds"`
	ManagedServer            string   `toml:"managed_server"`
	ManagedServerFingerprint string   `toml:"managed_server_fingerprint"`
	ManagedCAFile            string   `toml:"managed_ca_file"`
	StaticPeers              []string `toml:"static_peers"`
}

// SecurityConfig documents security settings. Transport encryption and peer
// approval are mandatory; the fields exist so that an explicit attempt to
// disable them is rejected with a clear error instead of being ignored.
type SecurityConfig struct {
	TLSEnabled           bool `toml:"tls_enabled"`
	RequirePeerApproval  bool `toml:"require_peer_approval"`
	AllowPairingRequests bool `toml:"allow_pairing_requests"`
	MaxUntrustedSessions int  `toml:"max_untrusted_sessions"`
}

// ChatConfig controls messaging behaviour.
type ChatConfig struct {
	SaveHistory          bool `toml:"save_history"`
	MaxMessageBytes      int  `toml:"max_message_bytes"`
	QueueOfflineMessages bool `toml:"queue_offline_messages"`
	OfflineQueueTTLHours int  `toml:"offline_queue_ttl_hours"`
	MaxQueuedPerPeer     int  `toml:"max_queued_per_peer"`
	MaxRetryAttempts     int  `toml:"max_retry_attempts"`
}

// TransferConfig controls file transfers.
type TransferConfig struct {
	DownloadDir   string `toml:"download_dir"`
	MaxFileSizeMB int64  `toml:"max_file_size_mb"`
}

// NotificationConfig controls terminal-native notifications.
type NotificationConfig struct {
	Enabled    bool `toml:"enabled"`
	Bell       bool `toml:"bell"`
	PeerEvents bool `toml:"peer_events"`
}

// UIConfig controls appearance.
type UIConfig struct {
	Theme      string `toml:"theme"`
	TimeFormat string `toml:"time_format"`
	Mouse      bool   `toml:"mouse"`
}

// KeyConfig maps actions to key strings as reported by Bubble Tea
// (for example "ctrl+p", "shift+enter", "alt+enter").
type KeyConfig struct {
	Send           []string `toml:"send"`
	Newline        []string `toml:"newline"`
	CommandPalette []string `toml:"command_palette"`
	Search         []string `toml:"search"`
	Conversations  []string `toml:"conversations"`
	Refresh        []string `toml:"refresh"`
	NextPanel      []string `toml:"next_panel"`
	PrevPanel      []string `toml:"prev_panel"`
	Help           []string `toml:"help"`
	Quit           []string `toml:"quit"`
}

// StorageConfig controls persistence.
type StorageConfig struct {
	Database string `toml:"database"`
}

// LoggingConfig controls the log file.
type LoggingConfig struct {
	Level     string `toml:"level"`
	File      string `toml:"file"`
	MaxSizeMB int    `toml:"max_size_mb"`
	MaxFiles  int    `toml:"max_files"`
}

// Default returns a configuration with every default applied. The user and
// device names are left empty for the setup wizard to fill in.
func Default() Config {
	return Config{
		ConfigVersion: CurrentVersion,
		Network: NetworkConfig{
			Mode:                     ModeAuto,
			Interface:                "auto",
			Port:                     DefaultPort,
			EnableIPv4:               true,
			EnableIPv6:               true,
			ConnectionTimeoutSeconds: 10,
			HeartbeatIntervalSeconds: 15,
			MaxConnections:           64,
		},
		Discovery: DiscoveryConfig{
			MDNSEnabled:            true,
			RefreshIntervalSeconds: 30,
		},
		Security: SecurityConfig{
			TLSEnabled:           true,
			RequirePeerApproval:  true,
			AllowPairingRequests: true,
			MaxUntrustedSessions: 16,
		},
		Chat: ChatConfig{
			SaveHistory:          true,
			MaxMessageBytes:      16 * 1024,
			QueueOfflineMessages: true,
			OfflineQueueTTLHours: 168,
			MaxQueuedPerPeer:     500,
			MaxRetryAttempts:     20,
		},
		Transfer: TransferConfig{
			MaxFileSizeMB: 4096,
		},
		Notifications: NotificationConfig{
			Enabled:    true,
			Bell:       false,
			PeerEvents: true,
		},
		UI: UIConfig{
			Theme:      "dark",
			TimeFormat: "24h",
		},
		Keys: DefaultKeys(),
		Logging: LoggingConfig{
			Level:     "info",
			MaxSizeMB: 5,
			MaxFiles:  3,
		},
	}
}

// DefaultKeys returns the default key bindings.
func DefaultKeys() KeyConfig {
	return KeyConfig{
		Send:           []string{"enter"},
		Newline:        []string{"shift+enter", "alt+enter", "ctrl+j"},
		CommandPalette: []string{"ctrl+p"},
		Search:         []string{"ctrl+f"},
		Conversations:  []string{"ctrl+l"},
		Refresh:        []string{"ctrl+r"},
		NextPanel:      []string{"tab"},
		PrevPanel:      []string{"shift+tab"},
		Help:           []string{"f1"},
		Quit:           []string{"ctrl+c"},
	}
}

// ErrNotFound is returned by Load when the configuration file does not exist.
var ErrNotFound = errors.New("configuration file not found")

// LoadResult carries non-fatal information gathered while loading.
type LoadResult struct {
	// UnknownKeys lists keys present in the file that LANChat does not use.
	UnknownKeys []string
}

// Load reads path, applying defaults for missing keys. It does not validate;
// call Validate on the result.
func Load(path string) (Config, LoadResult, error) {
	var res LoadResult
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, res, ErrNotFound
	}
	if err != nil {
		return Config{}, res, fmt.Errorf("read %s: %w", path, err)
	}
	cfg, res, err := Parse(data)
	if err != nil {
		return Config{}, res, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, res, nil
}

// Parse decodes TOML data on top of the defaults. Keys absent from the file
// keep their default values; arrays present in the file replace the default.
func Parse(data []byte) (Config, LoadResult, error) {
	var res LoadResult
	cfg := Default()
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&cfg)
	if err != nil {
		return Config{}, res, err
	}
	undecoded := md.Undecoded()
	for i, k := range undecoded {
		// Report only the most specific keys: an unknown table "x" with key
		// "x.y" is reported once, as "x.y".
		name := k.String()
		parent := false
		for j, other := range undecoded {
			if i != j && strings.HasPrefix(other.String(), name+".") {
				parent = true
				break
			}
		}
		if !parent {
			res.UnknownKeys = append(res.UnknownKeys, name)
		}
	}
	return cfg, res, nil
}

// Save writes cfg to path atomically with owner-only permissions.
func Save(path string, cfg Config) error {
	var buf bytes.Buffer
	buf.WriteString("# LANChat configuration file.\n")
	buf.WriteString("# Reference: docs/configuration.md\n")
	buf.WriteString("# Edit with `lanchat config edit` and check with `lanchat config validate`.\n\n")
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	return platform.WriteFileAtomic(path, buf.Bytes(), 0o600)
}

// Encode returns the TOML representation of cfg.
func Encode(cfg Config) (string, error) {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	err := enc.Encode(cfg)
	return buf.String(), err
}

// ValidationError aggregates every problem found in a configuration.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid configuration: " + e.Problems[0]
	}
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks cfg and returns a *ValidationError listing every problem.
func (c *Config) Validate() error {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if c.ConfigVersion > CurrentVersion {
		add("config_version: %d was written by a newer LANChat; this build understands version %d", c.ConfigVersion, CurrentVersion)
	}
	if err := ValidateDisplayName(c.User.DisplayName); err != nil {
		add("user.display_name: %v", err)
	}
	if err := ValidateDeviceName(c.User.DeviceName); err != nil {
		add("user.device_name: %v", err)
	}

	n := c.Network
	switch n.Mode {
	case ModeAuto, ModeManaged:
	default:
		add("network.mode: must be %q or %q (got %q)", ModeAuto, ModeManaged, n.Mode)
	}
	if n.Interface == "" {
		add(`network.interface: must be "auto" or an interface name`)
	}
	if n.ListenAddress != "" {
		ip := net.ParseIP(n.ListenAddress)
		if ip == nil {
			add("network.listen_address: %q is not an IP address", n.ListenAddress)
		} else if ip.To4() != nil && !n.EnableIPv4 {
			add("network.listen_address: IPv4 address given but network.enable_ipv4 is false")
		} else if ip.To4() == nil && !n.EnableIPv6 {
			add("network.listen_address: IPv6 address given but network.enable_ipv6 is false")
		}
	}
	if n.Port != 0 && (n.Port < 1024 || n.Port > 65535) {
		add("network.port: must be between 1024 and 65535, or 0 for a random port (got %d)", n.Port)
	}
	if !n.EnableIPv4 && !n.EnableIPv6 {
		add("network: at least one of enable_ipv4 or enable_ipv6 must be true")
	}
	if n.ConnectionTimeoutSeconds < 1 || n.ConnectionTimeoutSeconds > 120 {
		add("network.connection_timeout_seconds: must be between 1 and 120 (got %d)", n.ConnectionTimeoutSeconds)
	}
	if n.HeartbeatIntervalSeconds < 2 || n.HeartbeatIntervalSeconds > 300 {
		add("network.heartbeat_interval_seconds: must be between 2 and 300 (got %d)", n.HeartbeatIntervalSeconds)
	}
	if n.MaxConnections < 2 || n.MaxConnections > 1024 {
		add("network.max_connections: must be between 2 and 1024 (got %d)", n.MaxConnections)
	}

	d := c.Discovery
	if d.RefreshIntervalSeconds < 5 || d.RefreshIntervalSeconds > 3600 {
		add("discovery.refresh_interval_seconds: must be between 5 and 3600 (got %d)", d.RefreshIntervalSeconds)
	}
	if d.ManagedServer != "" {
		if err := validateHostPort(d.ManagedServer); err != nil {
			add("discovery.managed_server: %v", err)
		}
		if d.ManagedServerFingerprint == "" && d.ManagedCAFile == "" {
			add("discovery.managed_server: set managed_server_fingerprint (recommended) or managed_ca_file so the server can be authenticated")
		}
	}
	if d.ManagedServerFingerprint != "" && !validFingerprintFormat(d.ManagedServerFingerprint) {
		add("discovery.managed_server_fingerprint: expected the 64-hex-digit SHA-256 fingerprint printed by `lanchat-discovery fingerprint`")
	}
	if d.ManagedCAFile != "" {
		if _, err := os.Stat(d.ManagedCAFile); err != nil {
			add("discovery.managed_ca_file: %v", err)
		}
	}
	if n.Mode == ModeManaged && d.ManagedServer == "" {
		add("network.mode: \"managed\" requires discovery.managed_server")
	}
	if len(d.StaticPeers) > 256 {
		add("discovery.static_peers: at most 256 entries are allowed")
	}
	for i, sp := range d.StaticPeers {
		if err := validateHostPort(sp); err != nil {
			add("discovery.static_peers[%d]: %v", i, err)
		}
	}
	if !d.MDNSEnabled && d.ManagedServer == "" && len(d.StaticPeers) == 0 {
		add("discovery: all discovery methods are disabled; enable mdns_enabled, set managed_server or list static_peers")
	}

	s := c.Security
	if !s.TLSEnabled {
		add("security.tls_enabled: transport encryption is mandatory in LANChat and cannot be disabled")
	}
	if !s.RequirePeerApproval {
		add("security.require_peer_approval: explicit peer approval is mandatory and cannot be disabled")
	}
	if s.MaxUntrustedSessions < 1 || s.MaxUntrustedSessions > 256 {
		add("security.max_untrusted_sessions: must be between 1 and 256 (got %d)", s.MaxUntrustedSessions)
	}

	ch := c.Chat
	if ch.MaxMessageBytes < 1 || ch.MaxMessageBytes > MaxMessageBytesLimit {
		add("chat.max_message_bytes: must be between 1 and %d (got %d)", MaxMessageBytesLimit, ch.MaxMessageBytes)
	}
	if ch.OfflineQueueTTLHours < 1 || ch.OfflineQueueTTLHours > 24*365 {
		add("chat.offline_queue_ttl_hours: must be between 1 and 8760 (got %d)", ch.OfflineQueueTTLHours)
	}
	if ch.MaxQueuedPerPeer < 1 || ch.MaxQueuedPerPeer > 100000 {
		add("chat.max_queued_per_peer: must be between 1 and 100000 (got %d)", ch.MaxQueuedPerPeer)
	}
	if ch.MaxRetryAttempts < 1 || ch.MaxRetryAttempts > 1000 {
		add("chat.max_retry_attempts: must be between 1 and 1000 (got %d)", ch.MaxRetryAttempts)
	}

	if c.Transfer.MaxFileSizeMB < 1 || c.Transfer.MaxFileSizeMB > 1024*1024 {
		add("transfer.max_file_size_mb: must be between 1 and 1048576 (got %d)", c.Transfer.MaxFileSizeMB)
	}

	if !contains(Themes, c.UI.Theme) {
		add("ui.theme: must be one of %s (got %q)", strings.Join(Themes, ", "), c.UI.Theme)
	}
	if c.UI.TimeFormat != "24h" && c.UI.TimeFormat != "12h" {
		add(`ui.time_format: must be "24h" or "12h" (got %q)`, c.UI.TimeFormat)
	}

	for _, kb := range c.Keys.Named() {
		if len(kb.Keys) == 0 {
			add("keys.%s: at least one key is required", kb.Name)
		}
		for _, k := range kb.Keys {
			if strings.TrimSpace(k) == "" || len(k) > 32 {
				add("keys.%s: invalid key %q", kb.Name, k)
			}
		}
	}

	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
	default:
		add(`logging.level: must be "debug", "info", "warn" or "error" (got %q)`, c.Logging.Level)
	}
	if c.Logging.MaxSizeMB < 1 || c.Logging.MaxSizeMB > 1024 {
		add("logging.max_size_mb: must be between 1 and 1024 (got %d)", c.Logging.MaxSizeMB)
	}
	if c.Logging.MaxFiles < 1 || c.Logging.MaxFiles > 50 {
		add("logging.max_files: must be between 1 and 50 (got %d)", c.Logging.MaxFiles)
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// NamedKeys pairs a key-binding action name with its keys.
type NamedKeys struct {
	Name string
	Keys []string
}

// Named returns the bindings in a stable order.
func (k KeyConfig) Named() []NamedKeys {
	return []NamedKeys{
		{"send", k.Send}, {"newline", k.Newline}, {"command_palette", k.CommandPalette},
		{"search", k.Search}, {"conversations", k.Conversations}, {"refresh", k.Refresh},
		{"next_panel", k.NextPanel}, {"prev_panel", k.PrevPanel}, {"help", k.Help}, {"quit", k.Quit},
	}
}

// ValidateDisplayName checks a user-chosen display name.
func ValidateDisplayName(s string) error {
	return validateName(s, MaxDisplayNameRunes)
}

// ValidateDeviceName checks a device name.
func ValidateDeviceName(s string) error {
	return validateName(s, MaxDeviceNameRunes)
}

func validateName(s string, max int) error {
	if !utf8.ValidString(s) {
		return errors.New("must be valid UTF-8")
	}
	t := strings.TrimSpace(s)
	if t == "" {
		return errors.New("must not be empty")
	}
	if t != s {
		return errors.New("must not start or end with whitespace")
	}
	if n := utf8.RuneCountInString(s); n > max {
		return fmt.Errorf("must be at most %d characters (got %d)", max, n)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("must not contain control or formatting characters (found U+%04X)", r)
		}
	}
	return nil
}

func validateHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%q must be in host:port form (IPv6 as [addr]:port)", s)
	}
	if host == "" {
		return fmt.Errorf("%q is missing a host", s)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%q has an invalid port", s)
	}
	return nil
}

func validFingerprintFormat(s string) bool {
	s = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), ":", ""), " ", "")
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ConnectionTimeout returns the configured dial/handshake timeout.
func (c *Config) ConnectionTimeout() time.Duration {
	return time.Duration(c.Network.ConnectionTimeoutSeconds) * time.Second
}

// HeartbeatInterval returns the keepalive interval.
func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.Network.HeartbeatIntervalSeconds) * time.Second
}

// RefreshInterval returns the discovery refresh interval.
func (c *Config) RefreshInterval() time.Duration {
	return time.Duration(c.Discovery.RefreshIntervalSeconds) * time.Second
}

// OfflineQueueTTL returns how long undelivered messages are retried.
func (c *Config) OfflineQueueTTL() time.Duration {
	return time.Duration(c.Chat.OfflineQueueTTLHours) * time.Hour
}

// MaxFileSize returns the maximum accepted incoming file size in bytes.
func (c *Config) MaxFileSize() int64 {
	return c.Transfer.MaxFileSizeMB * 1024 * 1024
}

// DatabasePath resolves the database location.
func (c *Config) DatabasePath(d platform.Dirs) string {
	if c.Storage.Database != "" {
		return c.Storage.Database
	}
	return d.DefaultDatabase()
}

// DownloadDir resolves the download directory.
func (c *Config) DownloadDir(d platform.Dirs) string {
	if c.Transfer.DownloadDir != "" {
		return c.Transfer.DownloadDir
	}
	return platform.DefaultDownloads(d)
}
