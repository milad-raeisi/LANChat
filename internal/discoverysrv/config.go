// Package discoverysrv implements lanchat-discovery, the optional managed
// discovery server for networks where mDNS cannot cross segment or VLAN
// boundaries.
//
// The server only coordinates discovery and presence: authorized LANChat
// instances announce themselves over mutually authenticated HTTPS and receive
// the list of other online authorized instances with their candidate
// addresses. It never carries, stores or relays chat content, files or any
// other peer-to-peer traffic; peers still connect to each other directly.
// The directory lives in memory only and is lost on restart, after which
// clients re-register on their next refresh.
package discoverysrv

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// Defaults.
const (
	DefaultPort        = 47780
	DefaultListen      = ":47780"
	DefaultPresenceTTL = 90 * time.Second
	DefaultMaxPeers    = 10000
	DefaultRateLimit   = 5.0 // sustained requests per second per source address
	DefaultRateBurst   = 20
)

// Bounds enforced by Validate.
const (
	MinPresenceTTL = time.Second
	MaxPresenceTTL = 24 * time.Hour
	MaxMaxPeers    = 1_000_000
)

// Config configures a Server. The zero value of each field selects its
// default, except that an authorization policy (AuthorizedPeersFile or
// AllowAny) and a certificate source (IdentityFile or TLSCertFile and
// TLSKeyFile) must be given explicitly.
type Config struct {
	// Listen is the TCP address to listen on (default ":47780").
	Listen string

	// TLSCertFile and TLSKeyFile are an optional PEM certificate and key,
	// for example issued by an internal CA so that clients can use
	// managed_ca_file instead of fingerprint pinning. Both or neither must
	// be set. When unset, the server uses the persistent Ed25519 identity
	// stored at IdentityFile (created on first use).
	TLSCertFile string
	TLSKeyFile  string
	// IdentityFile is the server identity key used when no TLS certificate
	// files are configured.
	IdentityFile string

	// AuthorizedPeersFile lists the LANChat peer IDs allowed to use the
	// server, one per line; '#' starts a comment and blank lines are
	// ignored. It is re-read when its modification time or size changes.
	AuthorizedPeersFile string
	// AllowAny accepts every valid LANChat identity. It is an explicit
	// opt-in; when set, AuthorizedPeersFile is ignored.
	AllowAny bool
	// AllowedCIDRs optionally restricts the source addresses that may use
	// the /v1 API (CIDR prefixes or single addresses). Empty means any.
	AllowedCIDRs []string

	// PresenceTTL is how long an announcement stays valid without a
	// refresh (default 90s). Clients refresh every 30s by default.
	PresenceTTL time.Duration
	// MaxPeers caps the number of registered peers (default 10000). New
	// registrations beyond it are refused with HTTP 503.
	MaxPeers int

	// RateLimit is the sustained number of requests per second allowed from
	// one source address (IPv6: one /64), and RateBurst the bucket size.
	RateLimit float64
	RateBurst int

	// LogLevel (debug, info, warn, error) and LogFile configure OpenLogger.
	// An empty LogFile logs to the provided writer (normally stderr).
	LogLevel string
	LogFile  string
}

// WithDefaults returns a copy of c with defaults applied to zero fields.
func (c Config) WithDefaults() Config {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.PresenceTTL == 0 {
		c.PresenceTTL = DefaultPresenceTTL
	}
	if c.MaxPeers == 0 {
		c.MaxPeers = DefaultMaxPeers
	}
	if c.RateLimit == 0 {
		c.RateLimit = DefaultRateLimit
	}
	if c.RateBurst == 0 {
		c.RateBurst = DefaultRateBurst
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return c
}

// Validate checks a configuration (after WithDefaults) and returns every
// problem found.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if _, port, err := net.SplitHostPort(c.Listen); err != nil || port == "" {
		add("listen: %q must be in host:port or :port form", c.Listen)
	}
	switch {
	case (c.TLSCertFile == "") != (c.TLSKeyFile == ""):
		add("tls_cert_file and tls_key_file must be set together")
	case c.TLSCertFile == "" && c.IdentityFile == "":
		add("identity_file is required when no tls_cert_file/tls_key_file are configured")
	}
	if !c.AllowAny && c.AuthorizedPeersFile == "" {
		add("no authorization policy: set authorized_peers_file (recommended) or allow_any = true to accept any LANChat identity")
	}
	if _, err := parseCIDRs(c.AllowedCIDRs); err != nil {
		add("allowed_cidrs: %v", err)
	}
	if c.PresenceTTL < MinPresenceTTL || c.PresenceTTL > MaxPresenceTTL {
		add("presence_ttl: must be between %s and %s (got %s)", MinPresenceTTL, MaxPresenceTTL, c.PresenceTTL)
	}
	if c.MaxPeers < 1 || c.MaxPeers > MaxMaxPeers {
		add("max_peers: must be between 1 and %d (got %d)", MaxMaxPeers, c.MaxPeers)
	}
	if c.RateLimit <= 0 {
		add("rate_limit: must be greater than zero (got %v)", c.RateLimit)
	}
	if c.RateBurst < 1 {
		add("rate_burst: must be at least 1 (got %d)", c.RateBurst)
	}
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "debug", "info", "warn", "warning", "error":
	default:
		add("log_level: must be debug, info, warn or error (got %q)", c.LogLevel)
	}
	return errors.Join(errs...)
}

// parseCIDRs parses prefixes or bare addresses into masked prefixes.
func parseCIDRs(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid CIDR prefix", s)
			}
			if p.Addr().Is4In6() {
				return nil, fmt.Errorf("%q: use the plain IPv4 form", s)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("%q is not a valid address or CIDR prefix", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// ServerCertificate is the certificate the server presents.
type ServerCertificate struct {
	Cert tls.Certificate
	// Fingerprint is the lowercase hex SHA-256 of the certificate's
	// SubjectPublicKeyInfo, as pinned by clients in
	// managed_server_fingerprint.
	Fingerprint string
	// Source describes where the certificate came from, for messages.
	Source string
	// Created reports that a new identity key was generated and saved.
	Created bool
}

// LoadServerCertificate loads the configured TLS certificate files, or
// loads (creating on first use) the persistent server identity.
func LoadServerCertificate(c Config) (*ServerCertificate, error) {
	if c.TLSCertFile != "" || c.TLSKeyFile != "" {
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return nil, errors.New("tls_cert_file and tls_key_file must be set together")
		}
		cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse TLS certificate %s: %w", c.TLSCertFile, err)
		}
		cert.Leaf = leaf
		return &ServerCertificate{
			Cert:        cert,
			Fingerprint: identity.FingerprintSPKI(leaf.RawSubjectPublicKeyInfo),
			Source:      c.TLSCertFile,
		}, nil
	}
	if c.IdentityFile == "" {
		return nil, errors.New("identity_file is required when no TLS certificate files are configured")
	}
	if err := platform.EnsurePrivateDir(filepath.Dir(c.IdentityFile)); err != nil {
		return nil, err
	}
	id, created, err := identity.LoadOrCreate(c.IdentityFile)
	if err != nil {
		return nil, fmt.Errorf("server identity %s: %w", c.IdentityFile, err)
	}
	cert, err := id.Certificate()
	if err != nil {
		return nil, fmt.Errorf("server identity certificate: %w", err)
	}
	return &ServerCertificate{
		Cert:        cert,
		Fingerprint: identity.FingerprintSPKI(cert.Leaf.RawSubjectPublicKeyInfo),
		Source:      c.IdentityFile,
		Created:     created,
	}, nil
}

// OpenLogger builds the server logger: a size-rotated file when LogFile is
// set, otherwise text on stderr. Sensitive attribute keys are redacted.
func (c Config) OpenLogger(stderr io.Writer) (*slog.Logger, io.Closer, error) {
	if c.LogFile != "" {
		return logging.Setup(logging.Options{Level: c.LogLevel, File: c.LogFile})
	}
	h := slog.NewTextHandler(stderr, &slog.HandlerOptions{
		Level:       logging.ParseLevel(c.LogLevel),
		ReplaceAttr: logging.Redact,
	})
	return slog.New(h), nopCloser{}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// checkKeyFilePerms warns about a private key readable by other users.
func checkKeyFilePerms(path string, log *slog.Logger) {
	if path == "" {
		return
	}
	if err := platform.CheckPrivateFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Warn("server key file is readable by other users", "err", err)
	}
}
