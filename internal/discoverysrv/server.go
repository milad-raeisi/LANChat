package discoverysrv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/managedapi"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/security/tlsconf"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

// HTTP server limits.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 16 << 10
	shutdownTimeout   = 5 * time.Second

	// maxNameRunes bounds sanitized display and device names. 64 runes is at
	// most 256 bytes of UTF-8, the limit clients enforce on PeerEntry.
	maxNameRunes = 64
)

// Server is a managed discovery server.
type Server struct {
	cfg      Config
	cert     *ServerCertificate
	log      *slog.Logger
	auth     *authorizer
	dir      *directory
	limiter  *rateLimiter
	prefixes []netip.Prefix
	now      func() time.Time

	mu sync.Mutex
	ln net.Listener
}

// New validates cfg, loads (or creates) the server certificate and the
// authorized peers list, and returns a server ready to Listen.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = logging.Discard()
	}
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	prefixes, err := parseCIDRs(cfg.AllowedCIDRs)
	if err != nil {
		return nil, err
	}
	cert, err := LoadServerCertificate(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.TLSKeyFile != "" {
		checkKeyFilePerms(cfg.TLSKeyFile, log)
	} else {
		checkKeyFilePerms(cfg.IdentityFile, log)
	}
	if cert.Created {
		log.Info("generated a new server identity", "path", cert.Source, "fingerprint", cert.Fingerprint)
	}
	auth, err := newAuthorizer(cfg.AuthorizedPeersFile, cfg.AllowAny, log)
	if err != nil {
		return nil, err
	}
	if cfg.AllowAny && cfg.AuthorizedPeersFile != "" {
		log.Warn("allow_any is enabled; authorized_peers_file is ignored", "path", cfg.AuthorizedPeersFile)
	}
	if !cfg.AllowAny && auth.count() == 0 {
		log.Warn("the authorized peers file lists no peer IDs; every client will be refused until it does", "path", cfg.AuthorizedPeersFile)
	}
	return &Server{
		cfg:      cfg,
		cert:     cert,
		log:      log,
		auth:     auth,
		dir:      newDirectory(),
		limiter:  newRateLimiter(cfg.RateLimit, cfg.RateBurst),
		prefixes: prefixes,
		now:      time.Now,
	}, nil
}

// Config returns the effective configuration (with defaults applied).
func (s *Server) Config() Config { return s.cfg }

// Fingerprint returns the SPKI SHA-256 fingerprint clients pin.
func (s *Server) Fingerprint() string { return s.cert.Fingerprint }

// AuthorizedCount returns the number of peer IDs in the authorized peers
// list (0 when allow_any is enabled).
func (s *Server) AuthorizedCount() int { return s.auth.count() }

// Listen binds the configured address.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return errors.New("discovery server is already listening")
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	return nil
}

// Addr returns the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// ListenAndServe binds the configured address and serves until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Serve serves HTTPS on the bound listener until ctx is cancelled, then
// shuts down gracefully. It returns nil after a clean shutdown.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return errors.New("discovery server: Serve called before Listen")
	}
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		// An empty, non-nil map disables HTTP/2; the API is HTTP/1.1 only.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		// Handshake failures from scanners and misconfigured clients are
		// routine; keep them out of the default log level.
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}

	sweepCtx, stopSweep := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.sweepLoop(sweepCtx)
	}()
	defer func() {
		stopSweep()
		wg.Wait()
	}()

	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(tls.NewListener(ln, s.tlsConfig())) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := hs.Shutdown(shCtx); err != nil {
		s.log.Warn("graceful shutdown timed out; closing remaining connections", "err", err)
		_ = hs.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// tlsConfig requires TLS 1.3 and requests (but does not require) a client
// certificate, so that /healthz works without one while /v1 can derive
// the caller's peer ID.
//
// tls.RequestClientCert is used rather than tls.VerifyClientCertIfGiven:
// the latter verifies client chains against ClientCAs, which always fails
// for self-signed LANChat identity certificates. Identity checks are done
// by verifyOptionalClientCert instead.
func (s *Server) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{s.cert.Cert},
		ClientAuth:            tls.RequestClientCert,
		VerifyPeerCertificate: verifyOptionalClientCert,
		NextProtos:            []string{"http/1.1"},
	}
}

// verifyOptionalClientCert accepts connections without a client
// certificate and otherwise requires a valid LANChat identity certificate.
func verifyOptionalClientCert(raw [][]byte, chains [][]*x509.Certificate) error {
	if len(raw) == 0 {
		return nil
	}
	return tlsconf.VerifyPeerCertificate(raw, chains)
}

func (s *Server) sweepLoop(ctx context.Context) {
	interval := s.cfg.PresenceTTL / 3
	if interval < 250*time.Millisecond {
		interval = 250 * time.Millisecond
	}
	if interval > 15*time.Second {
		interval = 15 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *Server) sweep() {
	now := s.now()
	s.auth.maybeReload(now)
	var allowed func(identity.PeerID) bool
	if !s.cfg.AllowAny {
		allowed = s.auth.allowed
	}
	expired, revoked := s.dir.prune(now, s.cfg.PresenceTTL, allowed)
	for _, id := range expired {
		s.log.Info("peer expired", "peer_id", id)
	}
	for _, id := range revoked {
		s.log.Info("peer removed: no longer authorized", "peer_id", id)
	}
	s.limiter.sweep(now)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	src, ok := sourceAddr(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "cannot determine the source address")
		return
	}
	now := s.now()
	if !s.limiter.allow(src, now) {
		s.log.Debug("rate limited", "source", src)
		h.Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	switch r.URL.Path {
	case managedapi.PathHealth:
		s.handleHealth(w, r, src, now)
	case managedapi.PathAnnounce, managedapi.PathWithdraw:
		if r.Method != http.MethodPost {
			h.Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method not allowed; use POST")
			return
		}
		if !s.sourceAllowed(src) {
			s.log.Warn("refused request from a source outside allowed_cidrs", "source", src)
			writeError(w, http.StatusForbidden, "source address is not allowed on this discovery server")
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, http.StatusUnauthorized, "a LANChat identity client certificate is required")
			return
		}
		_, id, err := tlsconf.PeerFromState(*r.TLS)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid client certificate")
			return
		}
		if r.URL.Path == managedapi.PathAnnounce {
			s.handleAnnounce(w, r, id, src, now)
		} else {
			s.handleWithdraw(w, r, id, src)
		}
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

type healthResponse struct {
	Status string `json:"status"`
	Peers  int    `json:"peers"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, src netip.Addr, now time.Time) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed; use GET")
		return
	}
	// Local health checks always work; otherwise the same source policy as
	// the API applies.
	if !src.IsLoopback() && !s.sourceAllowed(src) {
		writeError(w, http.StatusForbidden, "source address is not allowed on this discovery server")
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", Peers: s.dir.live(now, s.cfg.PresenceTTL)})
}

func (s *Server) handleAnnounce(w http.ResponseWriter, r *http.Request, id identity.PeerID, src netip.Addr, now time.Time) {
	s.auth.maybeReload(now)
	if !s.auth.allowed(id) {
		s.log.Warn("refused unauthorized peer", "peer_id", id, "source", src)
		writeError(w, http.StatusForbidden, "this LANChat identity is not authorized on this discovery server")
		return
	}
	var req managedapi.AnnounceRequest
	if code, msg := decodeJSON(w, r, &req); code != 0 {
		s.log.Warn("rejected announcement", "peer_id", id, "source", src, "status", code, "err", msg)
		writeError(w, code, msg)
		return
	}
	if err := req.Validate(); err != nil {
		// Validation errors can quote client input; keep log lines short.
		s.log.Warn("rejected announcement", "peer_id", id, "source", src, "err", truncate(err.Error(), 120))
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	display := textsafe.Line(req.DisplayName, maxNameRunes)
	if display == "" {
		writeError(w, http.StatusBadRequest, "invalid display_name")
		return
	}
	e := &entry{
		id:              id,
		displayName:     display,
		deviceName:      textsafe.Line(req.DeviceName, maxNameRunes),
		port:            req.Port,
		protocolVersion: req.ProtocolVersion,
		addrs:           candidateAddrs(src, req.Addresses, req.Port),
		lastSeen:        now,
	}
	ttl := s.cfg.PresenceTTL
	switch s.dir.upsert(e, s.cfg.MaxPeers, ttl) {
	case upsertFull:
		s.log.Warn("directory is full; registration refused", "peer_id", id, "source", src, "max_peers", s.cfg.MaxPeers)
		w.Header().Set("Retry-After", strconv.Itoa(int(ttl/time.Second)))
		writeError(w, http.StatusServiceUnavailable, "the discovery server has reached its peer limit")
		return
	case upsertNew:
		s.log.Info("peer registered", "peer_id", id, "source", src, "addresses", len(e.addrs))
	default:
		s.log.Debug("peer refreshed", "peer_id", id, "source", src)
	}
	writeJSON(w, http.StatusOK, managedapi.AnnounceResponse{
		Peers:           s.dir.others(id, now, ttl, s.auth.allowed, managedapi.MaxPeersReturn),
		TTLSeconds:      int(ttl / time.Second),
		ObservedAddress: net.JoinHostPort(src.String(), strconv.Itoa(req.Port)),
	})
}

func (s *Server) handleWithdraw(w http.ResponseWriter, r *http.Request, id identity.PeerID, src netip.Addr) {
	// The body carries nothing; read and bound it so the connection can be
	// reused. Removing one's own entry is always permitted.
	body := http.MaxBytesReader(w, r.Body, managedapi.MaxBodyBytes)
	if _, err := io.Copy(io.Discard, body); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "cannot read request body")
		return
	}
	if s.dir.remove(id) {
		s.log.Info("peer withdrew", "peer_id", id, "source", src)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sourceAllowed(a netip.Addr) bool {
	if len(s.prefixes) == 0 {
		return true
	}
	for _, p := range s.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func sourceAddr(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap().WithZone(""), true
}

// decodeJSON decodes a single bounded JSON value. It returns a non-zero
// HTTP status and message on failure. Request bodies are never logged.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) (int, string) {
	body := http.MaxBytesReader(w, r.Body, managedapi.MaxBodyBytes)
	dec := json.NewDecoder(body)
	tooLarge := func(err error) bool {
		var mbe *http.MaxBytesError
		return errors.As(err, &mbe)
	}
	if err := dec.Decode(v); err != nil {
		if tooLarge(err) {
			return http.StatusRequestEntityTooLarge, "request body too large"
		}
		return http.StatusBadRequest, "invalid JSON request body"
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if tooLarge(err) {
			return http.StatusRequestEntityTooLarge, "request body too large"
		}
		return http.StatusBadRequest, "unexpected data after the JSON request body"
	}
	return 0, ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, managedapi.ErrorResponse{Error: msg})
}
