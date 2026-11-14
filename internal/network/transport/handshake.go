// Package transport establishes authenticated LANChat sessions over TCP and
// TLS 1.3 and moves frames over them.
//
// A session is created in two steps:
//
//  1. TLS 1.3 handshake with mutual certificate authentication. The peer ID
//     is derived from the certificate's Ed25519 key (see package tlsconf).
//  2. hello exchange. Both sides send hello immediately; the claimed peer ID
//     must equal the authenticated one, and a common protocol version must
//     exist. Dialers can additionally require a specific peer ID (the one
//     advertised by discovery) and fail with IdentityMismatchError.
package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/security/tlsconf"
)

// Config holds what is needed to establish sessions.
type Config struct {
	Identity  *identity.Identity
	ServerTLS *tls.Config
	ClientTLS *tls.Config
	// LocalHello returns the hello to send (display name may change at runtime).
	LocalHello func() protocol.Hello
	// HandshakeTimeout bounds TCP connect, TLS and the hello exchange.
	HandshakeTimeout time.Duration
	// Heartbeat is the keepalive interval; a session with no inbound frame
	// for 3× this interval is considered dead.
	Heartbeat time.Duration
}

// NewConfig builds a Config for id.
func NewConfig(id *identity.Identity, hello func() protocol.Hello, handshake, heartbeat time.Duration) (*Config, error) {
	srv, err := tlsconf.PeerServerConfig(id)
	if err != nil {
		return nil, err
	}
	cli, err := tlsconf.PeerClientConfig(id)
	if err != nil {
		return nil, err
	}
	if handshake <= 0 {
		handshake = 10 * time.Second
	}
	if heartbeat <= 0 {
		heartbeat = 15 * time.Second
	}
	return &Config{Identity: id, ServerTLS: srv, ClientTLS: cli, LocalHello: hello, HandshakeTimeout: handshake, Heartbeat: heartbeat}, nil
}

// IdentityMismatchError reports that the peer reached at an address is not
// the peer that was expected there (for example, discovery advertised one
// identity but the TLS handshake proved another).
type IdentityMismatchError struct {
	Expected, Got identity.PeerID
}

func (e *IdentityMismatchError) Error() string {
	return fmt.Sprintf("identity mismatch: expected peer %s but the remote side authenticated as %s", e.Expected, e.Got)
}

// IncompatibleVersionError reports that no common protocol version exists.
type IncompatibleVersionError struct {
	RemoteMin, RemoteMax int
}

func (e *IncompatibleVersionError) Error() string {
	return fmt.Sprintf("incompatible protocol: peer supports v%d–v%d, this build supports v%d–v%d",
		e.RemoteMin, e.RemoteMax, buildinfo.MinProtocolVersion, buildinfo.ProtocolVersion)
}

// RemoteError is an error message received from the peer.
type RemoteError struct {
	Code, Message string
}

func (e *RemoteError) Error() string {
	if e.Message == "" {
		return "peer reported " + e.Code
	}
	return fmt.Sprintf("peer reported %s: %s", e.Code, e.Message)
}

// ErrSelfConnection is returned when a dial reaches our own listener.
var ErrSelfConnection = errors.New("connected to this LANChat instance itself")

// Dial connects to the first reachable address and establishes a session.
// expected may be empty when the peer identity is not known in advance
// (static peers). Each address gets an equal share of the timeout.
func Dial(ctx context.Context, cfg *Config, addrs []string, expected identity.PeerID) (*Session, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no address to dial")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	per := cfg.HandshakeTimeout / time.Duration(len(addrs))
	if per < 2*time.Second {
		per = 2 * time.Second
	}
	var errs []error
	for _, addr := range addrs {
		if ctx.Err() != nil {
			break
		}
		d := net.Dialer{Timeout: per, KeepAlive: 30 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s, err := handshake(ctx, cfg, conn, true, expected)
		if err != nil {
			var mm *IdentityMismatchError
			var iv *IncompatibleVersionError
			if errors.As(err, &mm) || errors.As(err, &iv) || errors.Is(err, ErrSelfConnection) {
				return nil, err // definitive answers; do not try other addresses
			}
			errs = append(errs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		return s, nil
	}
	if len(errs) == 0 {
		return nil, ctx.Err()
	}
	return nil, errors.Join(errs...)
}

// Accept establishes a session on an accepted TCP connection.
func Accept(ctx context.Context, cfg *Config, conn net.Conn) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	return handshake(ctx, cfg, conn, false, "")
}

func handshake(ctx context.Context, cfg *Config, raw net.Conn, outbound bool, expected identity.PeerID) (*Session, error) {
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	var tc *tls.Conn
	if outbound {
		tc = tls.Client(raw, cfg.ClientTLS)
	} else {
		tc = tls.Server(raw, cfg.ServerTLS)
	}
	fail := func(err error) (*Session, error) {
		_ = tc.Close()
		return nil, err
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(fmt.Errorf("TLS handshake: %w", err))
	}
	st := tc.ConnectionState()
	if st.NegotiatedProtocol != tlsconf.ALPN {
		return fail(errors.New("peer did not negotiate the LANChat protocol"))
	}
	pub, peerID, err := tlsconf.PeerFromState(st)
	if err != nil {
		return fail(err)
	}
	if peerID == cfg.Identity.ID() {
		return fail(ErrSelfConnection)
	}
	if expected != "" && peerID != expected {
		writeErrorDirect(tc, protocol.CodeIdentityMismatch, "unexpected identity")
		return fail(&IdentityMismatchError{Expected: expected, Got: peerID})
	}
	exporter, err := tlsconf.PairingExporter(st)
	if err != nil {
		return fail(err)
	}

	local := cfg.LocalHello()
	local.ProtocolVersion = buildinfo.ProtocolVersion
	local.MinVersion = buildinfo.MinProtocolVersion
	local.PeerID = string(cfg.Identity.ID())
	env, err := protocol.NewEnvelope(buildinfo.ProtocolVersion, protocol.TypeHello, local)
	if err != nil {
		return fail(err)
	}
	frame, err := protocol.EncodeEnvelope(env)
	if err != nil {
		return fail(err)
	}
	if _, err := tc.Write(frame); err != nil {
		return fail(fmt.Errorf("send hello: %w", err))
	}

	reader := protocol.NewReader(tc)
	f, err := reader.Next()
	if err != nil {
		return fail(fmt.Errorf("read hello: %w", err))
	}
	if f.Kind != protocol.KindEnvelope {
		return fail(errors.New("expected hello, got a data frame"))
	}
	if f.Envelope.Type == protocol.TypeError {
		if em, err := protocol.DecodeBody[protocol.ErrorMsg](f.Envelope); err == nil {
			return fail(&RemoteError{Code: em.Code, Message: em.Message})
		}
		return fail(errors.New("peer refused the connection"))
	}
	if f.Envelope.Type != protocol.TypeHello {
		return fail(fmt.Errorf("expected hello, got %q", f.Envelope.Type))
	}
	remote, err := protocol.DecodeBody[protocol.Hello](f.Envelope)
	if err != nil {
		return fail(err)
	}
	if identity.PeerID(remote.PeerID) != peerID {
		writeErrorDirect(tc, protocol.CodeIdentityMismatch, "claimed peer id does not match certificate")
		return fail(&IdentityMismatchError{Expected: identity.PeerID(remote.PeerID), Got: peerID})
	}
	version, ok := protocol.Negotiate(buildinfo.MinProtocolVersion, buildinfo.ProtocolVersion, remote.MinVersion, remote.ProtocolVersion)
	if !ok {
		writeErrorDirect(tc, protocol.CodeIncompatibleVersion,
			fmt.Sprintf("supported versions %d-%d", buildinfo.MinProtocolVersion, buildinfo.ProtocolVersion))
		return fail(&IncompatibleVersionError{RemoteMin: remote.MinVersion, RemoteMax: remote.ProtocolVersion})
	}
	_ = raw.SetDeadline(time.Time{})

	dialer := peerID
	if outbound {
		dialer = cfg.Identity.ID()
	}
	return newSession(sessionParams{
		conn:      tc,
		reader:    reader,
		cfg:       cfg,
		peerID:    peerID,
		peerKey:   pub,
		hello:     *remote,
		version:   version,
		outbound:  outbound,
		dialerID:  dialer,
		exporter:  exporter,
		localSPKI: identity.SPKI(cfg.Identity.PublicKey()),
	}), nil
}

// writeErrorDirect sends an error envelope synchronously during handshake.
func writeErrorDirect(c net.Conn, code, msg string) {
	env, err := protocol.NewEnvelope(buildinfo.ProtocolVersion, protocol.TypeError, protocol.ErrorMsg{Code: code, Message: msg})
	if err != nil {
		return
	}
	frame, err := protocol.EncodeEnvelope(env)
	if err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(frame)
}

// keyOf is used by tests.
func keyOf(s *Session) ed25519.PublicKey { return s.peerKey }
