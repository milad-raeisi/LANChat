package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// Errors returned by Session methods.
var (
	ErrClosed       = errors.New("session closed")
	ErrBackpressure = errors.New("send queue is full")
	ErrTimeout      = errors.New("peer stopped responding")
)

const (
	ctrlQueue    = 512
	bulkQueue    = 4
	writeTimeout = 20 * time.Second
	// Inbound envelope rate limit (token bucket). A peer that exceeds it is
	// throttled, not disconnected: the session stops reading, so TCP flow
	// control slows the sender down. This bounds the work any peer can cause
	// without losing messages from legitimate bursts (for example a queue
	// flushed after reconnecting). File chunks are paced by TCP alone.
	rateBurst  = 2000.0
	ratePerSec = 500.0
)

// Handler receives frames and the close notification of a session.
// HandleFrame is called sequentially from the session's read goroutine, so
// per-peer ordering is preserved. Returning an error closes the session as a
// protocol violation.
type Handler interface {
	HandleFrame(s *Session, f *protocol.Frame) error
	SessionClosed(s *Session, err error)
}

// Session is an established, authenticated connection to one peer.
type Session struct {
	conn      *tls.Conn
	reader    *protocol.Reader
	cfg       *Config
	peerID    identity.PeerID
	peerKey   ed25519.PublicKey
	hello     protocol.Hello
	version   int
	outbound  bool
	dialerID  identity.PeerID
	exporter  []byte
	localSPKI []byte
	createdAt time.Time

	ctrl chan []byte
	bulk chan []byte

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  atomic.Value // error
	started   atomic.Bool
	lastRecv  atomic.Int64

	pingMu sync.Mutex
	pings  map[string]chan time.Time
}

type sessionParams struct {
	conn      *tls.Conn
	reader    *protocol.Reader
	cfg       *Config
	peerID    identity.PeerID
	peerKey   ed25519.PublicKey
	hello     protocol.Hello
	version   int
	outbound  bool
	dialerID  identity.PeerID
	exporter  []byte
	localSPKI []byte
}

func newSession(p sessionParams) *Session {
	s := &Session{
		conn: p.conn, reader: p.reader, cfg: p.cfg, peerID: p.peerID, peerKey: p.peerKey,
		hello: p.hello, version: p.version, outbound: p.outbound, dialerID: p.dialerID,
		exporter: p.exporter, localSPKI: p.localSPKI, createdAt: time.Now(),
		ctrl:   make(chan []byte, ctrlQueue),
		bulk:   make(chan []byte, bulkQueue),
		closed: make(chan struct{}),
		pings:  make(map[string]chan time.Time),
	}
	s.lastRecv.Store(time.Now().UnixNano())
	return s
}

// PeerID returns the authenticated peer ID.
func (s *Session) PeerID() identity.PeerID { return s.peerID }

// PublicKey returns the authenticated Ed25519 key.
func (s *Session) PublicKey() ed25519.PublicKey { return s.peerKey }

// SPKI returns the peer's DER SubjectPublicKeyInfo.
func (s *Session) SPKI() []byte { return identity.SPKI(s.peerKey) }

// Hello returns the peer's hello message.
func (s *Session) Hello() protocol.Hello { return s.hello }

// Version returns the negotiated protocol version.
func (s *Session) Version() int { return s.version }

// Outbound reports whether this side dialed.
func (s *Session) Outbound() bool { return s.outbound }

// DialerID returns the peer ID of the side that initiated the connection.
func (s *Session) DialerID() identity.PeerID { return s.dialerID }

// RemoteAddr returns the peer's network address.
func (s *Session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// LocalAddr returns the local network address.
func (s *Session) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// CreatedAt returns when the session was established.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// PairingCode returns the six-digit short authentication string for this
// session and the pairing nonces exchanged on it (commit-then-reveal). Both
// ends compute the same value only if no one is in the middle.
func (s *Session) PairingCode(initiatorNonce, responderNonce []byte) string {
	return identity.SAS(s.localSPKI, s.SPKI(), s.exporter, initiatorNonce, responderNonce)
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.closed }

// Err returns the reason the session closed, or nil while open.
func (s *Session) Err() error {
	if v := s.closeErr.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// Alive reports whether the session is open.
func (s *Session) Alive() bool {
	select {
	case <-s.closed:
		return false
	default:
		return true
	}
}

// Start launches the read, write and heartbeat goroutines.
func (s *Session) Start(h Handler) {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	go s.writeLoop()
	go s.heartbeatLoop()
	go s.readLoop(h)
}

// Send queues an envelope without blocking.
func (s *Session) Send(typ string, body any) error {
	frame, err := s.encode(typ, body)
	if err != nil {
		return err
	}
	if !s.Alive() {
		return ErrClosed
	}
	select {
	case s.ctrl <- frame:
		return s.queued()
	case <-s.closed:
		return ErrClosed
	default:
		return ErrBackpressure
	}
}

// queued reports the outcome of a successful enqueue. A select with both a
// free queue slot and a closed session picks one at random, and a session
// can close while a frame is being queued; in both cases the frame will
// never be written, so report ErrClosed rather than success. (Success still
// only means "queued on a live session", never "delivered".)
func (s *Session) queued() error {
	if !s.Alive() {
		return ErrClosed
	}
	return nil
}

// SendWait queues an envelope, waiting for queue space.
func (s *Session) SendWait(ctx context.Context, typ string, body any) error {
	frame, err := s.encode(typ, body)
	if err != nil {
		return err
	}
	if !s.Alive() {
		return ErrClosed
	}
	select {
	case s.ctrl <- frame:
		return s.queued()
	case <-s.closed:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendBulk queues a pre-encoded bulk frame (file chunk), waiting for space.
// Control frames are always written before pending bulk frames.
func (s *Session) SendBulk(ctx context.Context, frame []byte) error {
	if !s.Alive() {
		return ErrClosed
	}
	select {
	case s.bulk <- frame:
		return s.queued()
	case <-s.closed:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendBulkEnvelope queues an envelope on the bulk queue so that it is
// written strictly after previously queued bulk frames (for example the
// end-of-file marker after the last file chunk).
func (s *Session) SendBulkEnvelope(ctx context.Context, typ string, body any) error {
	frame, err := s.encode(typ, body)
	if err != nil {
		return err
	}
	return s.SendBulk(ctx, frame)
}

func (s *Session) encode(typ string, body any) ([]byte, error) {
	env, err := protocol.NewEnvelope(s.version, typ, body)
	if err != nil {
		return nil, err
	}
	env.TS = time.Now().UnixMilli()
	return protocol.EncodeEnvelope(env)
}

// Ping measures the application-level round-trip time.
func (s *Session) Ping(ctx context.Context) (time.Duration, error) {
	nonce := protocol.NewID()
	ch := make(chan time.Time, 1)
	s.pingMu.Lock()
	s.pings[nonce] = ch
	s.pingMu.Unlock()
	defer func() {
		s.pingMu.Lock()
		delete(s.pings, nonce)
		s.pingMu.Unlock()
	}()
	start := time.Now()
	if err := s.SendWait(ctx, protocol.TypePing, protocol.Ping{Nonce: nonce}); err != nil {
		return 0, err
	}
	select {
	case t := <-ch:
		return t.Sub(start), nil
	case <-s.closed:
		return 0, ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Close closes the session immediately.
func (s *Session) Close(reason error) {
	s.closeOnce.Do(func() {
		if reason == nil {
			reason = ErrClosed
		}
		s.closeErr.Store(reason)
		close(s.closed)
		_ = s.conn.Close()
	})
}

// CloseWithError tells the peer why the session is ending (best effort,
// bounded by a short deadline) and closes it.
func (s *Session) CloseWithError(code, msg string) {
	if s.Alive() {
		if frame, err := s.encode(protocol.TypeError, protocol.ErrorMsg{Code: code, Message: msg}); err == nil {
			_ = s.conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = s.conn.Write(frame)
		}
	}
	s.Close(&RemoteError{Code: code, Message: "closed locally: " + msg})
}

func (s *Session) writeLoop() {
	write := func(frame []byte) bool {
		_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := s.conn.Write(frame); err != nil {
			s.Close(fmt.Errorf("write: %w", err))
			return false
		}
		return true
	}
	for {
		// Strict priority: drain control frames before any bulk frame.
		select {
		case <-s.closed:
			return
		case f := <-s.ctrl:
			if !write(f) {
				return
			}
			continue
		default:
		}
		select {
		case <-s.closed:
			return
		case f := <-s.ctrl:
			if !write(f) {
				return
			}
		case f := <-s.bulk:
			if !write(f) {
				return
			}
		}
	}
}

func (s *Session) heartbeatLoop() {
	interval := s.cfg.Heartbeat
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			last := time.Unix(0, s.lastRecv.Load())
			if time.Since(last) > 3*interval {
				s.Close(ErrTimeout)
				return
			}
			_ = s.Send(protocol.TypePing, protocol.Ping{Nonce: protocol.NewID()})
		}
	}
}

func (s *Session) readLoop(h Handler) {
	var closeErr error
	defer func() {
		s.Close(closeErr)
		h.SessionClosed(s, s.Err())
	}()
	tokens := rateBurst
	lastRefill := time.Now()
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(3*s.cfg.Heartbeat + 5*time.Second))
		f, err := s.reader.Next()
		if err != nil {
			select {
			case <-s.closed:
				closeErr = s.Err()
			default:
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					closeErr = ErrTimeout
				} else {
					closeErr = fmt.Errorf("read: %w", err)
				}
			}
			if errors.Is(err, protocol.ErrMalformed) || errors.Is(err, protocol.ErrFrameTooLarge) {
				s.CloseWithError(protocol.CodeProtocolViolation, err.Error())
			}
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		if f.Kind == protocol.KindEnvelope {
			now := time.Now()
			tokens += now.Sub(lastRefill).Seconds() * ratePerSec
			if tokens > rateBurst {
				tokens = rateBurst
			}
			lastRefill = now
			if tokens < 1 {
				wait := time.Duration((1 - tokens) / ratePerSec * float64(time.Second))
				select {
				case <-s.closed:
					closeErr = s.Err()
					return
				case <-time.After(wait):
				}
				now = time.Now()
				tokens += now.Sub(lastRefill).Seconds() * ratePerSec
				lastRefill = now
			}
			tokens--
			if s.handleBuiltin(f.Envelope) {
				continue
			}
		}
		if err := h.HandleFrame(s, f); err != nil {
			s.CloseWithError(protocol.CodeProtocolViolation, err.Error())
			closeErr = fmt.Errorf("protocol violation: %w", err)
			return
		}
	}
}

// handleBuiltin answers keepalive traffic inside the transport.
func (s *Session) handleBuiltin(env *protocol.Envelope) bool {
	switch env.Type {
	case protocol.TypePing:
		if p, err := protocol.DecodeBody[protocol.Ping](env); err == nil {
			_ = s.Send(protocol.TypePong, protocol.Ping{Nonce: p.Nonce})
		}
		return true
	case protocol.TypePong:
		if p, err := protocol.DecodeBody[protocol.Ping](env); err == nil {
			s.pingMu.Lock()
			ch := s.pings[p.Nonce]
			s.pingMu.Unlock()
			if ch != nil {
				select {
				case ch <- time.Now():
				default:
				}
			}
		}
		return true
	case protocol.TypeHello:
		// A second hello is a protocol violation; let the handler reject it.
		return false
	}
	return false
}
