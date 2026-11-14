package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/security/tlsconf"
)

type recorder struct {
	mu     sync.Mutex
	frames []*protocol.Frame
	closed chan error
	got    chan struct{}
	reject bool
}

func newRecorder() *recorder {
	return &recorder{closed: make(chan error, 1), got: make(chan struct{}, 100)}
}

func (r *recorder) HandleFrame(_ *Session, f *protocol.Frame) error {
	r.mu.Lock()
	r.frames = append(r.frames, f)
	r.mu.Unlock()
	r.got <- struct{}{}
	if r.reject {
		return errors.New("rejected by test")
	}
	return nil
}

func (r *recorder) SessionClosed(_ *Session, err error) { r.closed <- err }

func cfgFor(t *testing.T, name string) *Config {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewConfig(id, func() protocol.Hello {
		return protocol.Hello{DisplayName: name, DeviceName: name + "-dev", ListenPort: 1, App: "test"}
	}, 3*time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// pair returns an accepted server session and a dialed client session.
func pair(t *testing.T, server, client *Config, expected identity.PeerID) (*Session, *Session, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- res{err: err}
			return
		}
		s, err := Accept(context.Background(), server, c)
		ch <- res{s, err}
	}()
	cs, cerr := Dial(context.Background(), client, []string{ln.Addr().String()}, expected)
	r := <-ch
	if cerr != nil {
		return r.s, nil, cerr
	}
	return r.s, cs, r.err
}

func TestSessionExchange(t *testing.T) {
	a, b := cfgFor(t, "alice"), cfgFor(t, "bob")
	srv, cli, err := pair(t, a, b, a.Identity.ID())
	if err != nil {
		t.Fatal(err)
	}
	if srv.PeerID() != b.Identity.ID() || cli.PeerID() != a.Identity.ID() {
		t.Fatal("peer ids wrong")
	}
	if srv.Hello().DisplayName != "bob" || cli.Hello().DisplayName != "alice" {
		t.Fatal("hello names wrong")
	}
	if !cli.Outbound() || srv.Outbound() || cli.DialerID() != b.Identity.ID() || srv.DialerID() != b.Identity.ID() {
		t.Fatal("direction / dialer bookkeeping wrong")
	}
	if srv.PairingCode() != cli.PairingCode() {
		t.Fatal("pairing codes differ between ends")
	}
	if !bytes.Equal(keyOf(srv), b.Identity.PublicKey()) {
		t.Fatal("key mismatch")
	}
	rs, rc := newRecorder(), newRecorder()
	srv.Start(rs)
	cli.Start(rc)
	msg := protocol.ChatMessage{MessageID: protocol.NewID(), Kind: protocol.ConvDirect, Body: "hi", SentAt: 1}
	if err := cli.Send(protocol.TypeChat, msg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rs.got:
	case <-time.After(3 * time.Second):
		t.Fatal("message not received")
	}
	rtt, err := cli.Ping(context.Background())
	if err != nil || rtt <= 0 {
		t.Fatalf("ping: %v %v", rtt, err)
	}
	cli.CloseWithError(protocol.CodeShuttingDown, "bye")
	select {
	case <-rs.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not notice close")
	}
}

func TestIdentityMismatch(t *testing.T) {
	a, b, c := cfgFor(t, "a"), cfgFor(t, "b"), cfgFor(t, "c")
	_, _, err := pair(t, a, b, c.Identity.ID())
	var mm *IdentityMismatchError
	if !errors.As(err, &mm) || mm.Got != a.Identity.ID() || mm.Expected != c.Identity.ID() {
		t.Fatalf("expected identity mismatch, got %v", err)
	}
}

func TestSelfConnectionRejected(t *testing.T) {
	a := cfgFor(t, "a")
	_, _, err := pair(t, a, a, "")
	if !errors.Is(err, ErrSelfConnection) {
		t.Fatalf("expected ErrSelfConnection, got %v", err)
	}
}

// rawClient performs TLS with a valid identity and then sends crafted bytes.
func rawClient(t *testing.T, server *Config, payload func(conn *tls.Conn)) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		_, err = Accept(context.Background(), server, c)
		errCh <- err
	}()
	id, _ := identity.Generate()
	cc, _ := tlsconf.PeerClientConfig(id)
	conn, err := tls.Dial("tcp", ln.Addr().String(), cc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload(conn)
	select {
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not finish")
		return nil
	}
}

func helloFrame(t *testing.T, h protocol.Hello) []byte {
	env, _ := protocol.NewEnvelope(h.ProtocolVersion, protocol.TypeHello, h)
	f, err := protocol.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHandshakeRejectsGarbageAndBadHello(t *testing.T) {
	srv := cfgFor(t, "srv")
	if err := rawClient(t, srv, func(c *tls.Conn) {
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}); err == nil {
		t.Fatal("garbage accepted")
	}
	if err := rawClient(t, srv, func(c *tls.Conn) {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], protocol.MaxFrameSize+10)
		_, _ = c.Write(hdr[:])
	}); !errors.Is(err, protocol.ErrFrameTooLarge) {
		t.Fatalf("oversized frame: %v", err)
	}
	// Claiming someone else's peer id.
	other, _ := identity.Generate()
	if err := rawClient(t, srv, func(c *tls.Conn) {
		_, _ = c.Write(helloFrame(t, protocol.Hello{ProtocolVersion: 1, MinVersion: 1, PeerID: string(other.ID()), DisplayName: "x"}))
	}); err == nil {
		t.Fatal("spoofed peer id accepted")
	}
}

func TestVersionNegotiationAgainstFutureOnlyPeer(t *testing.T) {
	srv := cfgFor(t, "srv")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		_, err = Accept(context.Background(), srv, c)
		errCh <- err
	}()
	future, _ := identity.Generate()
	cc, _ := tlsconf.PeerClientConfig(future)
	conn, err := tls.Dial("tcp", ln.Addr().String(), cc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	v := buildinfo.ProtocolVersion + 5
	_, _ = conn.Write(helloFrame(t, protocol.Hello{ProtocolVersion: v + 1, MinVersion: v, PeerID: string(future.ID()), DisplayName: "future"}))
	var iv *IncompatibleVersionError
	if err := <-errCh; !errors.As(err, &iv) {
		t.Fatalf("expected IncompatibleVersionError, got %v", err)
	}
	// The server explains why before closing: hello, then an error frame.
	r := protocol.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	f1, err := r.Next()
	if err != nil || f1.Envelope.Type != protocol.TypeHello {
		t.Fatalf("expected server hello first: %v", err)
	}
	f2, err := r.Next()
	if err != nil || f2.Envelope.Type != protocol.TypeError {
		t.Fatalf("expected error frame: %v", err)
	}
	em, _ := protocol.DecodeBody[protocol.ErrorMsg](f2.Envelope)
	if em == nil || em.Code != protocol.CodeIncompatibleVersion {
		t.Fatalf("error code = %+v", em)
	}
}

func TestHandlerErrorClosesSession(t *testing.T) {
	a, b := cfgFor(t, "a"), cfgFor(t, "b")
	srv, cli, err := pair(t, a, b, "")
	if err != nil {
		t.Fatal(err)
	}
	rs := newRecorder()
	rs.reject = true
	rc := newRecorder()
	srv.Start(rs)
	cli.Start(rc)
	_ = cli.Send(protocol.TypeChat, protocol.ChatMessage{MessageID: protocol.NewID(), Kind: protocol.ConvDirect, Body: "x"})
	select {
	case err := <-rc.closed:
		var re *RemoteError
		_ = re
		if err == nil {
			t.Fatal("expected close error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client session not closed after protocol violation")
	}
}

func TestHeartbeatTimeout(t *testing.T) {
	a, b := cfgFor(t, "a"), cfgFor(t, "b")
	a.Heartbeat = 200 * time.Millisecond
	srv, cli, err := pair(t, a, b, "")
	if err != nil {
		t.Fatal(err)
	}
	// The client never starts its loops, so it never answers pings.
	_ = cli
	rs := newRecorder()
	srv.Start(rs)
	select {
	case err := <-rs.closed:
		if !errors.Is(err, ErrTimeout) {
			t.Logf("closed with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dead peer not detected")
	}
}

func TestPriorityAndBackpressure(t *testing.T) {
	a, b := cfgFor(t, "a"), cfgFor(t, "b")
	srv, cli, err := pair(t, a, b, "")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(nil)
	defer cli.Close(nil)
	// Without started loops nothing drains the queue: Send must eventually
	// report backpressure instead of blocking.
	var sawBackpressure bool
	for i := 0; i < ctrlQueue+10; i++ {
		if err := cli.Send(protocol.TypePing, protocol.Ping{Nonce: protocol.NewID()}); errors.Is(err, ErrBackpressure) {
			sawBackpressure = true
			break
		}
	}
	if !sawBackpressure {
		t.Fatal("Send never reported backpressure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := cli.SendWait(ctx, protocol.TypePing, protocol.Ping{Nonce: protocol.NewID()}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SendWait on full queue: %v", err)
	}
}

func TestBurstIsThrottledNotDisconnected(t *testing.T) {
	a, b := cfgFor(t, "a"), cfgFor(t, "b")
	srv, cli, err := pair(t, a, b, "")
	if err != nil {
		t.Fatal(err)
	}
	const n = int(rateBurst) + 1500
	got := make(chan struct{}, n)
	h := &countHandler{got: got}
	srv.Start(h)
	cli.Start(newRecorder())
	defer cli.Close(nil)
	start := time.Now()
	for i := 0; i < n; i++ {
		if err := cli.SendWait(context.Background(), protocol.TypePresence, protocol.Presence{DisplayName: "x", Status: "online"}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	for i := 0; i < n; i++ {
		select {
		case <-got:
		case <-time.After(15 * time.Second):
			t.Fatalf("only %d of %d frames arrived", i, n)
		}
	}
	if !srv.Alive() {
		t.Fatal("burst caused a disconnect")
	}
	// Frames beyond the burst are paced at ratePerSec.
	if min := time.Duration(float64(n-int(rateBurst)) / ratePerSec * float64(time.Second) * 0.8); time.Since(start) < min {
		t.Fatalf("burst was not throttled: %v < %v", time.Since(start), min)
	}
}

type countHandler struct{ got chan struct{} }

func (h *countHandler) HandleFrame(*Session, *protocol.Frame) error { h.got <- struct{}{}; return nil }
func (h *countHandler) SessionClosed(*Session, error)               {}
