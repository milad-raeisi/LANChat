package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

type result struct {
	state tls.ConnectionState
	err   error
}

func handshake(t *testing.T, server, client *tls.Config) (srv, cli result) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		tc := tls.Server(c, server)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		err = tc.Handshake()
		done <- result{state: tc.ConnectionState(), err: err}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := tls.Client(c, client)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	err = tc.Handshake()
	cli = result{state: tc.ConnectionState(), err: err}
	if err != nil {
		_ = tc.Close()
	}
	srv = <-done
	return srv, cli
}

func TestMutualAuthentication(t *testing.T) {
	a, _ := identity.Generate()
	b, _ := identity.Generate()
	sc, _ := PeerServerConfig(a)
	cc, _ := PeerClientConfig(b)
	srv, cli := handshake(t, sc, cc)
	if srv.err != nil || cli.err != nil {
		t.Fatalf("handshake failed: server=%v client=%v", srv.err, cli.err)
	}
	_, gotB, err := PeerFromState(srv.state)
	if err != nil || gotB != b.ID() {
		t.Fatalf("server saw %s (%v), want %s", gotB, err, b.ID())
	}
	_, gotA, err := PeerFromState(cli.state)
	if err != nil || gotA != a.ID() {
		t.Fatalf("client saw %s (%v), want %s", gotA, err, a.ID())
	}
	if cli.state.NegotiatedProtocol != ALPN {
		t.Fatalf("ALPN = %q", cli.state.NegotiatedProtocol)
	}
	e1, _ := PairingExporter(srv.state)
	e2, _ := PairingExporter(cli.state)
	if string(e1) != string(e2) {
		t.Fatal("exporter values differ between endpoints")
	}
	if identity.SAS(identity.SPKI(a.PublicKey()), identity.SPKI(b.PublicKey()), e1, []byte("i"), []byte("r")) !=
		identity.SAS(identity.SPKI(b.PublicKey()), identity.SPKI(a.PublicKey()), e2, []byte("i"), []byte("r")) {
		t.Fatal("pairing codes differ")
	}
}

func TestClientWithoutCertificateRejected(t *testing.T) {
	a, _ := identity.Generate()
	sc, _ := PeerServerConfig(a)
	cc := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} //nolint:gosec // test
	srv, _ := handshake(t, sc, cc)
	if srv.err == nil {
		t.Fatal("server accepted a client without an identity certificate")
	}
}

func TestTLS12Rejected(t *testing.T) {
	a, _ := identity.Generate()
	b, _ := identity.Generate()
	sc, _ := PeerServerConfig(a)
	cc, _ := PeerClientConfig(b)
	cc.MinVersion, cc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	srv, cli := handshake(t, sc, cc)
	if srv.err == nil && cli.err == nil {
		t.Fatal("TLS 1.2 handshake succeeded")
	}
}

func TestNonEd25519CertificateRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err := VerifyPeerCertificate([][]byte{der}, nil); !errors.Is(err, ErrBadPeerCertificate) {
		t.Fatalf("expected ErrBadPeerCertificate, got %v", err)
	}
	if err := VerifyPeerCertificate(nil, nil); !errors.Is(err, ErrBadPeerCertificate) {
		t.Fatal("empty chain accepted")
	}
	if err := VerifyPeerCertificate([][]byte{[]byte("garbage")}, nil); !errors.Is(err, ErrBadPeerCertificate) {
		t.Fatal("garbage accepted")
	}
}

func TestForgedCertificateRejected(t *testing.T) {
	// A certificate carrying victim's public key but signed by the attacker
	// fails the self-signature check (and the attacker could not complete
	// CertificateVerify anyway).
	victim, _ := identity.Generate()
	attacker, _ := identity.Generate()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "forged"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	signer := attacker
	cert, _ := signer.Certificate()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, victim.PublicKey(), cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPeerCertificate([][]byte{der}, nil); !errors.Is(err, ErrBadPeerCertificate) {
		t.Fatalf("forged certificate accepted: %v", err)
	}
}
