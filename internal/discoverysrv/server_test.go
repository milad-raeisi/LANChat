package discoverysrv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/managedapi"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/security/tlsconf"
)

// ---- helpers ---------------------------------------------------------------

type testEnv struct {
	srv  *Server
	addr string
}

// startServer runs a server on 127.0.0.1:0 until the test ends.
func startServer(t *testing.T, mutate func(*Config)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		Listen:       "127.0.0.1:0",
		IdentityFile: filepath.Join(dir, "server-identity.key"),
		RateLimit:    1000,
		RateBurst:    1000,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg, logging.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Check the authorized peers file on every request so reload tests do
	// not have to wait (set before Serve starts any goroutine).
	srv.auth.minInterval = 0
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v after shutdown", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("server did not shut down")
		}
	})
	return &testEnv{srv: srv, addr: srv.Addr().String()}
}

func newID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// Guarantee a visible mtime change even on coarse-grained filesystems.
	future := time.Now().Add(time.Duration(len(content)+1) * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func authFile(t *testing.T, ids ...*identity.Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authorized_peers")
	var b strings.Builder
	b.WriteString("# LANChat peers allowed to use this server\n\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "%s  # %s\n", id.ID(), "someone")
	}
	writeFile(t, path, b.String())
	return path
}

// client builds the real LANChat managed-discovery client, pinned to the
// server fingerprint.
func client(t *testing.T, env *testEnv, id *identity.Identity, name, pin string, addrs ...string) *discovery.Managed {
	t.Helper()
	if pin == "" {
		pin = env.srv.Fingerprint()
	}
	tc, err := tlsconf.DiscoveryClientConfig(id, "127.0.0.1", pin, "")
	if err != nil {
		t.Fatal(err)
	}
	return managedClient(t, env.addr, tc, id, name, addrs...)
}

func managedClient(t *testing.T, server string, tc *tls.Config, id *identity.Identity, name string, addrs ...string) *discovery.Managed {
	t.Helper()
	var list []netip.Addr
	for _, a := range addrs {
		list = append(list, netip.MustParseAddr(a))
	}
	self := discovery.Self{
		PeerID: id.ID(), DisplayName: name, DeviceName: "device-" + name, Port: 47777,
		ProtocolVersion: buildinfo.ProtocolVersion, Capabilities: []string{"files"},
	}
	return discovery.NewManaged(server, tc, self, func() []netip.Addr { return list }, 30*time.Second, logging.Discard())
}

func announce(t *testing.T, m *discovery.Managed) *managedapi.AnnounceResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := m.Announce(ctx)
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	return resp
}

func announceErr(t *testing.T, m *discovery.Managed) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := m.Announce(ctx)
	if err == nil {
		t.Fatal("Announce succeeded, expected an error")
	}
	return err
}

func peerIDs(resp *managedapi.AnnounceResponse) []string {
	out := []string{}
	for _, p := range resp.Peers {
		out = append(out, p.PeerID)
	}
	return out
}

// rawClient is a plain HTTPS client. With id it presents that identity and
// pins the server; without id it sends no client certificate.
func rawClient(t *testing.T, env *testEnv, id *identity.Identity) *http.Client {
	t.Helper()
	var tc *tls.Config
	if id != nil {
		var err error
		tc, err = tlsconf.DiscoveryClientConfig(id, "127.0.0.1", env.srv.Fingerprint(), "")
		if err != nil {
			t.Fatal(err)
		}
	} else {
		tc = &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}} //nolint:gosec // test checks the fingerprint explicitly
	}
	tr := &http.Transport{TLSClientConfig: tc, Proxy: nil}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func do(t *testing.T, c *http.Client, method, url string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, data
}

func health(t *testing.T, env *testEnv) healthResponse {
	t.Helper()
	res, data := do(t, rawClient(t, env, nil), http.MethodGet, "https://"+env.addr+managedapi.PathHealth, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("healthz: HTTP %d %s", res.StatusCode, data)
	}
	var h healthResponse
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func errorMessage(t *testing.T, data []byte) string {
	t.Helper()
	var er managedapi.ErrorResponse
	if err := json.Unmarshal(data, &er); err != nil || er.Error == "" {
		t.Fatalf("expected an ErrorResponse, got %q", data)
	}
	return er.Error
}

// ---- end-to-end tests --------------------------------------------------------

func TestAuthorizedPeersSeeEachOther(t *testing.T) {
	a, b := newID(t), newID(t)
	path := authFile(t, a, b)
	env := startServer(t, func(c *Config) { c.AuthorizedPeersFile = path })

	ca := client(t, env, a, "Alice", "", "192.0.2.10")
	// Bob reports unusable, duplicate and IPv4-mapped addresses, and a
	// display name with a bidi override and a terminal escape.
	cb := client(t, env, b, "Bob \u202eevil\x1b[31m", "",
		"127.0.0.1", "169.254.1.1", "fe80::1", "224.0.0.1", "0.0.0.0",
		"192.0.2.20", "192.0.2.20", "2001:db8::5", "::ffff:192.0.2.30")

	r1 := announce(t, ca)
	if len(r1.Peers) != 0 {
		t.Fatalf("first announcement should see nobody, got %v", peerIDs(r1))
	}
	if r1.TTLSeconds != 90 {
		t.Errorf("ttl_seconds = %d, want 90", r1.TTLSeconds)
	}
	if r1.ObservedAddress != "127.0.0.1:47777" {
		t.Errorf("observed_address = %q", r1.ObservedAddress)
	}

	r2 := announce(t, cb)
	if got := peerIDs(r2); !reflect.DeepEqual(got, []string{string(a.ID())}) {
		t.Fatalf("Bob sees %v, want only Alice", got)
	}
	alice := r2.Peers[0]
	if alice.DisplayName != "Alice" || alice.DeviceName != "device-Alice" || alice.ProtocolVersion != buildinfo.ProtocolVersion {
		t.Errorf("unexpected Alice entry %+v", alice)
	}
	// The observed loopback address is not a usable candidate for others.
	if !reflect.DeepEqual(alice.Addresses, []string{"192.0.2.10:47777"}) {
		t.Errorf("Alice addresses = %v", alice.Addresses)
	}
	if alice.LastSeen <= 0 {
		t.Errorf("last_seen = %d", alice.LastSeen)
	}

	r3 := announce(t, ca)
	if got := peerIDs(r3); !reflect.DeepEqual(got, []string{string(b.ID())}) {
		t.Fatalf("Alice sees %v, want only Bob", got)
	}
	bob := r3.Peers[0]
	wantAddrs := []string{"192.0.2.20:47777", "[2001:db8::5]:47777", "192.0.2.30:47777"}
	if !reflect.DeepEqual(bob.Addresses, wantAddrs) {
		t.Errorf("Bob addresses = %v, want %v", bob.Addresses, wantAddrs)
	}
	if strings.ContainsAny(bob.DisplayName, "\u202e\x1b") || !strings.HasPrefix(bob.DisplayName, "Bob") {
		t.Errorf("display name not sanitized: %q", bob.DisplayName)
	}
	for _, p := range r3.Peers {
		if err := p.Validate(); err != nil {
			t.Errorf("entry fails client-side validation: %v", err)
		}
	}
	if h := health(t, env); h.Peers != 2 {
		t.Errorf("healthz peers = %d, want 2", h.Peers)
	}
}

func TestUnauthorizedIdentityRefused(t *testing.T) {
	a, intruder := newID(t), newID(t)
	path := authFile(t, a)
	env := startServer(t, func(c *Config) { c.AuthorizedPeersFile = path })

	err := announceErr(t, client(t, env, intruder, "Mallory", "", "192.0.2.66"))
	if !strings.Contains(err.Error(), "refused this identity") {
		t.Fatalf("error %q does not mention refusal", err)
	}
	if h := health(t, env); h.Peers != 0 {
		t.Errorf("refused peer was registered (peers = %d)", h.Peers)
	}
	// The authorized peer is not shown the refused one.
	if r := announce(t, client(t, env, a, "Alice", "", "192.0.2.10")); len(r.Peers) != 0 {
		t.Errorf("Alice sees %v", peerIDs(r))
	}
}

func TestWrongPinFailsTLS(t *testing.T) {
	a := newID(t)
	env := startServer(t, func(c *Config) { c.AllowAny = true })
	wrong := newID(t).Fingerprint()
	err := announceErr(t, client(t, env, a, "Alice", wrong, "192.0.2.10"))
	if !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("error %q is not a fingerprint mismatch", err)
	}
	if h := health(t, env); h.Peers != 0 {
		t.Errorf("peers = %d after failed handshake", h.Peers)
	}
	// The grouped form printed by `lanchat-discovery fingerprint` also pins.
	announce(t, client(t, env, a, "Alice", identity.FormatFingerprint(env.srv.Fingerprint()), "192.0.2.10"))
}

func TestAllowAny(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true })
	a, b := newID(t), newID(t)
	announce(t, client(t, env, a, "Alice", "", "192.0.2.10"))
	r := announce(t, client(t, env, b, "Bob", "", "192.0.2.20"))
	if got := peerIDs(r); !reflect.DeepEqual(got, []string{string(a.ID())}) {
		t.Fatalf("Bob sees %v, want Alice", got)
	}
}

func TestWithdrawRemovesPeer(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true })
	a, b := newID(t), newID(t)
	ca, cb := client(t, env, a, "Alice", "", "192.0.2.10"), client(t, env, b, "Bob", "", "192.0.2.20")
	announce(t, ca)
	if r := announce(t, cb); len(r.Peers) != 1 {
		t.Fatalf("Bob sees %v", peerIDs(r))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cb.Withdraw(ctx); err != nil {
		t.Fatalf("Withdraw: %v", err)
	}
	if r := announce(t, ca); len(r.Peers) != 0 {
		t.Fatalf("Alice still sees %v after Bob withdrew", peerIDs(r))
	}
	if h := health(t, env); h.Peers != 1 {
		t.Errorf("healthz peers = %d, want 1", h.Peers)
	}
	// Withdrawing again is harmless.
	if err := cb.Withdraw(ctx); err != nil {
		t.Fatalf("second Withdraw: %v", err)
	}
}

func TestPresenceExpiry(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true; c.PresenceTTL = time.Second })
	a, b := newID(t), newID(t)
	ca := client(t, env, a, "Alice", "", "192.0.2.10")
	announce(t, client(t, env, b, "Bob", "", "192.0.2.20"))
	r := announce(t, ca)
	if len(r.Peers) != 1 || r.TTLSeconds != 1 {
		t.Fatalf("before expiry: peers %v ttl %d", peerIDs(r), r.TTLSeconds)
	}
	time.Sleep(1500 * time.Millisecond)
	if r := announce(t, ca); len(r.Peers) != 0 {
		t.Fatalf("expired peer still listed: %v", peerIDs(r))
	}
	// The sweeper removes the stale entry from memory too.
	deadline := time.Now().Add(5 * time.Second)
	for {
		env.srv.dir.mu.Lock()
		_, present := env.srv.dir.peers[b.ID()]
		env.srv.dir.mu.Unlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sweeper did not remove the expired entry")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestOversizedAndInvalidBodiesRejected(t *testing.T) {
	a := newID(t)
	env := startServer(t, func(c *Config) { c.AllowAny = true })
	c := rawClient(t, env, a)
	url := "https://" + env.addr + managedapi.PathAnnounce

	big := []byte(`{"display_name":"` + strings.Repeat("a", managedapi.MaxBodyBytes+1024) + `","port":47777,"protocol_version":1}`)
	res, data := do(t, c, http.MethodPost, url, big)
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: HTTP %d %s", res.StatusCode, data)
	}
	errorMessage(t, data)

	res, data = do(t, rawClient(t, env, a), http.MethodPost, url, []byte(`{"display_name":`))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("truncated JSON: HTTP %d %s", res.StatusCode, data)
	}
	res, data = do(t, rawClient(t, env, a), http.MethodPost, url, []byte(`{"display_name":"x","port":0,"protocol_version":1}`))
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(errorMessage(t, data), "port") {
		t.Fatalf("invalid port: HTTP %d %s", res.StatusCode, data)
	}
	res, data = do(t, rawClient(t, env, a), http.MethodPost, url, []byte(`{"display_name":"x","port":1,"protocol_version":1} {}`))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing data: HTTP %d %s", res.StatusCode, data)
	}
	// A name that sanitizes to nothing is rejected rather than stored empty.
	res, data = do(t, rawClient(t, env, a), http.MethodPost, url, []byte(`{"display_name":"\u202e\u0007","port":1,"protocol_version":1}`))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("invisible-only name: HTTP %d %s", res.StatusCode, data)
	}
	if h := health(t, env); h.Peers != 0 {
		t.Errorf("rejected requests registered %d peers", h.Peers)
	}
}

func TestHealthzWithoutClientCert(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true })
	announce(t, client(t, env, newID(t), "Alice", "", "192.0.2.10"))

	res, data := do(t, rawClient(t, env, nil), http.MethodGet, "https://"+env.addr+managedapi.PathHealth, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("healthz: HTTP %d %s", res.StatusCode, data)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 || fields["status"] != "ok" || fields["peers"] != float64(1) {
		t.Fatalf("healthz body = %s, want only status and peers", data)
	}
	if res.TLS == nil || res.TLS.Version != tls.VersionTLS13 || res.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("unexpected TLS state %+v", res.TLS)
	}
	if got := identity.FingerprintSPKI(res.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo); got != env.srv.Fingerprint() {
		t.Fatalf("served certificate fingerprint %s != %s", got, env.srv.Fingerprint())
	}
	res, _ = do(t, rawClient(t, env, nil), http.MethodPost, "https://"+env.addr+managedapi.PathHealth, nil)
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz: HTTP %d", res.StatusCode)
	}
}

func TestV1RequiresClientCertAndPOST(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true })
	body := []byte(`{"display_name":"x","port":47777,"protocol_version":1}`)
	for _, path := range []string{managedapi.PathAnnounce, managedapi.PathWithdraw} {
		res, data := do(t, rawClient(t, env, nil), http.MethodPost, "https://"+env.addr+path, body)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s without client cert: HTTP %d %s", path, res.StatusCode, data)
		}
		errorMessage(t, data)
	}
	c := rawClient(t, env, newID(t))
	res, _ := do(t, c, http.MethodGet, "https://"+env.addr+managedapi.PathAnnounce, nil)
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("GET /v1/announce: HTTP %d Allow=%q", res.StatusCode, res.Header.Get("Allow"))
	}
	res, _ = do(t, c, http.MethodPost, "https://"+env.addr+"/v1/unknown", body)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path: HTTP %d", res.StatusCode)
	}
}

func TestAuthorizedPeersReload(t *testing.T) {
	a, b := newID(t), newID(t)
	path := authFile(t, a)
	env := startServer(t, func(c *Config) { c.AuthorizedPeersFile = path })
	ca, cb := client(t, env, a, "Alice", "", "192.0.2.10"), client(t, env, b, "Bob", "", "192.0.2.20")

	announce(t, ca)
	if err := announceErr(t, cb); !strings.Contains(err.Error(), "refused this identity") {
		t.Fatalf("Bob before authorization: %v", err)
	}

	// Authorize Bob (upper case and a trailing comment are accepted).
	writeFile(t, path, fmt.Sprintf("%s\n%s # bob\n", a.ID(), strings.ToUpper(string(b.ID()))))
	if r := announce(t, cb); !reflect.DeepEqual(peerIDs(r), []string{string(a.ID())}) {
		t.Fatalf("Bob sees %v after authorization", peerIDs(r))
	}

	// An invalid file fails closed: nobody is authorized until it is fixed.
	writeFile(t, path, "not-a-peer-id\n")
	if err := announceErr(t, cb); !strings.Contains(err.Error(), "refused this identity") {
		t.Fatalf("invalid allowlist must refuse everyone: %v", err)
	}

	// Revoke Alice: she is refused and no longer shown to Bob.
	writeFile(t, path, string(b.ID())+"\n")
	if err := announceErr(t, ca); !strings.Contains(err.Error(), "refused this identity") {
		t.Fatalf("Alice after revocation: %v", err)
	}
	if r := announce(t, cb); len(r.Peers) != 0 {
		t.Fatalf("Bob still sees revoked peers %v", peerIDs(r))
	}

	// Removing the file fails closed.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := announceErr(t, cb); !strings.Contains(err.Error(), "refused this identity") {
		t.Fatalf("Bob after file removal: %v", err)
	}
}

func TestMaxPeers(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true; c.MaxPeers = 1 })
	ca := client(t, env, newID(t), "Alice", "", "192.0.2.10")
	announce(t, ca)
	err := announceErr(t, client(t, env, newID(t), "Bob", "", "192.0.2.20"))
	if !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected HTTP 503, got %v", err)
	}
	announce(t, ca) // existing registrations can still refresh
}

func TestRateLimit(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true; c.RateLimit = 0.01; c.RateBurst = 2 })
	c := rawClient(t, env, nil)
	url := "https://" + env.addr + managedapi.PathHealth
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests} {
		res, data := do(t, c, http.MethodGet, url, nil)
		if res.StatusCode != want {
			t.Fatalf("request %d: HTTP %d %s, want %d", i, res.StatusCode, data, want)
		}
	}
}

func TestAllowedCIDRs(t *testing.T) {
	env := startServer(t, func(c *Config) { c.AllowAny = true; c.AllowedCIDRs = []string{"10.0.0.0/8", "192.168.1.7"} })
	err := announceErr(t, client(t, env, newID(t), "Alice", "", "192.0.2.10"))
	if !strings.Contains(err.Error(), "source address is not allowed") {
		t.Fatalf("expected a source refusal, got %v", err)
	}
	health(t, env) // loopback health checks always work

	env2 := startServer(t, func(c *Config) { c.AllowAny = true; c.AllowedCIDRs = []string{"127.0.0.0/8"} })
	announce(t, client(t, env2, newID(t), "Alice", "", "192.0.2.10"))
}

func TestCustomCertificateWithCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	writeSelfSignedCert(t, certFile, keyFile)
	env := startServer(t, func(c *Config) {
		c.AllowAny = true
		c.IdentityFile = ""
		c.TLSCertFile, c.TLSKeyFile = certFile, keyFile
	})
	a := newID(t)
	tc, err := tlsconf.DiscoveryClientConfig(a, "127.0.0.1", "", certFile)
	if err != nil {
		t.Fatal(err)
	}
	announce(t, managedClient(t, env.addr, tc, a, "Alice", "192.0.2.10"))
	// Pinning the operator certificate works as well.
	announce(t, client(t, env, newID(t), "Bob", "", "192.0.2.20"))
	// A CA that did not issue the server certificate is rejected.
	otherCert := filepath.Join(dir, "other.crt")
	writeSelfSignedCert(t, otherCert, filepath.Join(dir, "other.key"))
	tc2, err := tlsconf.DiscoveryClientConfig(a, "127.0.0.1", "", otherCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := announceErr(t, managedClient(t, env.addr, tc2, a, "Alice", "192.0.2.10")); !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unexpected error with the wrong CA: %v", err)
	}
}

func writeSelfSignedCert(t *testing.T, certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "lanchat-discovery test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- configuration and unit tests -------------------------------------------

func TestServerIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity.key")
	cfg := Config{IdentityFile: path, AllowAny: true}
	s1, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Fingerprint() != s2.Fingerprint() || len(s1.Fingerprint()) != 64 {
		t.Fatalf("fingerprints differ or malformed: %s vs %s", s1.Fingerprint(), s2.Fingerprint())
	}
	if err := checkPrivate(path); err != nil {
		t.Error(err)
	}
}

func checkPrivate(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return fmt.Errorf("identity file mode %v", st.Mode().Perm())
	}
	return nil
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	idf := filepath.Join(dir, "id.key")
	bad := filepath.Join(dir, "bad_peers")
	writeFile(t, bad, "# ok\n"+strings.Repeat("a", identity.PeerIDLen)+"\nnot-an-id\n")
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no policy", Config{IdentityFile: idf}, "authorization"},
		{"cert without key", Config{AllowAny: true, TLSCertFile: "x.crt"}, "tls_cert_file and tls_key_file"},
		{"no certificate source", Config{AllowAny: true}, "identity_file"},
		{"bad cidr", Config{AllowAny: true, IdentityFile: idf, AllowedCIDRs: []string{"10.0.0.0/33"}}, "allowed_cidrs"},
		{"bad ttl", Config{AllowAny: true, IdentityFile: idf, PresenceTTL: time.Millisecond}, "presence_ttl"},
		{"bad listen", Config{AllowAny: true, IdentityFile: idf, Listen: "47780"}, "listen"},
		{"missing peers file", Config{IdentityFile: idf, AuthorizedPeersFile: filepath.Join(dir, "nope")}, "authorized peers file"},
		{"invalid peers file", Config{IdentityFile: idf, AuthorizedPeersFile: bad}, "line 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCandidateAddrsCap(t *testing.T) {
	var reported []string
	for i := 1; i <= 40; i++ {
		reported = append(reported, fmt.Sprintf("10.0.0.%d", i))
	}
	got := candidateAddrs(netip.MustParseAddr("192.0.2.1"), reported, 47777)
	if len(got) != managedapi.MaxAddresses || got[0] != "192.0.2.1:47777" || got[1] != "10.0.0.1:47777" {
		t.Fatalf("candidateAddrs = %v", got)
	}
	if got := candidateAddrs(netip.MustParseAddr("::1"), []string{"ff02::1", "255.255.255.255"}, 1); len(got) != 0 {
		t.Fatalf("unusable addresses kept: %v", got)
	}
}
