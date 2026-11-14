// Package integration_test runs several real LANChat nodes in one process.
// They communicate over genuine TCP + TLS 1.3 sockets on the loopback
// interface; only discovery is replaced by an injectable test double,
// because multicast is not reliably available in CI environments.
package integration_test

import (
	"context"
	"log/slog"
	"os"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/logging"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// fakeDiscovery delivers adverts pushed by the test.
type fakeDiscovery struct {
	ch chan discovery.Event
}

func newFakeDiscovery() *fakeDiscovery { return &fakeDiscovery{ch: make(chan discovery.Event, 64)} }

func (d *fakeDiscovery) Name() string { return "test" }
func (d *fakeDiscovery) Refresh()     {}
func (d *fakeDiscovery) Status() discovery.Status {
	return discovery.Status{Name: "test", Active: true}
}
func (d *fakeDiscovery) Run(ctx context.Context, events chan<- discovery.Event) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-d.ch:
			select {
			case events <- ev:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

type testNode struct {
	t     *testing.T
	name  string
	home  string
	id    *identity.Identity
	store *storage.Store
	disc  *fakeDiscovery
	*node.Node
	cfg config.Config
}

func newConfig(name, home string) config.Config {
	cfg := config.Default()
	cfg.User.DisplayName = name
	cfg.User.DeviceName = name + "-device"
	cfg.Network.Port = 0
	cfg.Network.ListenAddress = "127.0.0.1"
	cfg.Network.HeartbeatIntervalSeconds = 2
	cfg.Network.ConnectionTimeoutSeconds = 5
	cfg.Transfer.DownloadDir = filepath.Join(home, "downloads")
	return cfg
}

// startNode creates and starts a node. Passing an existing home restarts a
// node with the same identity and database.
func startNode(t *testing.T, name, home string, mutate ...func(*config.Config)) *testNode {
	t.Helper()
	if home == "" {
		home = t.TempDir()
	}
	dirs := platform.Dirs{Config: home, Data: filepath.Join(home, "data"), Log: filepath.Join(home, "logs")}
	if err := dirs.Ensure(); err != nil {
		t.Fatal(err)
	}
	id, _, err := identity.LoadOrCreate(dirs.IdentityFile())
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), dirs.DefaultDatabase())
	if err != nil {
		t.Fatal(err)
	}
	cfg := newConfig(name, home)
	for _, m := range mutate {
		m(&cfg)
	}
	disc := newFakeDiscovery()
	logger := logging.Discard()
	if os.Getenv("LANCHAT_TEST_LOG") != "" {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})).With("node", name)
	}
	n, err := node.New(node.Options{
		Config: cfg, Dirs: dirs, Identity: id, Store: store, Logger: logger,
		Discoverers: []discovery.Discoverer{disc}, DisableNetworkMonitor: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	tn := &testNode{t: t, name: name, home: home, id: id, store: store, disc: disc, Node: n, cfg: cfg}
	t.Cleanup(tn.stop)
	return tn
}

func (n *testNode) stop() {
	if n.Node != nil {
		_ = n.Node.Close()
		_ = n.store.Close()
		n.Node = nil
	}
}

func (n *testNode) ID() identity.PeerID { return n.id.ID() }

// advertiseTo makes `to` discover n at its current port.
func (n *testNode) advertiseTo(to *testNode) {
	self := n.Self()
	to.disc.ch <- discovery.Event{Advert: discovery.Advert{
		Source: discovery.SourceMDNS, Key: "test:" + string(n.ID()), PeerID: n.ID(),
		DisplayName: self.DisplayName, DeviceName: self.DeviceName,
		Addrs:  []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(self.Port))},
		SeenAt: time.Now(), TTL: time.Hour,
	}}
}

// connect makes a and b discover each other.
func connect(a, b *testNode) {
	a.advertiseTo(b)
	b.advertiseTo(a)
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func (n *testNode) connectedTo(o *testNode) bool {
	p, ok := n.Peer(o.ID())
	return ok && p.Connected
}

// pair runs the full interactive pairing flow: a requests, b accepts.
func pair(t *testing.T, a, b *testNode) {
	t.Helper()
	connect(a, b)
	eventually(t, a.name+" and "+b.name+" connected", 10*time.Second, func() bool { return a.connectedTo(b) && b.connectedTo(a) })
	ia, err := a.PairingInfo(b.ID())
	if err != nil {
		t.Fatal(err)
	}
	ib, err := b.PairingInfo(a.ID())
	if err != nil {
		t.Fatal(err)
	}
	if ia.Code != ib.Code {
		t.Fatalf("pairing codes differ: %s vs %s", ia.Code, ib.Code)
	}
	if err := a.RequestPairing(context.Background(), b.ID()); err != nil {
		t.Fatal(err)
	}
	eventually(t, b.name+" sees pairing request", 5*time.Second, func() bool {
		p, _ := b.Peer(a.ID())
		return p.IncomingPairing
	})
	if err := b.RespondPairing(context.Background(), a.ID(), true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "mutual trust", 5*time.Second, func() bool {
		pa, _ := a.Peer(b.ID())
		pb, _ := b.Peer(a.ID())
		return pa.Online() && pb.Online()
	})
}

func (n *testNode) messages(convID string) []storage.Message {
	msgs, err := n.Messages(context.Background(), convID, 0, 500)
	if err != nil {
		n.t.Fatal(err)
	}
	var out []storage.Message
	for _, m := range msgs {
		if m.Kind == storage.MessageText {
			out = append(out, m)
		}
	}
	return out
}

func (n *testNode) hasMessage(convID, body string) bool {
	for _, m := range n.messages(convID) {
		if m.Body == body {
			return true
		}
	}
	return false
}

func (n *testNode) countMessage(convID, body string) int {
	c := 0
	for _, m := range n.messages(convID) {
		if m.Body == body {
			c++
		}
	}
	return c
}

func (n *testNode) message(convID, body string) storage.Message {
	for _, m := range n.messages(convID) {
		if m.Body == body {
			return m
		}
	}
	return storage.Message{}
}
