// Package node is the LANChat application core. A Node owns the TCP/TLS
// listener, discovery, peer sessions, trust decisions, messaging, groups and
// file transfers, and publishes state changes as Events for the UI.
//
// Concurrency model: n.mu guards in-memory state only. Network writes are
// queued (non-blocking) and database calls are never made while holding
// n.mu. Frames from one peer are handled sequentially on that session's read
// goroutine, preserving per-peer ordering.
package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
	"github.com/milad-raeisi/LANChat/internal/transfer"
)

// Capabilities advertised by this build.
var Capabilities = []string{"chat", "rooms", "groups", "files"}

// Errors returned by Node operations.
var (
	ErrNotPaired        = errors.New("not paired with this peer; pair first to exchange messages")
	ErrNotConnected     = errors.New("peer is not connected right now")
	ErrAlreadyPaired    = errors.New("already paired with this peer")
	ErrNoPairingRequest = errors.New("there is no pending pairing request from this peer")
	ErrUnknownPeer      = errors.New("unknown peer")
	ErrEmptyMessage     = errors.New("message is empty")
	ErrPortInUse        = errors.New("the LANChat port is already in use")
	ErrClosed           = errors.New("LANChat is shutting down")
)

// Options configures a Node.
type Options struct {
	Config   config.Config
	Dirs     platform.Dirs
	Identity *identity.Identity
	Store    *storage.Store
	Logger   *slog.Logger
	// Discoverers replaces the discovery mechanisms derived from the
	// configuration. Integration tests use it to inject static discovery.
	Discoverers []discovery.Discoverer
	// DisableNetworkMonitor turns off interface polling (tests).
	DisableNetworkMonitor bool
}

// Node is a running LANChat instance.
type Node struct {
	cfg   config.Config
	dirs  platform.Dirs
	id    *identity.Identity
	store *storage.Store
	log   *slog.Logger
	opts  Options
	tcfg  *transport.Config

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	sessWG sync.WaitGroup
	discWG sync.WaitGroup

	ln   net.Listener
	port int

	events       chan Event
	wake         chan struct{}
	handshakeSem chan struct{}
	dialSem      chan struct{}
	discEvents   chan discovery.Event

	mu          sync.Mutex
	name        string
	device      string
	peers       map[identity.PeerID]*peerState
	statics     map[string]*staticTarget
	known       map[identity.PeerID]storage.Peer
	rooms       map[string]bool
	transfers   map[string]*transferState
	ifaces      []netif.Interface
	ifaceErr    string
	netKey      string
	netChanged  time.Time
	discoverers []discovery.Discoverer
	discCancel  context.CancelFunc
	started     bool
	closed      bool
	startedAt   time.Time
}

// New validates options and creates a Node. Call Start to run it.
func New(opts Options) (*Node, error) {
	if opts.Identity == nil || opts.Store == nil {
		return nil, errors.New("node requires an identity and a store")
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	n := &Node{
		cfg: opts.Config, dirs: opts.Dirs, id: opts.Identity, store: opts.Store, log: opts.Logger, opts: opts,
		events:       make(chan Event, 2048),
		wake:         make(chan struct{}, 1),
		handshakeSem: make(chan struct{}, 16),
		dialSem:      make(chan struct{}, 4),
		discEvents:   make(chan discovery.Event, 256),
		name:         opts.Config.User.DisplayName,
		device:       opts.Config.User.DeviceName,
		peers:        make(map[identity.PeerID]*peerState),
		statics:      make(map[string]*staticTarget),
		known:        make(map[identity.PeerID]storage.Peer),
		rooms:        make(map[string]bool),
		transfers:    make(map[string]*transferState),
	}
	tcfg, err := transport.NewConfig(opts.Identity, n.localHello, opts.Config.ConnectionTimeout(), opts.Config.HeartbeatInterval())
	if err != nil {
		return nil, err
	}
	n.tcfg = tcfg
	return n, nil
}

func (n *Node) localHello() protocol.Hello {
	n.mu.Lock()
	defer n.mu.Unlock()
	return protocol.Hello{
		DisplayName:  n.name,
		DeviceName:   n.device,
		ListenPort:   n.port,
		App:          buildinfo.AppName + "/" + buildinfo.Short(),
		Capabilities: Capabilities,
	}
}

// ListenAddress returns the address the listener should bind, following
// the configured address families. A single dual-stack socket is used when
// both families are enabled, so IPv4 and IPv6 never compete for the port.
func ListenAddress(cfg config.NetworkConfig) (network, addr string) {
	port := strconv.Itoa(cfg.Port)
	switch {
	case cfg.ListenAddress != "":
		return "tcp", net.JoinHostPort(cfg.ListenAddress, port)
	case cfg.EnableIPv4 && cfg.EnableIPv6:
		return "tcp", ":" + port
	case cfg.EnableIPv4:
		return "tcp4", "0.0.0.0:" + port
	default:
		return "tcp6", "[::]:" + port
	}
}

// Start binds the listener and starts discovery and background loops.
func (n *Node) Start(parent context.Context) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return errors.New("node already started")
	}
	n.started = true
	n.startedAt = time.Now()
	n.mu.Unlock()

	n.ctx, n.cancel = context.WithCancel(parent)
	ctx := n.ctx

	peers, err := n.store.ListPeers(ctx)
	if err != nil {
		return fmt.Errorf("load peers: %w", err)
	}
	rooms, err := n.store.JoinedRooms(ctx)
	if err != nil {
		return fmt.Errorf("load rooms: %w", err)
	}
	n.mu.Lock()
	for _, p := range peers {
		n.known[p.ID] = p
	}
	for _, r := range rooms {
		n.rooms[r] = true
	}
	n.mu.Unlock()

	network, addr := ListenAddress(n.cfg.Network)
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) || isAddrInUse(err) {
			return fmt.Errorf("%w: %s (another program, or another LANChat profile, is listening; choose a different network.port)", ErrPortInUse, addr)
		}
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	n.ln = ln
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		n.mu.Lock()
		n.port = ta.Port
		n.mu.Unlock()
	}
	n.log.Info("listening", "addr", ln.Addr().String(), "peer_id", string(n.id.ID()))

	n.refreshInterfaces()
	if dir := n.cfg.DownloadDir(n.dirs); dir != "" {
		if c := transfer.CleanupStale(dir); c > 0 {
			n.log.Info("removed incomplete downloads", "count", c)
		}
	}
	if convs, err := n.store.ExpireDeliveries(ctx, time.Now().Add(-n.cfg.OfflineQueueTTL()), n.cfg.Chat.MaxRetryAttempts); err == nil && len(convs) > 0 {
		n.log.Info("expired undelivered messages", "conversations", len(convs))
	}

	n.goLoop(n.acceptLoop)
	n.goLoop(n.connectorLoop)
	n.goLoop(n.maintenanceLoop)
	n.goLoop(n.discoveryEventLoop)
	if !n.opts.DisableNetworkMonitor {
		n.goLoop(n.networkMonitorLoop)
	}
	n.startDiscovery()
	return nil
}

func isAddrInUse(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) {
		var se *syscall.Errno
		if errors.As(oe.Err, &se) {
			return *se == syscall.EADDRINUSE
		}
		// Windows: WSAEADDRINUSE (10048)
		return contains(oe.Error(), "address already in use") || contains(oe.Error(), "Only one usage of each socket address")
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) <= len(s) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func (n *Node) goLoop(f func()) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		f()
	}()
}

// Close stops the node gracefully: discovery is withdrawn (mDNS goodbye),
// peers are told we are leaving, transfers are aborted and goroutines are
// awaited with a bounded timeout.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed || !n.started {
		n.closed = true
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	var sessions []*transport.Session
	for _, ps := range n.peers {
		if ps.session != nil {
			sessions = append(sessions, ps.session)
		}
	}
	var transfers []*transferState
	for _, t := range n.transfers {
		transfers = append(transfers, t)
	}
	n.mu.Unlock()

	n.cancel()
	if n.ln != nil {
		_ = n.ln.Close()
	}
	for _, s := range sessions {
		s.CloseWithError(protocol.CodeShuttingDown, "peer is shutting down")
	}
	for _, t := range transfers {
		t.abort("LANChat closed")
	}
	waitTimeout(&n.discWG, 3*time.Second)
	waitTimeout(&n.wg, 3*time.Second)
	waitTimeout(&n.sessWG, 2*time.Second)
	if !n.cfg.Chat.SaveHistory {
		if _, err := n.store.DeleteHistory(context.Background(), ""); err != nil {
			n.log.Warn("could not delete session history", "err", err)
		}
	}
	n.log.Info("stopped")
	return nil
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// Events returns the event stream. Events are hints for the UI to refresh;
// when the UI falls behind, events are dropped rather than blocking the
// network, so consumers should re-query state on each event.
func (n *Node) Events() <-chan Event { return n.events }

func (n *Node) emit(ev Event) {
	select {
	case n.events <- ev:
	default:
		n.log.Debug("event dropped", "kind", ev.Kind)
	}
}

func (n *Node) notice(level, format string, args ...any) {
	n.emit(Event{Kind: EventNotice, Level: level, Text: fmt.Sprintf(format, args...)})
}

func (n *Node) wakeConnector() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// SelfInfo describes the local user.
type SelfInfo struct {
	ID          identity.PeerID
	DisplayName string
	DeviceName  string
	Fingerprint string
	Port        int
	ListenAddr  string
	Mode        string
	StartedAt   time.Time
}

// Self returns information about the local user.
func (n *Node) Self() SelfInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	addr := ""
	if n.ln != nil {
		addr = n.ln.Addr().String()
	}
	return SelfInfo{
		ID: n.id.ID(), DisplayName: n.name, DeviceName: n.device,
		Fingerprint: identity.FormatFingerprint(n.id.Fingerprint()),
		Port:        n.port, ListenAddr: addr, Mode: n.cfg.Network.Mode, StartedAt: n.startedAt,
	}
}

// Config returns the configuration the node runs with.
func (n *Node) Config() config.Config { return n.cfg }

// NetworkStatus summarises network health.
type NetworkStatus struct {
	Interfaces     []netif.Interface
	InterfaceError string
	ListenAddr     string
	Port           int
	Discovery      []discovery.Status
	Sessions       int
	TrustedOnline  int
	Discovered     int
	LastChange     time.Time
}

// NetworkStatus returns current network information. It contains no
// secrets and is safe to display.
func (n *Node) NetworkStatus() NetworkStatus {
	n.mu.Lock()
	st := NetworkStatus{
		Interfaces:     append([]netif.Interface(nil), n.ifaces...),
		InterfaceError: n.ifaceErr,
		Port:           n.port,
		LastChange:     n.netChanged,
	}
	if n.ln != nil {
		st.ListenAddr = n.ln.Addr().String()
	}
	now := time.Now()
	for pid, ps := range n.peers {
		if ps.session != nil {
			st.Sessions++
			if n.known[pid].Trust == storage.TrustTrusted {
				st.TrustedOnline++
			}
		}
		if ps.hasFreshAdvert(now) {
			st.Discovered++
		}
	}
	discs := append([]discovery.Discoverer(nil), n.discoverers...)
	n.mu.Unlock()
	for _, d := range discs {
		st.Discovery = append(st.Discovery, d.Status())
	}
	return st
}

// sanitizeName cleans an untrusted display name for storage and display.
func sanitizeName(s string) string {
	s = textsafe.Line(s, config.MaxDisplayNameRunes)
	if s == "" {
		return "Unnamed"
	}
	return s
}

func sanitizeDevice(s string) string { return textsafe.Line(s, config.MaxDeviceNameRunes) }

// backoff returns the delay before the next connection attempt after the
// given number of consecutive failures: exponential with ±20% jitter,
// capped at one minute, then a slow five-minute cadence.
func backoff(failures int) time.Duration {
	var d time.Duration
	switch {
	case failures <= 0:
		d = time.Second
	case failures > 8:
		d = 5 * time.Minute
	default:
		d = time.Second << min(failures, 6)
		if d > time.Minute {
			d = time.Minute
		}
	}
	jitter := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(d) * jitter)
}
