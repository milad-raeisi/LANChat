package discovery

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brutella/dnssd"
	dnslog "github.com/brutella/dnssd/log"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

var silenceOnce sync.Once

// silenceLibraryLogs stops the mDNS library from printing to stdout, which
// would corrupt the terminal UI.
func silenceLibraryLogs() {
	silenceOnce.Do(func() {
		dnslog.Info.SetOutput(io.Discard)
		dnslog.Debug.SetOutput(io.Discard)
	})
}

// TXT record keys.
const (
	txtVersion = "v"
	txtID      = "id"
	txtName    = "name"
	txtDevice  = "dev"
	txtCaps    = "caps"
)

// MDNS announces and browses _lanchat._tcp.local. on selected interfaces.
type MDNS struct {
	self      Self
	ifaces    []string
	refresh   time.Duration
	log       *slog.Logger
	refreshCh chan struct{}

	mu     sync.Mutex
	status Status
}

// NewMDNS creates an mDNS discoverer. ifaces limits announcement and
// accepted results to those interfaces (empty = all multicast interfaces).
func NewMDNS(self Self, ifaces []string, refresh time.Duration, log *slog.Logger) *MDNS {
	silenceLibraryLogs()
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	return &MDNS{self: self, ifaces: ifaces, refresh: refresh, log: log,
		refreshCh: make(chan struct{}, 1), status: Status{Name: "mDNS"}}
}

// Name implements Discoverer.
func (m *MDNS) Name() string { return "mDNS" }

// Refresh implements Discoverer.
func (m *MDNS) Refresh() {
	select {
	case m.refreshCh <- struct{}{}:
	default:
	}
}

// Status implements Discoverer.
func (m *MDNS) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *MDNS) setStatus(f func(*Status)) {
	m.mu.Lock()
	f(&m.status)
	m.mu.Unlock()
}

// InstanceName returns the DNS-SD instance name for a peer. It contains no
// personal information; the display name travels in the TXT record.
func InstanceName(id identity.PeerID) string {
	s := string(id)
	if len(s) > 12 {
		s = s[:12]
	}
	return "LANChat-" + s
}

// TXT builds the TXT record for self.
func TXT(self Self) map[string]string {
	return map[string]string{
		txtVersion: strconv.Itoa(self.ProtocolVersion),
		txtID:      string(self.PeerID),
		txtName:    truncateUTF8(self.DisplayName, 200),
		txtDevice:  truncateUTF8(self.DeviceName, 200),
		txtCaps:    strings.Join(self.Capabilities, ","),
	}
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

// Run implements Discoverer.
func (m *MDNS) Run(ctx context.Context, events chan<- Event) error {
	m.setStatus(func(s *Status) { s.Active = true })
	defer m.setStatus(func(s *Status) { s.Active = false; s.Announcing = false })

	var wg sync.WaitGroup
	if m.self.Port > 0 {
		cfg := dnssd.Config{
			Name:   InstanceName(m.self.PeerID),
			Type:   ServiceType,
			Domain: ServiceDomain,
			Port:   m.self.Port,
			Text:   TXT(m.self),
			Ifaces: m.ifaces,
		}
		svc, err := dnssd.NewService(cfg)
		if err != nil {
			m.setStatus(func(s *Status) { s.LastError = "create service: " + err.Error() })
			return fmt.Errorf("mDNS service: %w", err)
		}
		rp, err := dnssd.NewResponder()
		if err != nil {
			m.setStatus(func(s *Status) { s.LastError = "open multicast socket: " + err.Error() })
			return fmt.Errorf("mDNS responder: %w", err)
		}
		if _, err := rp.Add(svc); err != nil {
			m.setStatus(func(s *Status) { s.LastError = "register service: " + err.Error() })
			return fmt.Errorf("mDNS register: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.setStatus(func(s *Status) { s.Announcing = true })
			// Respond probes, announces, answers queries, and sends goodbye
			// packets when ctx is cancelled.
			if err := rp.Respond(ctx); err != nil && ctx.Err() == nil {
				m.log.Warn("mDNS responder stopped", "err", err)
				m.setStatus(func(s *Status) { s.Announcing = false; s.LastError = "announce: " + err.Error() })
			}
		}()
	}

	// Continuous querying per RFC 6762 §5.2: the first queries go out after
	// 1 s, 2 s, 4 s … and the interval doubles up to the refresh interval.
	// Each round sends a fresh query; the library reports services only in
	// answer to its own queries, so this schedule is what makes instances
	// that start at the same time find each other quickly while keeping
	// multicast traffic low afterwards. Refresh() restarts the fast schedule.
	fullName := ServiceType + "." + ServiceDomain + "."
	interval := time.Second
	for ctx.Err() == nil {
		lookupCtx, cancel := context.WithTimeout(ctx, interval)
		reset := make(chan struct{}, 1)
		go func() {
			select {
			case <-m.refreshCh:
				reset <- struct{}{}
				cancel()
			case <-lookupCtx.Done():
			}
		}()
		seen := 0
		err := dnssd.LookupType(lookupCtx, fullName,
			func(e dnssd.BrowseEntry) {
				if a, ok := m.advertFrom(e); ok {
					seen++
					select {
					case events <- Event{Advert: a}:
					case <-ctx.Done():
					}
				}
			},
			func(e dnssd.BrowseEntry) {
				if a, ok := m.advertFrom(e); ok {
					select {
					case events <- Event{Advert: a, Removed: true}:
					case <-ctx.Done():
					}
				}
			})
		cancel()
		if err != nil && ctx.Err() == nil && lookupCtx.Err() == nil {
			m.setStatus(func(s *Status) { s.LastError = "browse: " + err.Error() })
			m.log.Warn("mDNS browse failed", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			continue
		}
		m.setStatus(func(s *Status) {
			s.LastSuccess = time.Now()
			s.Seen = seen
			if s.Announcing {
				s.LastError = ""
			}
		})
		select {
		case <-reset:
			interval = time.Second
		default:
			interval = min(interval*2, m.refresh)
		}
	}
	wg.Wait()
	return nil
}

func (m *MDNS) advertFrom(e dnssd.BrowseEntry) (Advert, bool) {
	if len(m.ifaces) > 0 && e.IfaceName != "" && !contains(m.ifaces, e.IfaceName) {
		m.log.Debug("mDNS result ignored: interface not selected", "instance", e.Name, "iface", e.IfaceName)
		return Advert{}, false
	}
	return ParseBrowseEntry(e, m.refresh)
}

// ParseBrowseEntry converts a DNS-SD result into an Advert, validating every
// field. Entries without a valid peer ID are ignored.
func ParseBrowseEntry(e dnssd.BrowseEntry, refresh time.Duration) (Advert, bool) {
	id, err := identity.ParsePeerID(e.Text[txtID])
	if err != nil {
		return Advert{}, false
	}
	if e.Port < 1 || e.Port > 65535 {
		return Advert{}, false
	}
	a := Advert{
		Source:      SourceMDNS,
		Key:         "mdns:" + string(id) + "@" + e.IfaceName,
		PeerID:      id,
		DisplayName: truncateUTF8(e.Text[txtName], 256),
		DeviceName:  truncateUTF8(e.Text[txtDevice], 256),
		Interface:   e.IfaceName,
		SeenAt:      time.Now(),
		TTL:         3*refresh + 15*time.Second,
	}
	if v, err := strconv.Atoi(e.Text[txtVersion]); err == nil {
		a.ProtocolVersion = v
	}
	for _, ip := range e.IPs {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
			continue
		}
		if addr.Is6() && addr.IsLinkLocalUnicast() {
			if e.IfaceName == "" {
				continue
			}
			addr = addr.WithZone(e.IfaceName)
		}
		a.Addrs = append(a.Addrs, netip.AddrPortFrom(addr, uint16(e.Port)))
	}
	if len(a.Addrs) == 0 {
		return Advert{}, false
	}
	a.Addrs = SortAddrs(a.Addrs)
	return a, true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ProbeMulticast checks that an mDNS multicast socket can be opened. It
// proves only socket initialisation, not that traffic reaches other hosts.
func ProbeMulticast() error {
	silenceLibraryLogs()
	conn, err := dnssd.NewMDNSConn()
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// Browse performs a one-shot browse for d and returns the adverts found,
// excluding exclude (normally the local peer ID).
func Browse(ctx context.Context, d time.Duration, exclude identity.PeerID) ([]Advert, error) {
	silenceLibraryLogs()
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var (
		mu  sync.Mutex
		out = map[string]Advert{}
	)
	err := dnssd.LookupType(ctx, ServiceType+"."+ServiceDomain+".", func(e dnssd.BrowseEntry) {
		if a, ok := ParseBrowseEntry(e, d); ok && a.PeerID != exclude {
			mu.Lock()
			out[a.Key] = a
			mu.Unlock()
		}
	}, func(dnssd.BrowseEntry) {})
	if err != nil && ctx.Err() == nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	list := make([]Advert, 0, len(out))
	for _, a := range out {
		list = append(list, a)
	}
	return list, nil
}

// ProbeResult is the outcome of ProbeAnnounceAndBrowse.
type ProbeResult struct {
	// Announced is true when the probe service was registered (probing and
	// announcement completed without error).
	Announced bool
	// SelfSeen is true when the probe announcement was received back by a
	// browse on this host, proving the announce/browse path works locally.
	SelfSeen bool
	// Peers lists other LANChat instances discovered during the probe.
	Peers []Advert
	// Err is the first error encountered.
	Err error
}

// ProbeAnnounceAndBrowse publishes a temporary probe service for d and
// browses at the same time. The probe carries no peer ID, so LANChat peers
// ignore it; it only proves that advertisement works. exclude is the local
// peer ID, omitted from Peers.
func ProbeAnnounceAndBrowse(ctx context.Context, d time.Duration, port int, exclude identity.PeerID) ProbeResult {
	silenceLibraryLogs()
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var res ProbeResult
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	probeName := fmt.Sprintf("LANChat-doctor-%x", rnd)
	svc, err := dnssd.NewService(dnssd.Config{Name: probeName, Type: ServiceType, Domain: ServiceDomain, Port: port,
		Text: map[string]string{"probe": "1"}})
	if err != nil {
		res.Err = err
		return res
	}
	rp, err := dnssd.NewResponder()
	if err != nil {
		res.Err = err
		return res
	}
	if _, err := rp.Add(svc); err != nil {
		res.Err = err
		return res
	}
	respondErr := make(chan error, 1)
	go func() { respondErr <- rp.Respond(ctx) }()

	var mu sync.Mutex
	found := map[string]Advert{}
	err = dnssd.LookupType(ctx, ServiceType+"."+ServiceDomain+".", func(e dnssd.BrowseEntry) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(e.Name, probeName) {
			res.SelfSeen = true
			return
		}
		if a, ok := ParseBrowseEntry(e, d); ok && a.PeerID != exclude {
			found[string(a.PeerID)] = a
		}
	}, func(dnssd.BrowseEntry) {})
	if err != nil && ctx.Err() == nil && res.Err == nil {
		res.Err = err
	}
	<-ctx.Done()
	if rerr := <-respondErr; rerr != nil && !errors.Is(rerr, context.Canceled) && !errors.Is(rerr, context.DeadlineExceeded) {
		if res.Err == nil {
			res.Err = rerr
		}
	} else {
		res.Announced = true
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range found {
		res.Peers = append(res.Peers, a)
	}
	return res
}
