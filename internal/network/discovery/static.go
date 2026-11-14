package discovery

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Static turns configured host:port entries into adverts. Host names are
// resolved on every refresh so DNS changes are picked up. The peer identity
// behind a static address is unknown until the TLS handshake.
type Static struct {
	entries   []string
	refresh   time.Duration
	log       *slog.Logger
	resolver  *net.Resolver
	refreshCh chan struct{}

	mu     sync.Mutex
	status Status
}

// NewStatic creates a static discoverer.
func NewStatic(entries []string, refresh time.Duration, log *slog.Logger) *Static {
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	return &Static{entries: entries, refresh: refresh, log: log, resolver: net.DefaultResolver,
		refreshCh: make(chan struct{}, 1), status: Status{Name: "static"}}
}

// Name implements Discoverer.
func (s *Static) Name() string { return "static" }

// Refresh implements Discoverer.
func (s *Static) Refresh() {
	select {
	case s.refreshCh <- struct{}{}:
	default:
	}
}

// Status implements Discoverer.
func (s *Static) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Run implements Discoverer.
func (s *Static) Run(ctx context.Context, events chan<- Event) error {
	s.mu.Lock()
	s.status.Active = true
	s.mu.Unlock()
	t := time.NewTicker(s.refresh)
	defer t.Stop()
	for {
		n, lastErr := 0, ""
		for _, e := range s.entries {
			a, err := s.resolve(ctx, e)
			if err != nil {
				lastErr = err.Error()
				s.log.Debug("static peer not resolvable", "entry", e, "err", err)
				continue
			}
			n++
			select {
			case events <- Event{Advert: a}:
			case <-ctx.Done():
				return nil
			}
		}
		s.mu.Lock()
		s.status.Seen = n
		s.status.LastError = lastErr
		s.status.LastSuccess = time.Now()
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-s.refreshCh:
		}
	}
}

func (s *Static) resolve(ctx context.Context, entry string) (Advert, error) {
	host, portStr, err := net.SplitHostPort(entry)
	if err != nil {
		return Advert{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Advert{}, &net.AddrError{Err: "invalid port", Addr: entry}
	}
	var addrs []netip.AddrPort
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, netip.AddrPortFrom(ip, uint16(port)))
	} else {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := s.resolver.LookupNetIP(rctx, "ip", host)
		cancel()
		if err != nil {
			return Advert{}, err
		}
		for _, ip := range ips {
			addrs = append(addrs, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
		}
	}
	return Advert{
		Source: SourceStatic,
		Key:    "static:" + entry,
		Addrs:  SortAddrs(addrs),
		SeenAt: time.Now(),
		TTL:    3*s.refresh + 15*time.Second,
	}, nil
}
