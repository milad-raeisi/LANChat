package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/milad-raeisi/LANChat/internal/managedapi"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// Managed registers with a lanchat-discovery server and turns its directory
// into adverts. Chat traffic never flows through the server.
type Managed struct {
	server    string
	self      Self
	addrs     func() []netip.Addr
	refresh   time.Duration
	log       *slog.Logger
	client    *http.Client
	refreshCh chan struct{}

	mu     sync.Mutex
	status Status
}

// NewManaged creates a managed-discovery client. addrs returns the local
// addresses to announce (the server also records the observed source address).
func NewManaged(server string, tlsConf *tls.Config, self Self, addrs func() []netip.Addr, refresh time.Duration, log *slog.Logger) *Managed {
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:       tlsConf,
		ForceAttemptHTTP2:     false,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          2,
		IdleConnTimeout:       2 * refresh,
		Proxy:                 nil, // never send LAN discovery traffic through an HTTP proxy
	}
	return &Managed{
		server: server, self: self, addrs: addrs, refresh: refresh, log: log,
		client:    &http.Client{Transport: tr, Timeout: 20 * time.Second},
		refreshCh: make(chan struct{}, 1),
		status:    Status{Name: "managed"},
	}
}

// Name implements Discoverer.
func (m *Managed) Name() string { return "managed" }

// Refresh implements Discoverer.
func (m *Managed) Refresh() {
	select {
	case m.refreshCh <- struct{}{}:
	default:
	}
}

// Status implements Discoverer.
func (m *Managed) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// Run implements Discoverer.
func (m *Managed) Run(ctx context.Context, events chan<- Event) error {
	m.mu.Lock()
	m.status.Active = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.status.Active, m.status.Announcing = false, false
		m.mu.Unlock()
	}()
	known := map[string]Advert{}
	backoff := time.Second
	for {
		resp, err := m.Announce(ctx)
		wait := m.refresh
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			m.log.Warn("managed discovery announce failed", "server", m.server, "err", err)
			m.mu.Lock()
			m.status.Announcing = false
			m.status.LastError = err.Error()
			m.mu.Unlock()
			wait = backoff
			if backoff < m.refresh {
				backoff *= 2
			}
		} else {
			backoff = time.Second
			ttl := time.Duration(resp.TTLSeconds) * time.Second
			if ttl <= 0 {
				ttl = 3 * m.refresh
			}
			current := map[string]Advert{}
			for _, p := range resp.Peers {
				if err := p.Validate(); err != nil {
					continue
				}
				if identity.PeerID(p.PeerID) == m.self.PeerID {
					continue
				}
				a := Advert{
					Source: SourceManaged, Key: "managed:" + p.PeerID, PeerID: identity.PeerID(p.PeerID),
					DisplayName: p.DisplayName, DeviceName: p.DeviceName, ProtocolVersion: p.ProtocolVersion,
					SeenAt: time.Now(), TTL: ttl + m.refresh,
				}
				for _, s := range p.Addresses {
					if ap, err := netip.ParseAddrPort(s); err == nil {
						a.Addrs = append(a.Addrs, ap)
					}
				}
				current[a.Key] = a
				select {
				case events <- Event{Advert: a}:
				case <-ctx.Done():
					return nil
				}
			}
			for k, a := range known {
				if _, ok := current[k]; !ok {
					select {
					case events <- Event{Advert: a, Removed: true}:
					case <-ctx.Done():
						return nil
					}
				}
			}
			known = current
			m.mu.Lock()
			m.status.Announcing = true
			m.status.LastError = ""
			m.status.LastSuccess = time.Now()
			m.status.Seen = len(current)
			m.mu.Unlock()
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
			continue
		case <-m.refreshCh:
			continue
		}
		break
	}
	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = m.Withdraw(wctx)
	return nil
}

// Announce sends one announcement and returns the directory.
func (m *Managed) Announce(ctx context.Context) (*managedapi.AnnounceResponse, error) {
	req := managedapi.AnnounceRequest{
		DisplayName: m.self.DisplayName, DeviceName: m.self.DeviceName, Port: m.self.Port,
		ProtocolVersion: m.self.ProtocolVersion, Capabilities: m.self.Capabilities,
	}
	if m.addrs != nil {
		for _, a := range m.addrs() {
			if len(req.Addresses) >= managedapi.MaxAddresses {
				break
			}
			req.Addresses = append(req.Addresses, a.String())
		}
	}
	var resp managedapi.AnnounceResponse
	if err := m.post(ctx, managedapi.PathAnnounce, req, &resp); err != nil {
		return nil, err
	}
	if len(resp.Peers) > managedapi.MaxPeersReturn {
		resp.Peers = resp.Peers[:managedapi.MaxPeersReturn]
	}
	return &resp, nil
}

// Withdraw removes the local instance from the directory.
func (m *Managed) Withdraw(ctx context.Context) error {
	return m.post(ctx, managedapi.PathWithdraw, struct{}{}, nil)
}

func (m *Managed) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+m.server+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "LANChat")
	res, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, managedapi.MaxRespBytes))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		var er managedapi.ErrorResponse
		_ = json.Unmarshal(data, &er)
		if er.Error == "" {
			er.Error = http.StatusText(res.StatusCode)
		}
		if res.StatusCode == http.StatusForbidden {
			return fmt.Errorf("discovery server refused this identity: %s", er.Error)
		}
		return fmt.Errorf("discovery server: %s (HTTP %d)", er.Error, res.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("discovery server sent an invalid response")
	}
	return nil
}
