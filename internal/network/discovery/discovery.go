// Package discovery finds other LANChat instances. Three mechanisms are
// supported and can run at the same time:
//
//   - mDNS / DNS-SD on the local link (service _lanchat._tcp.local.)
//   - static peers listed in the configuration (host:port)
//   - an optional managed discovery server for segmented networks
//
// Discovery results are hints only. An Advert says "something claiming to be
// peer X may be reachable at these addresses"; it is never treated as proof
// of identity or reachability. Identity is established by the TLS handshake,
// and trust by explicit user approval.
package discovery

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// ServiceType is the DNS-SD service type.
const ServiceType = "_lanchat._tcp"

// ServiceDomain is the mDNS domain.
const ServiceDomain = "local"

// Source identifies where an advert came from.
type Source string

// Advert sources.
const (
	SourceMDNS    Source = "mdns"
	SourceStatic  Source = "static"
	SourceManaged Source = "managed"
)

// Advert is an unverified announcement of a peer.
type Advert struct {
	Source Source
	// Key uniquely identifies the advert within its source.
	Key string
	// PeerID is the claimed identity; empty for static peers.
	PeerID          identity.PeerID
	DisplayName     string
	DeviceName      string
	Addrs           []netip.AddrPort
	ProtocolVersion int
	Interface       string
	SeenAt          time.Time
	// TTL is how long the advert stays valid without a refresh.
	TTL time.Duration
}

// Event reports a new/refreshed or removed advert.
type Event struct {
	Advert  Advert
	Removed bool
}

// Self describes the local instance for announcements.
type Self struct {
	PeerID          identity.PeerID
	DisplayName     string
	DeviceName      string
	Port            int
	ProtocolVersion int
	Capabilities    []string
}

// Status summarises a discoverer's health for the UI and diagnostics.
type Status struct {
	Name        string
	Active      bool
	Announcing  bool
	LastError   string
	LastSuccess time.Time
	Seen        int
}

// Discoverer is implemented by each discovery mechanism.
type Discoverer interface {
	// Name identifies the mechanism.
	Name() string
	// Run announces the local instance (where applicable) and reports
	// adverts until ctx is cancelled. It must not close events.
	Run(ctx context.Context, events chan<- Event) error
	// Refresh requests an immediate re-query.
	Refresh()
	// Status returns current health information.
	Status() Status
}

// SortAddrs orders candidate addresses for dialing: private IPv4 first,
// then other IPv4, IPv6 unique-local/global, and link-local IPv6 last.
func SortAddrs(addrs []netip.AddrPort) []netip.AddrPort {
	rank := func(a netip.Addr) int {
		switch {
		case a.Is4() && a.IsPrivate():
			return 0
		case a.Is4() && !a.IsLinkLocalUnicast():
			return 1
		case a.Is6() && !a.IsLinkLocalUnicast():
			return 2
		case a.Is4():
			return 3
		default:
			return 4
		}
	}
	out := append([]netip.AddrPort(nil), addrs...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Addr()) < rank(out[j].Addr()) })
	// De-duplicate.
	seen := make(map[netip.AddrPort]bool, len(out))
	dedup := out[:0]
	for _, a := range out {
		if !seen[a] {
			seen[a] = true
			dedup = append(dedup, a)
		}
	}
	return dedup
}
