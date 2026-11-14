package discoverysrv

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/milad-raeisi/LANChat/internal/managedapi"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

// entry is one registered peer. Only discovery metadata is kept.
type entry struct {
	id              identity.PeerID
	displayName     string
	deviceName      string
	port            int
	protocolVersion int
	addrs           []string // host:port, observed address first
	lastSeen        time.Time
}

func (e *entry) toAPI() managedapi.PeerEntry {
	return managedapi.PeerEntry{
		PeerID:          string(e.id),
		DisplayName:     e.displayName,
		DeviceName:      e.deviceName,
		Addresses:       append([]string(nil), e.addrs...),
		ProtocolVersion: e.protocolVersion,
		LastSeen:        e.lastSeen.UTC().UnixMilli(),
	}
}

// directory is the in-memory presence table.
type directory struct {
	mu    sync.Mutex
	peers map[identity.PeerID]*entry
}

func newDirectory() *directory {
	return &directory{peers: map[identity.PeerID]*entry{}}
}

type upsertResult int

const (
	upsertNew upsertResult = iota
	upsertRefreshed
	upsertFull
)

// upsert registers or refreshes e. New registrations are refused when the
// directory holds max live entries.
func (d *directory) upsert(e *entry, max int, ttl time.Duration) upsertResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.peers[e.id]; ok {
		d.peers[e.id] = e
		return upsertRefreshed
	}
	if len(d.peers) >= max {
		d.pruneLocked(e.lastSeen, ttl, nil)
		if len(d.peers) >= max {
			return upsertFull
		}
	}
	d.peers[e.id] = e
	return upsertNew
}

// remove deletes id and reports whether it was present.
func (d *directory) remove(id identity.PeerID) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.peers[id]
	delete(d.peers, id)
	return ok
}

// others returns the live, authorized, reachable peers other than self,
// most recently seen first, capped at limit.
func (d *directory) others(self identity.PeerID, now time.Time, ttl time.Duration, allowed func(identity.PeerID) bool, limit int) []managedapi.PeerEntry {
	d.mu.Lock()
	list := make([]*entry, 0, len(d.peers))
	for id, e := range d.peers {
		if id == self || len(e.addrs) == 0 || now.Sub(e.lastSeen) > ttl || !allowed(id) {
			continue
		}
		list = append(list, e)
	}
	d.mu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		if !list[i].lastSeen.Equal(list[j].lastSeen) {
			return list[i].lastSeen.After(list[j].lastSeen)
		}
		return list[i].id < list[j].id
	})
	if len(list) > limit {
		list = list[:limit]
	}
	out := make([]managedapi.PeerEntry, len(list))
	for i, e := range list {
		out[i] = e.toAPI()
	}
	return out
}

// live counts entries that have not expired.
func (d *directory) live(now time.Time, ttl time.Duration) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, e := range d.peers {
		if now.Sub(e.lastSeen) <= ttl {
			n++
		}
	}
	return n
}

// prune removes expired entries and, when allowed is non-nil, entries that
// are no longer authorized. It returns the removed peer IDs.
func (d *directory) prune(now time.Time, ttl time.Duration, allowed func(identity.PeerID) bool) (expired, revoked []identity.PeerID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pruneLocked(now, ttl, allowed)
}

func (d *directory) pruneLocked(now time.Time, ttl time.Duration, allowed func(identity.PeerID) bool) (expired, revoked []identity.PeerID) {
	for id, e := range d.peers {
		switch {
		case now.Sub(e.lastSeen) > ttl:
			delete(d.peers, id)
			expired = append(expired, id)
		case allowed != nil && !allowed(id):
			delete(d.peers, id)
			revoked = append(revoked, id)
		}
	}
	return expired, revoked
}

// usableAddr normalizes a candidate address and reports whether other
// peers could plausibly reach it: loopback, unspecified, multicast,
// link-local and broadcast addresses are rejected.
func usableAddr(a netip.Addr) (netip.Addr, bool) {
	a = a.Unmap().WithZone("")
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	return a, true
}

// candidateAddrs builds the address list for an entry: the observed source
// address first, then the reported addresses, filtered, deduplicated and
// capped at managedapi.MaxAddresses, formatted as host:port.
func candidateAddrs(observed netip.Addr, reported []string, port int) []string {
	seen := make(map[netip.Addr]struct{}, len(reported)+1)
	out := make([]string, 0, len(reported)+1)
	ps := strconv.Itoa(port)
	add := func(a netip.Addr) {
		a, ok := usableAddr(a)
		if !ok || len(out) >= managedapi.MaxAddresses {
			return
		}
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = struct{}{}
		out = append(out, net.JoinHostPort(a.String(), ps))
	}
	add(observed)
	for _, s := range reported {
		if a, err := netip.ParseAddr(s); err == nil {
			add(a)
		}
	}
	return out
}
