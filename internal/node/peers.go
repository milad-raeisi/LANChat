package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

const pairingWindow = 10 * time.Minute

type peerState struct {
	id           identity.PeerID
	displayName  string
	deviceName   string
	adverts      map[string]discovery.Advert
	session      *transport.Session
	dialing      bool
	failures     int
	nextDial     time.Time
	lastErr      string
	rooms        map[string]bool
	status       string
	warning      string
	outgoingPair time.Time
	incomingPair bool
	lastPairReq  time.Time
	flushing     bool
	app          string
	addr         string
	lastActive   time.Time
}

type staticTarget struct {
	advert   discovery.Advert
	peerID   identity.PeerID
	dialing  bool
	failures int
	nextDial time.Time
	lastErr  string
	self     bool
}

func (ps *peerState) hasFreshAdvert(now time.Time) bool {
	for _, a := range ps.adverts {
		if now.Sub(a.SeenAt) <= a.TTL {
			return true
		}
	}
	return false
}

func (ps *peerState) freshAddrs(now time.Time) []string {
	var all []netip.AddrPort
	for _, a := range ps.adverts {
		if now.Sub(a.SeenAt) <= a.TTL {
			all = append(all, a.Addrs...)
		}
	}
	all = discovery.SortAddrs(all)
	out := make([]string, 0, len(all))
	for _, a := range all {
		out = append(out, a.String())
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func (n *Node) peerLocked(id identity.PeerID) *peerState {
	ps := n.peers[id]
	if ps == nil {
		ps = &peerState{id: id, adverts: map[string]discovery.Advert{}, lastActive: time.Now()}
		if k, ok := n.known[id]; ok {
			ps.displayName, ps.deviceName = k.DisplayName, k.DeviceName
		}
		n.peers[id] = ps
	}
	return ps
}

func (n *Node) isTrusted(id identity.PeerID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.known[id].Trust == storage.TrustTrusted
}

func (n *Node) sessionFor(id identity.PeerID) *transport.Session {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ps := n.peers[id]; ps != nil && ps.session != nil && ps.session.Alive() {
		return ps.session
	}
	return nil
}

func (n *Node) trustedSession(id identity.PeerID) *transport.Session {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.known[id].Trust != storage.TrustTrusted {
		return nil
	}
	if ps := n.peers[id]; ps != nil && ps.session != nil && ps.session.Alive() {
		return ps.session
	}
	return nil
}

func (n *Node) peerName(id identity.PeerID) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ps := n.peers[id]; ps != nil && ps.displayName != "" {
		return ps.displayName
	}
	if k, ok := n.known[id]; ok && k.DisplayName != "" {
		return k.DisplayName
	}
	return id.Short()
}

// PeerInfo is a snapshot of everything known about a peer.
type PeerInfo struct {
	ID              identity.PeerID
	DisplayName     string
	DeviceName      string
	Trust           storage.TrustState
	Verified        bool
	Connected       bool
	Discovered      bool
	Sources         []string
	Address         string
	Interface       string
	LastSeen        time.Time
	LastError       string
	Rooms           []string
	Warning         string
	OutgoingPairing bool
	IncomingPairing bool
	Fingerprint     string
	App             string
	Status          string
}

// Trusted reports whether the peer is paired.
func (p PeerInfo) Trusted() bool { return p.Trust == storage.TrustTrusted }

// Online reports whether the peer is paired and connected.
func (p PeerInfo) Online() bool { return p.Trusted() && p.Connected }

// Peers returns every known or currently visible peer: trusted peers first
// (online before offline), then unpaired peers, each alphabetically.
func (n *Node) Peers() []PeerInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	seen := map[identity.PeerID]bool{}
	var out []PeerInfo
	for id, ps := range n.peers {
		seen[id] = true
		out = append(out, n.infoLocked(id, ps, now))
	}
	for id := range n.known {
		if !seen[id] {
			out = append(out, n.infoLocked(id, nil, now))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Trusted() != b.Trusted() {
			return a.Trusted()
		}
		if a.Connected != b.Connected {
			return a.Connected
		}
		if strings.ToLower(a.DisplayName) != strings.ToLower(b.DisplayName) {
			return strings.ToLower(a.DisplayName) < strings.ToLower(b.DisplayName)
		}
		return a.ID < b.ID
	})
	return out
}

// Peer returns one peer.
func (n *Node) Peer(id identity.PeerID) (PeerInfo, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ps := n.peers[id]
	_, known := n.known[id]
	if ps == nil && !known {
		return PeerInfo{}, false
	}
	return n.infoLocked(id, ps, time.Now()), true
}

func (n *Node) infoLocked(id identity.PeerID, ps *peerState, now time.Time) PeerInfo {
	k := n.known[id]
	info := PeerInfo{ID: id, DisplayName: k.DisplayName, DeviceName: k.DeviceName, Trust: k.Trust,
		Verified: k.Verified, LastSeen: k.LastSeen, Address: k.LastAddress}
	if info.Trust == "" {
		info.Trust = storage.TrustUnknown
	}
	if len(k.PublicKey) > 0 {
		info.Fingerprint = identity.FormatFingerprint(identity.FingerprintSPKI(k.PublicKey))
	}
	if ps != nil {
		if ps.displayName != "" {
			info.DisplayName = ps.displayName
		}
		if ps.deviceName != "" {
			info.DeviceName = ps.deviceName
		}
		info.Connected = ps.session != nil && ps.session.Alive()
		info.Discovered = ps.hasFreshAdvert(now)
		srcs := map[string]bool{}
		for _, a := range ps.adverts {
			if now.Sub(a.SeenAt) <= a.TTL {
				srcs[string(a.Source)] = true
				if info.Interface == "" {
					info.Interface = a.Interface
				}
				if !info.Connected && len(a.Addrs) > 0 {
					info.Address = a.Addrs[0].String()
				}
				if info.DisplayName == "" {
					info.DisplayName = sanitizeName(a.DisplayName)
				}
			}
		}
		for s := range srcs {
			info.Sources = append(info.Sources, s)
		}
		sort.Strings(info.Sources)
		if info.Connected {
			info.Address = ps.addr
			info.LastSeen = now
			info.Status = ps.status
			if info.Fingerprint == "" {
				info.Fingerprint = identity.FormatFingerprint(identity.Fingerprint(ps.session.PublicKey()))
			}
		}
		info.LastError = ps.lastErr
		info.Warning = ps.warning
		info.App = ps.app
		info.IncomingPairing = ps.incomingPair
		info.OutgoingPairing = !ps.outgoingPair.IsZero() && now.Sub(ps.outgoingPair) < pairingWindow
		for r := range ps.rooms {
			info.Rooms = append(info.Rooms, r)
		}
		sort.Strings(info.Rooms)
	}
	if info.DisplayName == "" {
		info.DisplayName = id.Short()
	}
	return info
}

// ResolvePeer finds peers matching a user-typed reference: a full or
// abbreviated peer ID, or a display name (exact, case-insensitive, then
// prefix). Several matches mean the reference is ambiguous.
func (n *Node) ResolvePeer(query string) []PeerInfo {
	q := strings.TrimPrefix(strings.TrimSpace(query), "@")
	if q == "" {
		return nil
	}
	lq := strings.ToLower(q)
	all := n.Peers()
	var exact, prefix, idMatch []PeerInfo
	for _, p := range all {
		switch {
		case string(p.ID) == lq || (len(lq) >= 4 && strings.HasPrefix(string(p.ID), lq)):
			idMatch = append(idMatch, p)
		case strings.EqualFold(p.DisplayName, q) || strings.EqualFold(p.DisplayName+"#"+p.ID.Short(), q):
			exact = append(exact, p)
		case strings.HasPrefix(strings.ToLower(p.DisplayName), lq):
			prefix = append(prefix, p)
		}
	}
	switch {
	case len(idMatch) > 0:
		return idMatch
	case len(exact) > 0:
		return exact
	default:
		return prefix
	}
}

// --- connection management ------------------------------------------------

func (n *Node) acceptLoop() {
	for {
		conn, err := n.ln.Accept()
		if err != nil {
			if n.ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			n.log.Warn("accept failed", "err", err)
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		if n.sessionCount() >= n.cfg.Network.MaxConnections {
			n.log.Warn("connection limit reached; refusing inbound connection", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		select {
		case n.handshakeSem <- struct{}{}:
		default:
			n.log.Warn("too many concurrent handshakes; refusing connection", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			defer func() { <-n.handshakeSem }()
			s, err := transport.Accept(n.ctx, n.tcfg, conn)
			if err != nil {
				n.log.Debug("inbound handshake failed", "remote", conn.RemoteAddr().String(), "err", err)
				return
			}
			n.register(s, "")
		}()
	}
}

func (n *Node) sessionCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, ps := range n.peers {
		if ps.session != nil {
			c++
		}
	}
	return c
}

func (n *Node) untrustedSessionsLocked() int {
	c := 0
	for id, ps := range n.peers {
		if ps.session != nil && n.known[id].Trust != storage.TrustTrusted {
			c++
		}
	}
	return c
}

// preferredSession implements deterministic duplicate-connection resolution.
// When two sessions exist between the same pair of peers, both sides keep
// the one dialed by the peer with the lexicographically smaller ID; if both
// were dialed by the same side, the newer one wins (the older is stale).
func preferredSession(self, remote identity.PeerID, older, newer *transport.Session) *transport.Session {
	low := self
	if remote < self {
		low = remote
	}
	oPref, nPref := older.DialerID() == low, newer.DialerID() == low
	if oPref && !nPref {
		return older
	}
	return newer
}

// register adopts a freshly established session.
func (n *Node) register(s *transport.Session, staticKey string) {
	pid := s.PeerID()
	hello := s.Hello()
	name, dev := sanitizeName(hello.DisplayName), sanitizeDevice(hello.DeviceName)
	now := time.Now()
	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	if err := n.store.RecordPeerSeen(ctx, storage.PeerSeen{
		ID: pid, PublicKey: s.SPKI(), DisplayName: name, DeviceName: dev, Address: s.RemoteAddr().String(), At: now,
	}); err != nil {
		n.log.Error("cannot record peer", "peer", string(pid), "err", err)
		s.CloseWithError(protocol.CodeProtocolViolation, "internal error")
		return
	}
	known, err := n.store.GetPeer(ctx, pid)
	if err != nil {
		s.CloseWithError(protocol.CodeProtocolViolation, "internal error")
		return
	}

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		s.CloseWithError(protocol.CodeShuttingDown, "shutting down")
		return
	}
	n.known[pid] = known
	trusted := known.Trust == storage.TrustTrusted
	ps := n.peerLocked(pid)
	if !trusted && ps.session == nil && n.untrustedSessionsLocked() >= n.cfg.Security.MaxUntrustedSessions {
		n.mu.Unlock()
		n.log.Warn("too many unpaired peers connected; refusing", "peer", string(pid))
		s.CloseWithError(protocol.CodeTooManyConnections, "too many unpaired connections")
		return
	}
	var replaced *transport.Session
	if old := ps.session; old != nil && old.Alive() {
		if preferredSession(n.id.ID(), pid, old, s) == old {
			n.mu.Unlock()
			s.CloseWithError(protocol.CodeDuplicateSession, "an existing connection is kept")
			return
		}
		replaced = old
	}
	ps.session = s
	ps.failures, ps.lastErr = 0, ""
	ps.displayName, ps.deviceName = name, dev
	ps.app = sanitizeDevice(hello.App)
	ps.addr = s.RemoteAddr().String()
	ps.status = "online"
	ps.lastActive = now
	if replaced == nil {
		ps.rooms = nil
	}
	if staticKey != "" {
		if st := n.statics[staticKey]; st != nil {
			st.peerID = pid
		}
	}
	n.mu.Unlock()

	n.sessWG.Add(1)
	s.Start(n)
	if replaced != nil {
		replaced.CloseWithError(protocol.CodeDuplicateSession, "replaced by a newer connection")
	}
	n.log.Info("peer connected", "peer", string(pid), "trusted", trusted, "outbound", s.Outbound(), "remote", s.RemoteAddr().String())

	n.sendPresence(s)
	if trusted {
		n.afterTrusted(s, true)
	} else {
		n.checkImpersonation(pid, name, dev)
	}
	n.emit(Event{Kind: EventPeerOnline, PeerID: pid, PeerName: name})
}

// SessionClosed implements transport.Handler.
func (n *Node) SessionClosed(s *transport.Session, err error) {
	defer n.sessWG.Done()
	pid := s.PeerID()
	n.mu.Lock()
	ps := n.peers[pid]
	current := ps != nil && ps.session == s
	var name string
	if current {
		ps.session = nil
		ps.incomingPair = false
		ps.rooms = nil
		ps.nextDial = time.Now().Add(backoff(0))
		ps.lastActive = time.Now()
		name = ps.displayName
	}
	closing := n.closed
	n.mu.Unlock()
	if !current {
		return
	}
	n.failTransfersFor(pid, "connection lost")
	if !closing {
		_ = n.store.TouchPeer(context.Background(), pid, time.Now())
	}
	n.log.Info("peer disconnected", "peer", string(pid), "reason", errString(err))
	n.emit(Event{Kind: EventPeerOffline, PeerID: pid, PeerName: name})
	n.wakeConnector()
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// shortError produces a compact, user-facing description of a dial error.
func shortError(err error) string {
	var mm *transport.IdentityMismatchError
	var iv *transport.IncompatibleVersionError
	var re *transport.RemoteError
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.As(err, &mm):
		return "identity mismatch"
	case errors.As(err, &iv):
		return "incompatible LANChat version"
	case errors.As(err, &re):
		return re.Error()
	case strings.Contains(msg, "connection refused"):
		return "connection refused (LANChat not listening or blocked by a firewall)"
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"):
		return "no route to host (different network or isolated by the router)"
	case errors.As(err, &ne) && ne.Timeout(), strings.Contains(msg, "i/o timeout"), errors.Is(err, context.DeadlineExceeded):
		return "timed out (a firewall may be dropping connections)"
	}
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return msg
}

func (n *Node) connectorLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		case <-n.wake:
		}
		n.dialDue()
	}
}

type dialJob struct {
	peer   identity.PeerID
	static string
	addrs  []string
}

func (n *Node) dialDue() {
	now := time.Now()
	var jobs []dialJob
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	sessions, untrusted := 0, 0
	for id, ps := range n.peers {
		if ps.session != nil {
			sessions++
			if n.known[id].Trust != storage.TrustTrusted {
				untrusted++
			}
		}
	}
	for id, ps := range n.peers {
		if sessions+len(jobs) >= n.cfg.Network.MaxConnections {
			break
		}
		if ps.session != nil || ps.dialing || now.Before(ps.nextDial) {
			continue
		}
		addrs := ps.freshAddrs(now)
		if len(addrs) == 0 {
			continue
		}
		if n.known[id].Trust != storage.TrustTrusted {
			if untrusted >= n.cfg.Security.MaxUntrustedSessions {
				continue
			}
			untrusted++
		}
		ps.dialing = true
		jobs = append(jobs, dialJob{peer: id, addrs: addrs})
	}
	for key, st := range n.statics {
		if st.self || st.dialing || now.Before(st.nextDial) || now.Sub(st.advert.SeenAt) > st.advert.TTL {
			continue
		}
		if st.peerID != "" {
			if ps := n.peers[st.peerID]; ps != nil && ps.session != nil {
				continue
			}
		}
		var addrs []string
		for _, a := range st.advert.Addrs {
			addrs = append(addrs, a.String())
		}
		if len(addrs) == 0 {
			continue
		}
		st.dialing = true
		jobs = append(jobs, dialJob{static: key, peer: st.peerID, addrs: addrs})
	}
	n.mu.Unlock()

	for _, j := range jobs {
		j := j
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			select {
			case n.dialSem <- struct{}{}:
			case <-n.ctx.Done():
				n.dialDone(j, nil, n.ctx.Err())
				return
			}
			defer func() { <-n.dialSem }()
			s, err := transport.Dial(n.ctx, n.tcfg, j.addrs, j.peer)
			n.dialDone(j, s, err)
		}()
	}
}

func (n *Node) dialDone(j dialJob, s *transport.Session, err error) {
	now := time.Now()
	var re *transport.RemoteError
	duplicate := errors.As(err, &re) && re.Code == protocol.CodeDuplicateSession
	var mm *transport.IdentityMismatchError
	mismatch := errors.As(err, &mm)
	n.mu.Lock()
	if j.static != "" {
		if st := n.statics[j.static]; st != nil {
			st.dialing = false
			switch {
			case err == nil:
				st.failures, st.lastErr = 0, ""
				st.peerID = s.PeerID()
			case errors.Is(err, transport.ErrSelfConnection):
				st.self = true
			case duplicate:
				st.nextDial = now.Add(backoff(1))
			default:
				st.failures++
				st.lastErr = shortError(err)
				st.nextDial = now.Add(backoff(st.failures))
			}
		}
	} else if ps := n.peers[j.peer]; ps != nil {
		ps.dialing = false
		switch {
		case err == nil:
		case duplicate:
			ps.nextDial = now.Add(backoff(1))
		default:
			ps.failures++
			ps.lastErr = shortError(err)
			ps.nextDial = now.Add(backoff(ps.failures))
			if mismatch {
				ps.warning = fmt.Sprintf("An address advertised for this peer answered with a different identity (%s). Someone may be spoofing discovery announcements.", mm.Got.Short())
			}
		}
	}
	n.mu.Unlock()
	if err != nil {
		if n.ctx.Err() == nil && !duplicate {
			n.log.Debug("dial failed", "peer", string(j.peer), "static", j.static, "err", err)
		}
		if mismatch {
			n.emit(Event{Kind: EventIdentityWarning, PeerID: j.peer, PeerName: n.peerName(j.peer),
				Text: fmt.Sprintf("%s: the device at the advertised address presented a different identity key. The connection was refused.", n.peerName(j.peer))})
		}
		n.emit(Event{Kind: EventPeers})
		return
	}
	n.register(s, j.static)
}

// RefreshDiscovery re-queries discovery and retries unreachable peers now.
func (n *Node) RefreshDiscovery() {
	n.mu.Lock()
	for _, ps := range n.peers {
		ps.failures = 0
		ps.nextDial = time.Time{}
	}
	for _, st := range n.statics {
		st.failures = 0
		st.nextDial = time.Time{}
	}
	discs := append([]discovery.Discoverer(nil), n.discoverers...)
	n.mu.Unlock()
	for _, d := range discs {
		d.Refresh()
	}
	n.wakeConnector()
}

func (n *Node) discoveryEventLoop() {
	for {
		select {
		case <-n.ctx.Done():
			return
		case ev := <-n.discEvents:
			n.handleDiscovery(ev)
		}
	}
}

func (n *Node) handleDiscovery(ev discovery.Event) {
	a := ev.Advert
	if a.PeerID == n.id.ID() {
		return
	}
	now := time.Now()
	changed := false
	n.mu.Lock()
	if a.PeerID == "" {
		if ev.Removed {
			delete(n.statics, a.Key)
		} else if st := n.statics[a.Key]; st != nil {
			st.advert = a
		} else {
			n.statics[a.Key] = &staticTarget{advert: a}
			changed = true
		}
		n.mu.Unlock()
		n.wakeConnector()
		if changed {
			n.emit(Event{Kind: EventPeers})
		}
		return
	}
	ps := n.peerLocked(a.PeerID)
	if ev.Removed {
		if _, ok := ps.adverts[a.Key]; ok {
			delete(ps.adverts, a.Key)
			changed = true
		}
	} else {
		_, existed := ps.adverts[a.Key]
		wasFresh := ps.hasFreshAdvert(now)
		ps.adverts[a.Key] = a
		ps.lastActive = now
		if ps.displayName == "" {
			ps.displayName = sanitizeName(a.DisplayName)
		}
		if !existed {
			changed = true
		}
		if !wasFresh && ps.session == nil && !ps.dialing {
			// A peer (re)appeared: retry immediately. The peer with the
			// larger ID waits briefly so the smaller one usually dials first,
			// which avoids duplicate connections in the common case.
			ps.failures = 0
			ps.nextDial = now
			if n.id.ID() > a.PeerID {
				ps.nextDial = now.Add(1500 * time.Millisecond)
			}
		}
	}
	n.mu.Unlock()
	if changed {
		n.emit(Event{Kind: EventPeers})
	}
	n.wakeConnector()
}

// checkImpersonation warns when a new, unpaired identity uses the same
// display and device name as an already trusted peer.
func (n *Node) checkImpersonation(pid identity.PeerID, name, device string) {
	matches, err := n.store.TrustedPeersNamed(context.Background(), name, device)
	if err != nil {
		return
	}
	for _, m := range matches {
		if m.ID == pid {
			continue
		}
		text := fmt.Sprintf("A new, unpaired device calls itself %q (%s) — the same name as your trusted peer with ID %s, but it uses a DIFFERENT identity key. If %s reset LANChat, verify the pairing code in person before pairing; otherwise this may be an impersonation attempt.",
			name, device, m.ID.Short(), name)
		n.mu.Lock()
		if ps := n.peers[pid]; ps != nil {
			ps.warning = text
		}
		n.mu.Unlock()
		n.log.Warn("possible impersonation", "new_peer", string(pid), "trusted_peer", string(m.ID))
		n.emit(Event{Kind: EventIdentityWarning, PeerID: pid, PeerName: name, Text: text})
		return
	}
}

// --- pairing & trust --------------------------------------------------------

// PairingInfo is shown to the user before approving a peer.
type PairingInfo struct {
	PeerID      identity.PeerID
	DisplayName string
	DeviceName  string
	Fingerprint string
	Code        string
	Address     string
	Warning     string
}

// PairingInfo returns the verification data for a connected peer.
func (n *Node) PairingInfo(id identity.PeerID) (PairingInfo, error) {
	s := n.sessionFor(id)
	if s == nil {
		return PairingInfo{}, ErrNotConnected
	}
	info, _ := n.Peer(id)
	return PairingInfo{
		PeerID: id, DisplayName: info.DisplayName, DeviceName: info.DeviceName,
		Fingerprint: identity.FormatFingerprint(identity.Fingerprint(s.PublicKey())),
		Code:        s.PairingCode(), Address: s.RemoteAddr().String(), Warning: info.Warning,
	}, nil
}

// RequestPairing records the local user's approval of the peer and asks the
// peer to approve us. Trust becomes effective when the peer accepts.
func (n *Node) RequestPairing(_ context.Context, id identity.PeerID) error {
	s := n.sessionFor(id)
	if s == nil {
		return ErrNotConnected
	}
	n.mu.Lock()
	if n.known[id].Trust == storage.TrustTrusted {
		n.mu.Unlock()
		return ErrAlreadyPaired
	}
	ps := n.peerLocked(id)
	ps.outgoingPair = time.Now()
	name := n.name
	n.mu.Unlock()
	if err := s.Send(protocol.TypePairRequest, protocol.PairRequest{DisplayName: name}); err != nil {
		return err
	}
	n.emit(Event{Kind: EventPeers})
	return nil
}

// RespondPairing answers a pending pairing request from a peer.
func (n *Node) RespondPairing(ctx context.Context, id identity.PeerID, accept bool) error {
	n.mu.Lock()
	ps := n.peers[id]
	if ps == nil || !ps.incomingPair {
		n.mu.Unlock()
		return ErrNoPairingRequest
	}
	ps.incomingPair = false
	s := ps.session
	n.mu.Unlock()
	if s == nil || !s.Alive() {
		return ErrNotConnected
	}
	if !accept {
		_ = s.Send(protocol.TypePairReject, protocol.PairResponse{Reason: "declined"})
		n.emit(Event{Kind: EventPeers})
		return nil
	}
	if err := n.setTrust(ctx, id, storage.TrustTrusted, true); err != nil {
		return err
	}
	if err := s.Send(protocol.TypePairAccept, protocol.PairResponse{}); err != nil {
		return err
	}
	n.afterTrusted(s, true)
	n.emit(Event{Kind: EventPairResult, PeerID: id, PeerName: n.peerName(id), Accepted: true})
	return nil
}

// Revoke withdraws trust from a peer. Undelivered messages to the peer are
// marked failed and the peer is informed.
func (n *Node) Revoke(ctx context.Context, id identity.PeerID) error {
	if err := n.setTrust(ctx, id, storage.TrustRevoked, false); err != nil {
		return err
	}
	n.mu.Lock()
	if ps := n.peers[id]; ps != nil {
		ps.outgoingPair = time.Time{}
		ps.incomingPair = false
	}
	n.mu.Unlock()
	if s := n.sessionFor(id); s != nil {
		_ = s.Send(protocol.TypePairRevoke, protocol.PairResponse{Reason: "trust revoked"})
	}
	convs, _ := n.store.FailPendingFor(ctx, id, "peer trust revoked")
	for _, c := range convs {
		n.emit(Event{Kind: EventDelivery, ConversationID: c})
	}
	n.failTransfersFor(id, "peer trust revoked")
	n.emit(Event{Kind: EventPeers})
	return nil
}

func (n *Node) setTrust(ctx context.Context, id identity.PeerID, state storage.TrustState, verified bool) error {
	if err := n.store.SetTrust(ctx, id, state, verified, time.Now()); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrUnknownPeer
		}
		return err
	}
	p, err := n.store.GetPeer(ctx, id)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.known[id] = p
	if ps := n.peers[id]; ps != nil && state == storage.TrustTrusted {
		ps.warning = ""
	}
	n.mu.Unlock()
	n.log.Info("trust changed", "peer", string(id), "trust", string(state))
	return nil
}

// afterTrusted runs when a session with a trusted peer becomes usable.
func (n *Node) afterTrusted(s *transport.Session, includeSent bool) {
	n.sendPresence(s)
	n.flush(s.PeerID(), includeSent)
	n.syncGroupsWith(s)
}

func (n *Node) handlePairRequest(s *transport.Session, req *protocol.PairRequest) {
	pid := s.PeerID()
	if !n.cfg.Security.AllowPairingRequests {
		_ = s.Send(protocol.TypePairReject, protocol.PairResponse{Reason: "this user does not accept pairing requests"})
		return
	}
	now := time.Now()
	n.mu.Lock()
	trusted := n.known[pid].Trust == storage.TrustTrusted
	ps := n.peerLocked(pid)
	if trusted {
		n.mu.Unlock()
		// We already trust this key; confirm so the peer can complete.
		_ = s.Send(protocol.TypePairAccept, protocol.PairResponse{})
		return
	}
	if !ps.lastPairReq.IsZero() && now.Sub(ps.lastPairReq) < 3*time.Second {
		n.mu.Unlock()
		return // rate limit
	}
	ps.lastPairReq = now
	simultaneous := !ps.outgoingPair.IsZero() && now.Sub(ps.outgoingPair) < pairingWindow
	if !simultaneous {
		ps.incomingPair = true
	} else {
		ps.outgoingPair = time.Time{}
	}
	name := ps.displayName
	n.mu.Unlock()

	if simultaneous {
		// Both users approved each other: the local approval was given when
		// RequestPairing was called.
		if err := n.setTrust(context.Background(), pid, storage.TrustTrusted, true); err == nil {
			_ = s.Send(protocol.TypePairAccept, protocol.PairResponse{})
			n.afterTrusted(s, true)
			n.emit(Event{Kind: EventPairResult, PeerID: pid, PeerName: name, Accepted: true})
		}
		return
	}
	n.emit(Event{Kind: EventPairRequest, PeerID: pid, PeerName: name, Code: s.PairingCode()})
}

func (n *Node) handlePairAccept(s *transport.Session) {
	pid := s.PeerID()
	n.mu.Lock()
	ps := n.peers[pid]
	pending := ps != nil && !ps.outgoingPair.IsZero() && time.Since(ps.outgoingPair) < pairingWindow
	if pending {
		ps.outgoingPair = time.Time{}
	}
	already := n.known[pid].Trust == storage.TrustTrusted
	n.mu.Unlock()
	if !pending {
		// An accept we did not ask for must never grant trust.
		if !already {
			n.log.Warn("ignoring unsolicited pairing acceptance", "peer", string(pid))
		}
		return
	}
	if err := n.setTrust(context.Background(), pid, storage.TrustTrusted, true); err != nil {
		n.log.Error("cannot store trust", "err", err)
		return
	}
	n.afterTrusted(s, true)
	n.emit(Event{Kind: EventPairResult, PeerID: pid, PeerName: n.peerName(pid), Accepted: true})
}

func (n *Node) handlePairReject(s *transport.Session, resp *protocol.PairResponse) {
	pid := s.PeerID()
	n.mu.Lock()
	ps := n.peers[pid]
	pending := ps != nil && !ps.outgoingPair.IsZero()
	if pending {
		ps.outgoingPair = time.Time{}
	}
	n.mu.Unlock()
	if pending {
		n.emit(Event{Kind: EventPairResult, PeerID: pid, PeerName: n.peerName(pid), Accepted: false, Text: sanitizeDevice(resp.Reason)})
	}
}

func (n *Node) handlePairRevoke(s *transport.Session) {
	pid := s.PeerID()
	n.notice("warn", "%s removed you from their trusted peers. Messages to them will not be accepted until you pair again.", n.peerName(pid))
}

// Ping measures the round trip time to a connected peer.
func (n *Node) Ping(ctx context.Context, id identity.PeerID) (time.Duration, error) {
	s := n.sessionFor(id)
	if s == nil {
		return 0, ErrNotConnected
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.Ping(ctx)
}

func (n *Node) sendPresence(s *transport.Session) {
	n.mu.Lock()
	p := protocol.Presence{DisplayName: n.name, DeviceName: n.device, Status: "online"}
	for r := range n.rooms {
		p.Rooms = append(p.Rooms, r)
	}
	n.mu.Unlock()
	sort.Strings(p.Rooms)
	if len(p.Rooms) > protocol.MaxRooms {
		p.Rooms = p.Rooms[:protocol.MaxRooms]
	}
	_ = s.Send(protocol.TypePresence, p)
}

func (n *Node) broadcastPresence() {
	n.mu.Lock()
	var sessions []*transport.Session
	for _, ps := range n.peers {
		if ps.session != nil {
			sessions = append(sessions, ps.session)
		}
	}
	n.mu.Unlock()
	for _, s := range sessions {
		n.sendPresence(s)
	}
}

func (n *Node) handlePresence(s *transport.Session, p *protocol.Presence) {
	pid := s.PeerID()
	name, dev := sanitizeName(p.DisplayName), sanitizeDevice(p.DeviceName)
	n.mu.Lock()
	ps := n.peerLocked(pid)
	if ps.session != s {
		n.mu.Unlock()
		return
	}
	renamed := ps.displayName != name || ps.deviceName != dev
	ps.displayName, ps.deviceName, ps.status = name, dev, p.Status
	ps.rooms = make(map[string]bool, len(p.Rooms))
	for _, r := range p.Rooms {
		ps.rooms[r] = true
	}
	n.mu.Unlock()
	if renamed {
		_ = n.store.RecordPeerSeen(context.Background(), storage.PeerSeen{ID: pid, PublicKey: s.SPKI(), DisplayName: name, DeviceName: dev, At: time.Now()})
		if k, err := n.store.GetPeer(context.Background(), pid); err == nil {
			n.mu.Lock()
			n.known[pid] = k
			n.mu.Unlock()
		}
	}
	n.emit(Event{Kind: EventPeers})
}
