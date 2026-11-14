package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// Pairing (see docs/security.md):
//
//	initiator                                 responder
//	pair.request{commit = H(Ni)}  ───────────►  stores commit, picks Nr
//	                              ◄───────────  pair.nonce{Nr}
//	pair.reveal{Ni}               ───────────►  checks H(Ni) == commit
//	code = SAS(keys, TLS exporter, Ni, Nr)       code = SAS(…, Ni, Nr)
//	user compares codes, approves                user compares codes, approves
//	pair.accept                   ◄──────────►  pair.accept
//
// Trust is granted on each side only after BOTH the local user approved and
// the remote side sent pair.accept, on the same authenticated session.
// Because the initiator commits to Ni before seeing Nr, and the responder
// sends Nr before seeing Ni, a man-in-the-middle cannot grind sessions in
// the background to make the codes on its two sessions match: every attempt
// is a fresh pairing request that the users see.

const pairingWindow = 10 * time.Minute

type pairRole int

const (
	roleInitiator pairRole = iota + 1
	roleResponder
)

type pairState struct {
	role           pairRole
	session        *transport.Session
	myNonce        []byte
	peerNonce      []byte
	commit         string // responder: the initiator's commitment
	code           string // set once both nonces are known
	localApproved  bool
	remoteApproved bool
	started        time.Time
}

// ErrCodeNotReady is returned when approving before the code exists.
var ErrCodeNotReady = errors.New("the verification code is not ready yet; wait a moment")

func randNonce() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

// PairingInfo is shown to the user before approving a peer.
type PairingInfo struct {
	PeerID      identity.PeerID
	DisplayName string
	DeviceName  string
	Fingerprint string
	// Code is the six-digit verification code, or "" until the
	// commit-then-reveal exchange has completed.
	Code    string
	Address string
	Warning string
	// Initiator is true when the local user started the pairing.
	Initiator bool
}

// PairingInfo returns the verification data for a connected peer.
func (n *Node) PairingInfo(id identity.PeerID) (PairingInfo, error) {
	s := n.sessionFor(id)
	if s == nil {
		return PairingInfo{}, ErrNotConnected
	}
	info, _ := n.Peer(id)
	pi := PairingInfo{
		PeerID: id, DisplayName: info.DisplayName, DeviceName: info.DeviceName,
		Fingerprint: identity.FormatFingerprint(identity.Fingerprint(s.PublicKey())),
		Address:     s.RemoteAddr().String(), Warning: info.Warning,
	}
	n.mu.Lock()
	if ps := n.peers[id]; ps != nil && ps.pair != nil && ps.pair.session == s && time.Since(ps.pair.started) < pairingWindow {
		pi.Code = ps.pair.code
		pi.Initiator = ps.pair.role == roleInitiator
	}
	n.mu.Unlock()
	return pi, nil
}

// RequestPairing starts pairing with a connected peer. The verification
// code becomes available (EventPairCode) once the peer has answered.
func (n *Node) RequestPairing(_ context.Context, id identity.PeerID) error {
	s := n.sessionFor(id)
	if s == nil {
		return ErrNotConnected
	}
	now := time.Now()
	n.mu.Lock()
	if n.known[id].Trust == storage.TrustTrusted {
		n.mu.Unlock()
		return ErrAlreadyPaired
	}
	ps := n.peerLocked(id)
	if p := ps.pair; p != nil && p.session == s && now.Sub(p.started) < pairingWindow {
		n.mu.Unlock()
		if p.role == roleResponder {
			return errors.New("this peer already asked to pair with you; review their request")
		}
		return nil // already in progress
	}
	nonce := randNonce()
	ps.pair = &pairState{role: roleInitiator, session: s, myNonce: nonce, started: now}
	name := n.name
	n.mu.Unlock()
	if err := s.Send(protocol.TypePairRequest, protocol.PairRequest{DisplayName: name, Commit: identity.PairingCommit(nonce)}); err != nil {
		return err
	}
	n.emit(Event{Kind: EventPeers})
	return nil
}

// RespondPairing records the local user's decision after comparing the
// verification code: accept approves the peer (trust is granted once the
// peer approved too), reject aborts the pairing.
func (n *Node) RespondPairing(ctx context.Context, id identity.PeerID, accept bool) error {
	n.mu.Lock()
	ps := n.peers[id]
	if ps == nil || ps.pair == nil || time.Since(ps.pair.started) > pairingWindow {
		n.mu.Unlock()
		return ErrNoPairingRequest
	}
	p := ps.pair
	s := p.session
	if !s.Alive() || ps.session != s {
		ps.pair = nil
		n.mu.Unlock()
		return ErrNotConnected
	}
	if !accept {
		ps.pair = nil
		n.mu.Unlock()
		_ = s.Send(protocol.TypePairReject, protocol.PairResponse{Reason: "declined"})
		n.emit(Event{Kind: EventPeers})
		return nil
	}
	if p.code == "" {
		n.mu.Unlock()
		return ErrCodeNotReady
	}
	p.localApproved = true
	complete := p.remoteApproved
	n.mu.Unlock()
	if err := s.Send(protocol.TypePairAccept, protocol.PairResponse{}); err != nil {
		return err
	}
	if complete {
		n.completePairing(ctx, s)
	}
	n.emit(Event{Kind: EventPeers})
	return nil
}

// completePairing persists the peer as trusted.
func (n *Node) completePairing(ctx context.Context, s *transport.Session) {
	pid := s.PeerID()
	n.mu.Lock()
	ps := n.peers[pid]
	if ps == nil || ps.pair == nil || ps.pair.session != s {
		n.mu.Unlock()
		return
	}
	ps.pair = nil
	name, dev := ps.displayName, ps.deviceName
	n.mu.Unlock()
	// Unpaired peers are kept in memory only; persist the identity now.
	if err := n.store.RecordPeerSeen(ctx, storage.PeerSeen{ID: pid, PublicKey: s.SPKI(), DisplayName: name, DeviceName: dev,
		Address: s.RemoteAddr().String(), At: time.Now()}); err != nil {
		n.log.Error("cannot store paired peer", "err", err)
		return
	}
	if err := n.setTrust(ctx, pid, storage.TrustTrusted, true); err != nil {
		n.log.Error("cannot store trust", "err", err)
		return
	}
	n.afterTrusted(s, true)
	n.emit(Event{Kind: EventPairResult, PeerID: pid, PeerName: name, Accepted: true})
}

// Revoke withdraws trust from a peer. Undelivered messages to the peer are
// marked failed and the peer is informed.
func (n *Node) Revoke(ctx context.Context, id identity.PeerID) error {
	if err := n.setTrust(ctx, id, storage.TrustRevoked, false); err != nil {
		return err
	}
	n.mu.Lock()
	if ps := n.peers[id]; ps != nil {
		ps.pair = nil
	}
	n.mu.Unlock()
	if s := n.sessionFor(id); s != nil {
		_ = s.Send(protocol.TypePairRevoke, protocol.PairResponse{Reason: "trust revoked"})
		n.sendPresence(s) // stop sharing room membership
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
	n.setKnownLocked(p)
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
	ps := n.peerLocked(pid)
	if ps.session != s || (!ps.lastPairReq.IsZero() && now.Sub(ps.lastPairReq) < 3*time.Second) {
		n.mu.Unlock()
		return // rate limit, or a request on a session that is not current
	}
	ps.lastPairReq = now
	if p := ps.pair; p != nil && p.session == s && now.Sub(p.started) < pairingWindow {
		if p.role == roleResponder || n.id.ID() < pid {
			// Duplicate request, or simultaneous requests where we keep the
			// initiator role (the smaller ID does); the peer yields when it
			// receives our request.
			n.mu.Unlock()
			return
		}
		// Simultaneous requests and we have the larger ID: become responder.
	}
	nonce := randNonce()
	ps.pair = &pairState{role: roleResponder, session: s, commit: req.Commit, myNonce: nonce, started: now,
		// A key we already trust may re-pair without asking the user again.
		localApproved: n.known[pid].Trust == storage.TrustTrusted}
	n.mu.Unlock()
	_ = s.Send(protocol.TypePairNonce, protocol.PairNonce{Nonce: hex.EncodeToString(nonce)})
}

func (n *Node) handlePairNonce(s *transport.Session, msg *protocol.PairNonce) {
	pid := s.PeerID()
	nonce, err := hex.DecodeString(msg.Nonce)
	if err != nil {
		return
	}
	n.mu.Lock()
	ps := n.peers[pid]
	if ps == nil || ps.pair == nil || ps.pair.role != roleInitiator || ps.pair.session != s || ps.pair.peerNonce != nil {
		n.mu.Unlock()
		return
	}
	p := ps.pair
	p.peerNonce = nonce
	p.code = s.PairingCode(p.myNonce, p.peerNonce)
	reveal, code, name := p.myNonce, p.code, ps.displayName
	n.mu.Unlock()
	_ = s.Send(protocol.TypePairReveal, protocol.PairNonce{Nonce: hex.EncodeToString(reveal)})
	n.emit(Event{Kind: EventPairCode, PeerID: pid, PeerName: name, Code: code})
}

func (n *Node) handlePairReveal(s *transport.Session, msg *protocol.PairNonce) {
	pid := s.PeerID()
	nonce, err := hex.DecodeString(msg.Nonce)
	if err != nil {
		return
	}
	n.mu.Lock()
	ps := n.peers[pid]
	if ps == nil || ps.pair == nil || ps.pair.role != roleResponder || ps.pair.session != s || ps.pair.code != "" {
		n.mu.Unlock()
		return
	}
	p := ps.pair
	if identity.PairingCommit(nonce) != p.commit {
		ps.pair = nil
		n.mu.Unlock()
		n.log.Warn("pairing aborted: revealed nonce does not match commitment", "peer", string(pid))
		_ = s.Send(protocol.TypePairReject, protocol.PairResponse{Reason: "commitment mismatch"})
		n.emit(Event{Kind: EventIdentityWarning, PeerID: pid, PeerName: n.peerName(pid),
			Text: "A pairing attempt was aborted because the other side did not follow the verification protocol. This can indicate an attack."})
		return
	}
	p.peerNonce = nonce
	p.code = s.PairingCode(p.peerNonce, p.myNonce)
	auto, code, name := p.localApproved, p.code, ps.displayName
	n.mu.Unlock()
	if auto {
		_ = s.Send(protocol.TypePairAccept, protocol.PairResponse{})
		return
	}
	n.emit(Event{Kind: EventPairRequest, PeerID: pid, PeerName: name, Code: code})
}

func (n *Node) handlePairAccept(s *transport.Session) {
	pid := s.PeerID()
	n.mu.Lock()
	ps := n.peers[pid]
	if ps == nil || ps.pair == nil || ps.pair.session != s || ps.pair.code == "" {
		n.mu.Unlock()
		// An acceptance without a completed exchange never grants trust.
		n.log.Debug("ignoring unsolicited pairing acceptance", "peer", string(pid))
		return
	}
	ps.pair.remoteApproved = true
	complete := ps.pair.localApproved
	n.mu.Unlock()
	if complete {
		n.completePairing(context.Background(), s)
	}
	n.emit(Event{Kind: EventPeers})
}

func (n *Node) handlePairReject(s *transport.Session, resp *protocol.PairResponse) {
	pid := s.PeerID()
	n.mu.Lock()
	ps := n.peers[pid]
	pending := ps != nil && ps.pair != nil && ps.pair.session == s
	if pending {
		ps.pair = nil
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
