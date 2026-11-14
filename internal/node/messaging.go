package node

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/rooms"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// HandleFrame implements transport.Handler. It dispatches one frame from an
// authenticated peer. Messages that require trust are refused (not treated
// as protocol violations) when the peer is not paired.
func (n *Node) HandleFrame(s *transport.Session, f *protocol.Frame) error {
	if f.Kind == protocol.KindChunk {
		return n.handleChunk(s, f.Chunk)
	}
	env := f.Envelope
	pid := s.PeerID()
	trusted := n.isTrusted(pid)
	switch env.Type {
	case protocol.TypeHello:
		return errors.New("duplicate hello")
	case protocol.TypeError:
		if em, err := protocol.DecodeBody[protocol.ErrorMsg](env); err == nil {
			n.log.Info("peer reported error", "peer", string(pid), "code", em.Code)
		}
		return nil
	case protocol.TypePresence:
		p, err := protocol.DecodeBody[protocol.Presence](env)
		if err != nil {
			return err
		}
		n.handlePresence(s, p)
		return nil
	case protocol.TypePairRequest:
		req, err := protocol.DecodeBody[protocol.PairRequest](env)
		if err != nil {
			return err
		}
		n.handlePairRequest(s, req)
		return nil
	case protocol.TypePairAccept:
		n.handlePairAccept(s)
		return nil
	case protocol.TypePairReject:
		resp, err := protocol.DecodeBody[protocol.PairResponse](env)
		if err != nil {
			return err
		}
		n.handlePairReject(s, resp)
		return nil
	case protocol.TypePairRevoke:
		n.handlePairRevoke(s)
		return nil
	case protocol.TypeAck:
		a, err := protocol.DecodeBody[protocol.Ack](env)
		if err != nil {
			return err
		}
		n.handleAck(s, a)
		return nil
	}

	// Every remaining message type requires a paired peer. Bodies are
	// decoded and validated first so that malformed traffic is treated as a
	// protocol violation regardless of trust.
	body, err := decodeTrusted(env)
	if err != nil {
		return err
	}
	if body == nil {
		// Unknown types from newer peers are ignored for forward compatibility.
		n.log.Debug("ignoring unknown message type", "peer", string(pid), "type", env.Type)
		return nil
	}
	if !trusted {
		switch b := body.(type) {
		case *protocol.ChatMessage:
			_ = s.Send(protocol.TypeAck, protocol.Ack{MessageID: b.MessageID, Status: protocol.AckRejected, Reason: "not paired"})
		case *protocol.FileOffer:
			_ = s.Send(protocol.TypeFileReject, protocol.FileControl{TransferID: b.TransferID, Reason: "not paired"})
		}
		n.log.Debug("refused message from unpaired peer", "peer", string(pid), "type", env.Type)
		return nil
	}
	switch b := body.(type) {
	case *protocol.ChatMessage:
		n.handleChat(s, b)
	case *protocol.GroupUpdate:
		n.handleGroupUpdate(s, b)
	case *protocol.GroupLeave:
		n.handleGroupLeave(s, b)
	case *protocol.GroupSync:
		n.handleGroupSync(s, b)
	case *protocol.FileOffer:
		n.handleFileOffer(s, b)
	case *protocol.FileControl:
		n.handleFileControl(s, env.Type, b)
	case *protocol.FileDone:
		n.handleFileDone(s, b)
	case *protocol.FileResult:
		n.handleFileResult(s, b)
	}
	return nil
}

// decodeTrusted decodes the body of a message type that requires trust. It
// returns (nil, nil) for unknown types.
func decodeTrusted(env *protocol.Envelope) (any, error) {
	switch env.Type {
	case protocol.TypeChat:
		return protocol.DecodeBody[protocol.ChatMessage](env)
	case protocol.TypeGroupUpdate:
		return protocol.DecodeBody[protocol.GroupUpdate](env)
	case protocol.TypeGroupLeave:
		return protocol.DecodeBody[protocol.GroupLeave](env)
	case protocol.TypeGroupSync:
		return protocol.DecodeBody[protocol.GroupSync](env)
	case protocol.TypeFileOffer:
		return protocol.DecodeBody[protocol.FileOffer](env)
	case protocol.TypeFileAccept, protocol.TypeFileReject, protocol.TypeFileCancel:
		return protocol.DecodeBody[protocol.FileControl](env)
	case protocol.TypeFileDone:
		return protocol.DecodeBody[protocol.FileDone](env)
	case protocol.TypeFileResult:
		return protocol.DecodeBody[protocol.FileResult](env)
	}
	return nil, nil
}

// --- conversations ----------------------------------------------------------

// Conversations lists conversations with unread counts.
func (n *Node) Conversations(ctx context.Context) ([]storage.Conversation, error) {
	return n.store.ListConversations(ctx)
}

// Conversation returns one conversation.
func (n *Node) Conversation(ctx context.Context, id string) (storage.Conversation, error) {
	return n.store.GetConversation(ctx, id)
}

// Messages returns a page of messages (ascending) before beforeSeq.
func (n *Node) Messages(ctx context.Context, convID string, beforeSeq int64, limit int) ([]storage.Message, error) {
	return n.store.Messages(ctx, convID, beforeSeq, limit)
}

// MarkRead marks a conversation read up to seq.
func (n *Node) MarkRead(ctx context.Context, convID string, seq int64) error {
	return n.store.MarkRead(ctx, convID, seq)
}

// Search finds messages containing query.
func (n *Node) Search(ctx context.Context, query, convID string) ([]storage.Message, error) {
	return n.store.Search(ctx, query, convID, 200)
}

// ClearHistory deletes the stored messages of a conversation ("" = all).
func (n *Node) ClearHistory(ctx context.Context, convID string) (int64, error) {
	c, err := n.store.DeleteHistory(ctx, convID)
	if err == nil {
		n.emit(Event{Kind: EventConversations, ConversationID: convID})
	}
	return c, err
}

// RetryFailed re-queues failed deliveries of a conversation and flushes them
// to connected recipients.
func (n *Node) RetryFailed(ctx context.Context, convID string) (int64, error) {
	c, err := n.store.RetryFailed(ctx, convID)
	if err != nil {
		return 0, err
	}
	n.flushAll(false)
	n.emit(Event{Kind: EventDelivery, ConversationID: convID})
	return c, nil
}

// OpenDirect ensures a direct conversation with a peer exists.
func (n *Node) OpenDirect(ctx context.Context, id identity.PeerID) (string, error) {
	info, ok := n.Peer(id)
	if !ok {
		return "", ErrUnknownPeer
	}
	convID := storage.DirectConversationID(id)
	err := n.store.EnsureConversation(ctx, storage.Conversation{ID: convID, Kind: storage.KindDirect, Title: info.DisplayName, PeerID: id, Joined: true})
	if err == nil {
		n.emit(Event{Kind: EventConversations, ConversationID: convID})
	}
	return convID, err
}

// RoomInfo describes a public room.
type RoomInfo struct {
	Name    string
	Joined  bool
	Members int // connected trusted peers announcing the room (excluding us)
}

// Rooms lists joined rooms and rooms announced by connected trusted peers.
func (n *Node) Rooms() []RoomInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	m := map[string]*RoomInfo{}
	for r := range n.rooms {
		m[r] = &RoomInfo{Name: r, Joined: true}
	}
	for id, ps := range n.peers {
		if ps.session == nil || n.known[id].Trust != storage.TrustTrusted {
			continue
		}
		for r := range ps.rooms {
			if m[r] == nil {
				m[r] = &RoomInfo{Name: r}
			}
			m[r].Members++
		}
	}
	out := make([]RoomInfo, 0, len(m))
	for _, r := range m {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RoomMembers returns connected trusted peers that joined the room.
func (n *Node) RoomMembers(name string) []PeerInfo {
	var out []PeerInfo
	for _, p := range n.Peers() {
		if !p.Online() {
			continue
		}
		for _, r := range p.Rooms {
			if r == name {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// JoinRoom joins (creating if necessary) a public room.
func (n *Node) JoinRoom(ctx context.Context, name string) (string, error) {
	name = protocol.NormalizeRoomName(name)
	if !protocol.ValidRoomName(name) {
		return "", fmt.Errorf("invalid room name %q: use 1–32 lowercase letters, digits, '-' or '_'", name)
	}
	n.mu.Lock()
	if !n.rooms[name] && len(n.rooms) >= protocol.MaxRooms {
		n.mu.Unlock()
		return "", fmt.Errorf("you can join at most %d rooms", protocol.MaxRooms)
	}
	n.mu.Unlock()
	id := storage.RoomConversationID(name)
	if err := n.store.EnsureConversation(ctx, storage.Conversation{ID: id, Kind: storage.KindRoom, Title: name, Joined: true}); err != nil {
		return "", err
	}
	n.mu.Lock()
	n.rooms[name] = true
	n.mu.Unlock()
	n.broadcastPresence()
	n.emit(Event{Kind: EventConversations, ConversationID: id})
	return id, nil
}

// LeaveRoom leaves a public room (history is kept).
func (n *Node) LeaveRoom(ctx context.Context, name string) error {
	name = protocol.NormalizeRoomName(name)
	if name == "general" {
		return errors.New("the general room cannot be left")
	}
	if err := n.store.SetJoined(ctx, storage.RoomConversationID(name), false); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("you are not in #%s", name)
		}
		return err
	}
	n.mu.Lock()
	delete(n.rooms, name)
	n.mu.Unlock()
	n.broadcastPresence()
	n.emit(Event{Kind: EventConversations})
	return nil
}

// --- sending ----------------------------------------------------------------

// SendText sends a chat message to a conversation and returns the stored
// message with its initial delivery state.
func (n *Node) SendText(ctx context.Context, convID, body string) (storage.Message, error) {
	body = strings.TrimRight(body, " \t\r\n")
	if strings.TrimSpace(body) == "" {
		return storage.Message{}, ErrEmptyMessage
	}
	if !utf8.ValidString(body) {
		return storage.Message{}, errors.New("message is not valid UTF-8")
	}
	if len(body) > n.cfg.Chat.MaxMessageBytes {
		return storage.Message{}, fmt.Errorf("message is too long (%d bytes; the limit is %d)", len(body), n.cfg.Chat.MaxMessageBytes)
	}
	kind, key, err := storage.ParseConversationID(convID)
	if err != nil {
		return storage.Message{}, err
	}
	if kind == storage.KindDirect && !n.isTrusted(identity.PeerID(key)) {
		return storage.Message{}, ErrNotPaired
	}
	conv, err := n.store.GetConversation(ctx, convID)
	if err != nil {
		return storage.Message{}, fmt.Errorf("conversation not found")
	}
	self := n.id.ID()
	wire := protocol.ChatMessage{MessageID: protocol.NewID(), Body: body}
	var recipients []identity.PeerID
	failReason := map[identity.PeerID]string{}
	switch kind {
	case storage.KindRoom:
		if !conv.Joined {
			return storage.Message{}, fmt.Errorf("join #%s first", key)
		}
		wire.Kind, wire.Room = protocol.ConvRoom, key
		for _, p := range n.RoomMembers(key) {
			recipients = append(recipients, p.ID)
		}
	case storage.KindDirect:
		pid := identity.PeerID(key)
		if !n.isTrusted(pid) {
			return storage.Message{}, ErrNotPaired
		}
		wire.Kind = protocol.ConvDirect
		recipients = []identity.PeerID{pid}
	case storage.KindGroup:
		g, err := n.store.GetGroup(ctx, key)
		if err != nil {
			return storage.Message{}, fmt.Errorf("group not found")
		}
		if !rooms.CanSend(&g, self) {
			return storage.Message{}, errors.New("you are no longer a member of this group")
		}
		wire.Kind, wire.GroupID = protocol.ConvGroup, g.ID
		for _, r := range rooms.Recipients(&g, self) {
			recipients = append(recipients, r)
			if !n.isTrusted(r) {
				failReason[r] = "not paired with this member"
			}
		}
	}
	now := time.Now()
	wire.SentAt = now.UnixMilli()
	n.mu.Lock()
	selfName := n.name
	n.mu.Unlock()
	m := &storage.Message{
		ID: wire.MessageID, ConversationID: convID, SenderID: self, SenderName: selfName,
		Kind: storage.MessageText, Body: body, SentAt: now, ReceivedAt: now, Outgoing: true,
	}
	if _, err := n.store.InsertMessage(ctx, m, recipients); err != nil {
		return storage.Message{}, fmt.Errorf("store message: %w", err)
	}
	for _, r := range recipients {
		if reason, ok := failReason[r]; ok {
			_ = n.store.MarkDelivery(ctx, m.Seq, r, storage.DeliveryFailed, reason)
			continue
		}
		s := n.trustedSession(r)
		if s == nil {
			if !n.cfg.Chat.QueueOfflineMessages {
				_ = n.store.MarkDelivery(ctx, m.Seq, r, storage.DeliveryFailed, "recipient offline")
			} else if q, err := n.store.CountQueued(ctx, r); err == nil && q > n.cfg.Chat.MaxQueuedPerPeer {
				_ = n.store.MarkDelivery(ctx, m.Seq, r, storage.DeliveryFailed, "offline queue for this peer is full")
			}
			continue
		}
		if err := s.Send(protocol.TypeChat, wire); err == nil {
			_ = n.store.MarkDelivery(ctx, m.Seq, r, storage.DeliverySent, "")
		} else {
			n.flush(r, false)
		}
	}
	stored, err := n.store.GetMessage(ctx, m.Seq)
	if err != nil {
		stored = *m
	}
	n.emit(Event{Kind: EventMessage, ConversationID: convID, Message: &stored})
	return stored, nil
}

// --- receiving --------------------------------------------------------------

func (n *Node) handleChat(s *transport.Session, msg *protocol.ChatMessage) {
	pid := s.PeerID()
	self := n.id.ID()
	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	reject := func(reason string) {
		_ = s.Send(protocol.TypeAck, protocol.Ack{MessageID: msg.MessageID, Status: protocol.AckRejected, Reason: reason})
	}
	name := n.peerName(pid)
	var convID string
	switch msg.Kind {
	case protocol.ConvRoom:
		n.mu.Lock()
		joined := n.rooms[msg.Room]
		n.mu.Unlock()
		if !joined {
			reject("recipient is not in #" + msg.Room)
			return
		}
		convID = storage.RoomConversationID(msg.Room)
	case protocol.ConvDirect:
		convID = storage.DirectConversationID(pid)
		if err := n.store.EnsureConversation(ctx, storage.Conversation{ID: convID, Kind: storage.KindDirect, Title: name, PeerID: pid, Joined: true}); err != nil {
			n.log.Error("cannot create conversation", "err", err)
			return
		}
	case protocol.ConvGroup:
		g, err := n.store.GetGroup(ctx, msg.GroupID)
		if err != nil || !rooms.AcceptMessage(&g, pid, self) {
			reject("not a member of this group")
			return
		}
		convID = g.ConversationID
	default:
		reject("unsupported conversation kind")
		return
	}
	now := time.Now()
	sent := time.UnixMilli(msg.SentAt)
	if msg.SentAt == 0 || sent.After(now.Add(time.Minute)) {
		// Never display a timestamp in the future: sender clocks are not
		// trusted and may be skewed.
		sent = now
	}
	m := &storage.Message{ID: msg.MessageID, ConversationID: convID, SenderID: pid, SenderName: name,
		Kind: storage.MessageText, Body: msg.Body, SentAt: sent, ReceivedAt: now}
	inserted, err := n.store.InsertMessage(ctx, m, nil)
	if err != nil {
		// Not acknowledged: the sender keeps it queued and retries.
		n.log.Error("cannot store incoming message", "err", err)
		return
	}
	_ = s.Send(protocol.TypeAck, protocol.Ack{MessageID: msg.MessageID, Status: protocol.AckDelivered})
	if inserted {
		n.emit(Event{Kind: EventMessage, ConversationID: convID, Message: m, PeerID: pid, PeerName: name, Incoming: true})
	}
}

func (n *Node) handleAck(s *transport.Session, a *protocol.Ack) {
	status := storage.DeliveryDelivered
	reason := ""
	if a.Status == protocol.AckRejected {
		status = storage.DeliveryFailed
		reason = "rejected by recipient: " + sanitizeDevice(a.Reason)
	}
	r, err := n.store.ApplyAck(context.Background(), n.id.ID(), s.PeerID(), a.MessageID, status, reason)
	if err != nil || !r.Changed {
		return
	}
	n.emit(Event{Kind: EventDelivery, ConversationID: r.ConversationID})
}

// flush resends undelivered messages to a connected trusted peer. Messages
// already "sent" are included when includeSent is true (after reconnecting)
// or when they have waited more than two minutes for an acknowledgement.
// Recipients de-duplicate by message ID, so resending is safe.
func (n *Node) flush(pid identity.PeerID, includeSent bool) {
	n.mu.Lock()
	ps := n.peers[pid]
	if ps == nil || ps.flushing || ps.session == nil || n.known[pid].Trust != storage.TrustTrusted || n.closed {
		n.mu.Unlock()
		return
	}
	ps.flushing = true
	s := ps.session
	n.mu.Unlock()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			n.mu.Lock()
			if p := n.peers[pid]; p != nil {
				p.flushing = false
			}
			n.mu.Unlock()
		}()
		pend, err := n.store.PendingFor(n.ctx, pid, 500)
		if err != nil {
			return
		}
		changed := map[string]bool{}
		for _, p := range pend {
			if p.Status == storage.DeliverySent && !includeSent && time.Since(p.UpdatedAt) < 2*time.Minute {
				continue
			}
			wire, ok := n.wireFor(p)
			if !ok {
				_ = n.store.MarkDelivery(n.ctx, p.Seq, pid, storage.DeliveryFailed, "conversation is no longer available")
				changed[p.ConversationID] = true
				continue
			}
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			err := s.SendWait(ctx, protocol.TypeChat, wire)
			cancel()
			if err != nil {
				return
			}
			_ = n.store.MarkDelivery(n.ctx, p.Seq, pid, storage.DeliverySent, "")
			changed[p.ConversationID] = true
		}
		for c := range changed {
			n.emit(Event{Kind: EventDelivery, ConversationID: c})
		}
	}()
}

func (n *Node) flushAll(includeSent bool) {
	n.mu.Lock()
	var ids []identity.PeerID
	for id, ps := range n.peers {
		if ps.session != nil && n.known[id].Trust == storage.TrustTrusted {
			ids = append(ids, id)
		}
	}
	n.mu.Unlock()
	for _, id := range ids {
		n.flush(id, includeSent)
	}
}

func (n *Node) wireFor(p storage.PendingDelivery) (protocol.ChatMessage, bool) {
	kind, key, err := storage.ParseConversationID(p.ConversationID)
	if err != nil {
		return protocol.ChatMessage{}, false
	}
	w := protocol.ChatMessage{MessageID: p.MessageID, Body: p.Body, SentAt: p.SentAt.UnixMilli()}
	switch kind {
	case storage.KindRoom:
		w.Kind, w.Room = protocol.ConvRoom, key
	case storage.KindDirect:
		if identity.PeerID(key) != p.PeerID {
			return w, false
		}
		w.Kind = protocol.ConvDirect
	case storage.KindGroup:
		g, err := n.store.GetGroup(n.ctx, key)
		if err != nil || !rooms.CanSend(&g, n.id.ID()) || !g.HasMember(p.PeerID) {
			return w, false
		}
		w.Kind, w.GroupID = protocol.ConvGroup, key
	}
	return w, true
}

// maintenanceLoop expires stale adverts and pairing requests, expires and
// retries deliveries, and prunes forgotten peers.
func (n *Node) maintenanceLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		changed := false
		n.mu.Lock()
		for id, ps := range n.peers {
			for k, a := range ps.adverts {
				if now.Sub(a.SeenAt) > a.TTL {
					delete(ps.adverts, k)
					changed = true
				}
			}
			if !ps.outgoingPair.IsZero() && now.Sub(ps.outgoingPair) > pairingWindow {
				ps.outgoingPair = time.Time{}
				changed = true
			}
			_, known := n.known[id]
			if !known && ps.session == nil && !ps.dialing && len(ps.adverts) == 0 && now.Sub(ps.lastActive) > time.Hour {
				delete(n.peers, id)
			}
		}
		for k, st := range n.statics {
			if now.Sub(st.advert.SeenAt) > st.advert.TTL {
				delete(n.statics, k)
			}
		}
		n.mu.Unlock()
		if changed {
			n.emit(Event{Kind: EventPeers})
		}
		convs, err := n.store.ExpireDeliveries(n.ctx, now.Add(-n.cfg.OfflineQueueTTL()), n.cfg.Chat.MaxRetryAttempts)
		if err == nil {
			for _, c := range convs {
				n.emit(Event{Kind: EventDelivery, ConversationID: c})
			}
		}
		n.flushAll(false)
	}
}

// systemMessage stores a local, non-transmitted notice in a conversation.
func (n *Node) systemMessage(ctx context.Context, convID, text string) {
	now := time.Now()
	m := &storage.Message{ID: protocol.NewID(), ConversationID: convID, SenderID: "system", SenderName: "LANChat",
		Kind: storage.MessageSystem, Body: text, SentAt: now, ReceivedAt: now}
	if _, err := n.store.InsertMessage(ctx, m, nil); err == nil {
		n.emit(Event{Kind: EventMessage, ConversationID: convID, Message: m})
	}
}
