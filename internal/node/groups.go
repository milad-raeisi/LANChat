package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/rooms"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// Group returns a stored group.
func (n *Node) Group(ctx context.Context, groupID string) (storage.Group, error) {
	return n.store.GetGroup(ctx, groupID)
}

func (n *Node) selfMember() storage.GroupMember {
	n.mu.Lock()
	defer n.mu.Unlock()
	return storage.GroupMember{PeerID: n.id.ID(), DisplayName: n.name}
}

// CreateGroup creates a private group owned by the local user and invites
// the given paired peers.
func (n *Node) CreateGroup(ctx context.Context, name string, members []identity.PeerID) (string, error) {
	if c, err := n.store.CountActiveGroups(ctx); err == nil && c >= protocol.MaxGroups {
		return "", fmt.Errorf("you can be in at most %d active groups", protocol.MaxGroups)
	}
	g, err := rooms.NewGroup(identity.SPKI(n.id.PublicKey()), name, n.selfMember())
	if err != nil {
		return "", err
	}
	for _, m := range members {
		if !n.isTrusted(m) {
			return "", fmt.Errorf("%s: %w", n.peerName(m), ErrNotPaired)
		}
		if g, err = rooms.AddMember(g, n.id.ID(), storage.GroupMember{PeerID: m, DisplayName: n.peerName(m)}); err != nil && !errors.Is(err, rooms.ErrAlreadyMember) {
			return "", err
		}
	}
	g.ConversationID = storage.GroupConversationID(g.ID)
	if err := n.store.SaveGroup(ctx, g); err != nil {
		return "", err
	}
	n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("You created the group %q.", g.Name))
	n.publishGroup(g)
	n.emit(Event{Kind: EventConversations, ConversationID: g.ConversationID})
	return g.ConversationID, nil
}

// InviteToGroup adds a paired peer to a group owned by the local user.
func (n *Node) InviteToGroup(ctx context.Context, groupID string, peer identity.PeerID) error {
	if !n.isTrusted(peer) {
		return ErrNotPaired
	}
	g, err := n.store.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	g, err = rooms.AddMember(g, n.id.ID(), storage.GroupMember{PeerID: peer, DisplayName: n.peerName(peer)})
	if err != nil {
		return err
	}
	if err := n.store.SaveGroup(ctx, g); err != nil {
		return err
	}
	n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("You added %s.", n.peerName(peer)))
	n.publishGroup(g)
	n.emit(Event{Kind: EventConversations, ConversationID: g.ConversationID})
	return nil
}

// RemoveFromGroup removes a member from a group owned by the local user.
func (n *Node) RemoveFromGroup(ctx context.Context, groupID string, peer identity.PeerID) error {
	g, err := n.store.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	g, err = rooms.RemoveMember(g, n.id.ID(), peer)
	if err != nil {
		return err
	}
	if err := n.store.SaveGroup(ctx, g); err != nil {
		return err
	}
	n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("You removed %s.", n.peerName(peer)))
	n.publishGroup(g, peer) // the removed member learns about the removal too
	n.emit(Event{Kind: EventConversations, ConversationID: g.ConversationID})
	return nil
}

// LeaveGroup leaves a group. For the owner this disbands the group.
func (n *Node) LeaveGroup(ctx context.Context, groupID string) error {
	g, err := n.store.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if g.State != storage.GroupActive {
		return rooms.ErrInactive
	}
	self := n.id.ID()
	if g.OwnerID == self {
		members := rooms.Recipients(&g, self)
		g, err = rooms.Disband(g, self)
		if err != nil {
			return err
		}
		if err := n.store.SaveGroup(ctx, g); err != nil {
			return err
		}
		n.systemMessage(ctx, g.ConversationID, "You disbanded this group.")
		n.publishGroup(g, members...)
	} else {
		g.State = storage.GroupLeft
		if err := n.store.SaveGroup(ctx, g); err != nil {
			return err
		}
		n.systemMessage(ctx, g.ConversationID, "You left this group.")
		if s := n.trustedSession(g.OwnerID); s != nil {
			_ = s.Send(protocol.TypeGroupLeave, protocol.GroupLeave{GroupID: g.ID})
		}
		// If the owner is offline, the next group.sync tells them.
	}
	n.emit(Event{Kind: EventConversations, ConversationID: g.ConversationID})
	return nil
}

// publishGroup sends the owner's snapshot to every connected member (and
// to extra recipients such as removed members).
func (n *Node) publishGroup(g storage.Group, extra ...identity.PeerID) {
	upd := rooms.ToUpdate(&g)
	targets := map[identity.PeerID]bool{}
	for _, m := range g.Members {
		targets[m.PeerID] = true
	}
	for _, e := range extra {
		targets[e] = true
	}
	delete(targets, n.id.ID())
	for id := range targets {
		if s := n.trustedSession(id); s != nil {
			_ = s.Send(protocol.TypeGroupUpdate, upd)
		}
	}
}

// syncGroupsWith runs when a trusted session is established: as owner we
// push snapshots of our groups that include the peer; as member we tell the
// peer which of its groups we know and whether we left them.
func (n *Node) syncGroupsWith(s *transport.Session) {
	pid := s.PeerID()
	self := n.id.ID()
	groups, err := n.store.ListGroups(n.ctx)
	if err != nil {
		return
	}
	var sync protocol.GroupSync
	for _, g := range groups {
		switch {
		case g.OwnerID == self && g.HasMember(pid):
			_ = s.Send(protocol.TypeGroupUpdate, rooms.ToUpdate(&g))
		case g.OwnerID == pid:
			status := "member"
			if g.State == storage.GroupLeft {
				status = "left"
			}
			if g.State == storage.GroupActive || g.State == storage.GroupLeft {
				sync.Groups = append(sync.Groups, protocol.GroupSyncEntry{GroupID: g.ID, Version: g.Version, Status: status})
			}
		}
	}
	if len(sync.Groups) > protocol.MaxGroups {
		sync.Groups = sync.Groups[:protocol.MaxGroups]
	}
	_ = s.Send(protocol.TypeGroupSync, sync)
}

func (n *Node) handleGroupUpdate(s *transport.Session, upd *protocol.GroupUpdate) {
	pid := s.PeerID()
	self := n.id.ID()
	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	var local *storage.Group
	if g, err := n.store.GetGroup(ctx, upd.GroupID); err == nil {
		local = &g
	} else if c, err := n.store.CountActiveGroups(ctx); err == nil && c >= protocol.MaxGroups {
		n.log.Warn("ignoring group invitation: group limit reached", "peer", string(pid))
		return
	}
	d := rooms.EvaluateUpdate(local, upd, pid, s.SPKI(), self)
	if d.Action != rooms.Apply {
		n.log.Debug("group update ignored", "group", upd.GroupID, "reason", d.Reason)
		return
	}
	g := rooms.FromUpdate(upd, d.State)
	g.Name = sanitizeDevice(g.Name)
	for i := range g.Members {
		g.Members[i].DisplayName = sanitizeName(g.Members[i].DisplayName)
	}
	g.ConversationID = storage.GroupConversationID(g.ID)
	if err := n.store.SaveGroup(ctx, g); err != nil {
		n.log.Error("cannot save group", "err", err)
		return
	}
	owner := n.peerName(pid)
	switch {
	case local == nil || d.Joined:
		n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("%s added you to the group %q.", owner, g.Name))
		n.notice("info", "%s added you to the group %q.", owner, g.Name)
	case d.State == storage.GroupRemoved:
		n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("%s removed you from this group.", owner))
	case d.State == storage.GroupDisbanded:
		n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("%s disbanded this group.", owner))
	default:
		n.systemMessage(ctx, g.ConversationID, describeMembershipChange(local, &g))
	}
	n.emit(Event{Kind: EventConversations, ConversationID: g.ConversationID})
}

func describeMembershipChange(old, cur *storage.Group) string {
	var added, removed []string
	for _, m := range cur.Members {
		if !old.HasMember(m.PeerID) {
			added = append(added, m.DisplayName)
		}
	}
	for _, m := range old.Members {
		if !cur.HasMember(m.PeerID) {
			removed = append(removed, m.DisplayName)
		}
	}
	switch {
	case len(added) > 0 && len(removed) == 0:
		return fmt.Sprintf("Joined: %s.", join(added))
	case len(removed) > 0 && len(added) == 0:
		return fmt.Sprintf("Left or removed: %s.", join(removed))
	case len(added) > 0:
		return fmt.Sprintf("Joined: %s. Left or removed: %s.", join(added), join(removed))
	}
	if old.Name != cur.Name {
		return fmt.Sprintf("Group renamed to %q.", cur.Name)
	}
	return "Group membership updated."
}

func join(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func (n *Node) handleGroupLeave(s *transport.Session, gl *protocol.GroupLeave) {
	n.processLeave(s.PeerID(), gl.GroupID)
}

func (n *Node) processLeave(pid identity.PeerID, groupID string) {
	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	g, err := n.store.GetGroup(ctx, groupID)
	if err != nil {
		return
	}
	g, err = rooms.ProcessLeave(g, n.id.ID(), pid)
	if err != nil {
		return
	}
	if err := n.store.SaveGroup(ctx, g); err != nil {
		return
	}
	n.systemMessage(ctx, g.ConversationID, fmt.Sprintf("%s left the group.", n.peerName(pid)))
	n.publishGroup(g, pid)
	n.emit(Event{Kind: EventConversations, ConversationID: g.ConversationID})
}

func (n *Node) handleGroupSync(s *transport.Session, gs *protocol.GroupSync) {
	pid := s.PeerID()
	self := n.id.ID()
	for _, e := range gs.Groups {
		g, err := n.store.GetGroup(n.ctx, e.GroupID)
		if err != nil || g.OwnerID != self {
			continue
		}
		switch {
		case e.Status == "left" && g.HasMember(pid):
			n.processLeave(pid, g.ID)
		case !g.HasMember(pid) && e.Version < g.Version:
			// The peer still believes it is a member: send the current
			// snapshot so it learns about its removal or the disbanding.
			_ = s.Send(protocol.TypeGroupUpdate, rooms.ToUpdate(&g))
		}
	}
}
