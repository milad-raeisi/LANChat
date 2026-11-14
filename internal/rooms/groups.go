// Package rooms holds the membership rules for public rooms and private
// groups. The functions are pure so the rules can be tested exhaustively.
//
// Group model (owner-authoritative, decentralized):
//   - The creator of a group is its owner for its whole life.
//   - Only the owner changes membership. Each change increments a version
//     counter and produces a complete snapshot (group.update).
//   - A snapshot is accepted only when it arrives over an authenticated
//     session from the owner itself, names the same owner as the local copy
//     and has a strictly greater version. Because there is a single writer,
//     concurrent conflicting updates cannot occur; the highest version wins.
//   - Members leave by notifying the owner (directly, or via group.sync on
//     the next connection if the owner was offline). The owner publishes the
//     new snapshot.
//   - Messages are accepted only from members of the local snapshot and are
//     sent only to members of the local snapshot.
package rooms

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// Errors returned by membership operations.
var (
	ErrNotOwner      = errors.New("only the group owner can do that")
	ErrNotMember     = errors.New("not a member of this group")
	ErrAlreadyMember = errors.New("already a member")
	ErrGroupFull     = fmt.Errorf("a group can have at most %d members", protocol.MaxGroupMembers)
	ErrOwnerLeave    = errors.New("the owner cannot leave; disband the group instead")
	ErrInactive      = errors.New("group is not active")
)

// ValidateGroupName checks a user-entered group name.
func ValidateGroupName(name string) error {
	t := strings.TrimSpace(name)
	if t == "" {
		return errors.New("group name must not be empty")
	}
	if utf8.RuneCountInString(t) > 48 {
		return errors.New("group name must be at most 48 characters")
	}
	for _, r := range t {
		if r < 0x20 || r == 0x7f {
			return errors.New("group name must not contain control characters")
		}
	}
	return nil
}

// UpdateAction is the outcome of evaluating an incoming group snapshot.
type UpdateAction int

// Update actions.
const (
	// Ignore leaves local state unchanged.
	Ignore UpdateAction = iota
	// Apply stores the snapshot with the returned local state.
	Apply
)

// UpdateDecision explains what to do with an incoming snapshot.
type UpdateDecision struct {
	Action UpdateAction
	// State is the resulting local state when Action == Apply.
	State string
	// Reason explains an Ignore decision (for logs).
	Reason string
	// Joined is true when the snapshot adds the local user to a group it was
	// not an active member of (an invitation).
	Joined bool
}

// EvaluateUpdate decides whether to apply a group snapshot received from
// sender. local is nil when the group is unknown.
func EvaluateUpdate(local *storage.Group, upd *protocol.GroupUpdate, sender, self identity.PeerID) UpdateDecision {
	if string(sender) != upd.OwnerID {
		return UpdateDecision{Reason: "snapshot not sent by the group owner"}
	}
	selfMember := false
	for _, m := range upd.Members {
		if m.PeerID == string(self) {
			selfMember = true
			break
		}
	}
	if local == nil {
		if upd.State != protocol.GroupActive || !selfMember {
			return UpdateDecision{Reason: "unknown group that does not include us"}
		}
		return UpdateDecision{Action: Apply, State: storage.GroupActive, Joined: true}
	}
	if string(local.OwnerID) != upd.OwnerID {
		return UpdateDecision{Reason: "owner does not match the local copy"}
	}
	if upd.Version <= local.Version {
		return UpdateDecision{Reason: "stale snapshot"}
	}
	if local.State == storage.GroupLeft {
		// We left; keep it that way. The owner learns about it via sync.
		return UpdateDecision{Reason: "group was left locally"}
	}
	switch {
	case upd.State == protocol.GroupDisbanded:
		return UpdateDecision{Action: Apply, State: storage.GroupDisbanded}
	case selfMember:
		return UpdateDecision{Action: Apply, State: storage.GroupActive, Joined: local.State != storage.GroupActive}
	default:
		return UpdateDecision{Action: Apply, State: storage.GroupRemoved}
	}
}

// FromUpdate converts a protocol snapshot into a storage group.
func FromUpdate(upd *protocol.GroupUpdate, state string) storage.Group {
	g := storage.Group{
		ID:      upd.GroupID,
		Name:    upd.Name,
		OwnerID: identity.PeerID(upd.OwnerID),
		Version: upd.Version,
		State:   state,
	}
	for _, m := range upd.Members {
		g.Members = append(g.Members, storage.GroupMember{PeerID: identity.PeerID(m.PeerID), DisplayName: m.DisplayName})
	}
	return g
}

// ToUpdate converts a group into a protocol snapshot.
func ToUpdate(g *storage.Group) *protocol.GroupUpdate {
	upd := &protocol.GroupUpdate{
		GroupID: g.ID,
		Name:    g.Name,
		OwnerID: string(g.OwnerID),
		Version: g.Version,
		State:   protocol.GroupActive,
	}
	if g.State == storage.GroupDisbanded {
		upd.State = protocol.GroupDisbanded
	}
	for _, m := range g.Members {
		upd.Members = append(upd.Members, protocol.GroupMember{PeerID: string(m.PeerID), DisplayName: m.DisplayName})
	}
	return upd
}

// CanSend reports whether self may send messages to the group.
func CanSend(g *storage.Group, self identity.PeerID) bool {
	return g.State == storage.GroupActive && g.HasMember(self)
}

// AcceptMessage reports whether a message from sender to the group should
// be accepted locally.
func AcceptMessage(g *storage.Group, sender, self identity.PeerID) bool {
	return CanSend(g, self) && g.HasMember(sender)
}

// Recipients returns every member except self.
func Recipients(g *storage.Group, self identity.PeerID) []identity.PeerID {
	var out []identity.PeerID
	for _, m := range g.Members {
		if m.PeerID != self {
			out = append(out, m.PeerID)
		}
	}
	return out
}

// NewGroup creates a group owned by owner.
func NewGroup(id, name string, owner storage.GroupMember) (storage.Group, error) {
	if err := ValidateGroupName(name); err != nil {
		return storage.Group{}, err
	}
	return storage.Group{
		ID:      id,
		Name:    strings.TrimSpace(name),
		OwnerID: owner.PeerID,
		Version: 1,
		State:   storage.GroupActive,
		Members: []storage.GroupMember{owner},
	}, nil
}

func ownerCheck(g *storage.Group, actor identity.PeerID) error {
	if g.OwnerID != actor {
		return ErrNotOwner
	}
	if g.State != storage.GroupActive {
		return ErrInactive
	}
	return nil
}

// AddMember returns a copy of g with member added and the version bumped.
func AddMember(g storage.Group, actor identity.PeerID, member storage.GroupMember) (storage.Group, error) {
	if err := ownerCheck(&g, actor); err != nil {
		return g, err
	}
	if g.HasMember(member.PeerID) {
		return g, ErrAlreadyMember
	}
	if len(g.Members) >= protocol.MaxGroupMembers {
		return g, ErrGroupFull
	}
	g.Members = append(append([]storage.GroupMember(nil), g.Members...), member)
	g.Version++
	return g, nil
}

// RemoveMember returns a copy of g without member. Only the owner may
// remove others and the owner cannot remove itself.
func RemoveMember(g storage.Group, actor, member identity.PeerID) (storage.Group, error) {
	if err := ownerCheck(&g, actor); err != nil {
		return g, err
	}
	if member == g.OwnerID {
		return g, ErrOwnerLeave
	}
	return without(g, member)
}

// ProcessLeave applies a leave notification received by the owner.
func ProcessLeave(g storage.Group, self, leaver identity.PeerID) (storage.Group, error) {
	if g.OwnerID != self {
		return g, ErrNotOwner
	}
	if g.State != storage.GroupActive {
		return g, ErrInactive
	}
	if leaver == g.OwnerID {
		return g, ErrOwnerLeave
	}
	return without(g, leaver)
}

// Disband marks the group as disbanded.
func Disband(g storage.Group, actor identity.PeerID) (storage.Group, error) {
	if err := ownerCheck(&g, actor); err != nil {
		return g, err
	}
	g.State = storage.GroupDisbanded
	g.Version++
	return g, nil
}

func without(g storage.Group, member identity.PeerID) (storage.Group, error) {
	if !g.HasMember(member) {
		return g, ErrNotMember
	}
	var keep []storage.GroupMember
	for _, m := range g.Members {
		if m.PeerID != member {
			keep = append(keep, m)
		}
	}
	g.Members = keep
	g.Version++
	return g, nil
}
