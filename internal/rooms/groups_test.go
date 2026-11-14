package rooms

import (
	"errors"
	"testing"

	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

func pid(t *testing.T) identity.PeerID {
	id, _ := ident(t)
	return id
}

func ident(t *testing.T) (identity.PeerID, []byte) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id.ID(), identity.SPKI(id.PublicKey())
}

func TestOwnerOperations(t *testing.T) {
	owner, ownerKey := ident(t)
	alice, bob := pid(t), pid(t)
	g, err := NewGroup(ownerKey, "  Project X ", storage.GroupMember{PeerID: owner, DisplayName: "Owner"})
	if err != nil || g.Name != "Project X" || g.Version != 1 || g.ID != DeriveGroupID(ownerKey, g.Salt) {
		t.Fatalf("NewGroup: %+v %v", g, err)
	}
	g, err = AddMember(g, owner, storage.GroupMember{PeerID: alice, DisplayName: "Alice"})
	if err != nil || g.Version != 2 || !g.HasMember(alice) {
		t.Fatalf("AddMember: %v", err)
	}
	if _, err := AddMember(g, alice, storage.GroupMember{PeerID: bob}); !errors.Is(err, ErrNotOwner) {
		t.Fatal("non-owner added a member")
	}
	if _, err := AddMember(g, owner, storage.GroupMember{PeerID: alice}); !errors.Is(err, ErrAlreadyMember) {
		t.Fatal("duplicate member")
	}
	if _, err := RemoveMember(g, alice, owner); !errors.Is(err, ErrNotOwner) {
		t.Fatal("member removed the owner")
	}
	if _, err := RemoveMember(g, owner, owner); !errors.Is(err, ErrOwnerLeave) {
		t.Fatal("owner removed itself")
	}
	g2, err := ProcessLeave(g, owner, alice)
	if err != nil || g2.HasMember(alice) || g2.Version != 3 {
		t.Fatalf("ProcessLeave: %v", err)
	}
	if !AcceptMessage(&g, alice, owner) || AcceptMessage(&g, bob, owner) {
		t.Fatal("AcceptMessage membership check")
	}
	if r := Recipients(&g, owner); len(r) != 1 || r[0] != alice {
		t.Fatalf("Recipients = %v", r)
	}
	d, err := Disband(g, owner)
	if err != nil || d.State != storage.GroupDisbanded || CanSend(&d, owner) {
		t.Fatal("Disband")
	}
	if _, err := ValidateGroupNameErr("\x1b"); err == nil {
		t.Fatal("control char accepted")
	}
}

func ValidateGroupNameErr(s string) (struct{}, error) { return struct{}{}, ValidateGroupName(s) }

func TestEvaluateUpdate(t *testing.T) {
	owner, ownerKey := ident(t)
	self := pid(t)
	mallory, malloryKey := ident(t)
	salt := NewSalt()
	gid := DeriveGroupID(ownerKey, salt)
	upd := func(version uint64, state string, members ...identity.PeerID) *protocol.GroupUpdate {
		u := &protocol.GroupUpdate{GroupID: gid, Salt: salt, Name: "G", OwnerID: string(owner), Version: version, State: state}
		for _, m := range members {
			u.Members = append(u.Members, protocol.GroupMember{PeerID: string(m)})
		}
		return u
	}

	// Invitation to an unknown group.
	d := EvaluateUpdate(nil, upd(1, protocol.GroupActive, owner, self), owner, ownerKey, self)
	if d.Action != Apply || !d.Joined || d.State != storage.GroupActive {
		t.Fatalf("invite: %+v", d)
	}
	// Forged snapshot relayed by a non-owner.
	if d := EvaluateUpdate(nil, upd(1, protocol.GroupActive, owner, self), mallory, malloryKey, self); d.Action != Ignore {
		t.Fatal("snapshot from non-owner applied")
	}
	// Group-ID hijack: Mallory names herself owner of the real group's ID.
	hijack := upd(1, protocol.GroupActive, mallory, self)
	hijack.OwnerID = string(mallory)
	if d := EvaluateUpdate(nil, hijack, mallory, malloryKey, self); d.Action != Ignore {
		t.Fatal("group id claimed by a peer whose key it is not derived from")
	}
	// Mallory's own, correctly derived group is fine.
	msalt := NewSalt()
	own := &protocol.GroupUpdate{GroupID: DeriveGroupID(malloryKey, msalt), Salt: msalt, Name: "M", OwnerID: string(mallory), Version: 1,
		State: protocol.GroupActive, Members: []protocol.GroupMember{{PeerID: string(mallory)}, {PeerID: string(self)}}}
	if d := EvaluateUpdate(nil, own, mallory, malloryKey, self); d.Action != Apply {
		t.Fatalf("legitimate group rejected: %+v", d)
	}
	// Unknown group not including us.
	if d := EvaluateUpdate(nil, upd(1, protocol.GroupActive, owner), owner, ownerKey, self); d.Action != Ignore {
		t.Fatal("foreign group applied")
	}

	local := FromUpdate(upd(3, protocol.GroupActive, owner, self), storage.GroupActive)
	if d := EvaluateUpdate(&local, upd(3, protocol.GroupActive, owner, self), owner, ownerKey, self); d.Action != Ignore {
		t.Fatal("same version applied")
	}
	if d := EvaluateUpdate(&local, upd(2, protocol.GroupActive, owner), owner, ownerKey, self); d.Action != Ignore {
		t.Fatal("stale version applied")
	}
	if d := EvaluateUpdate(&local, upd(4, protocol.GroupActive, owner), owner, ownerKey, self); d.Action != Apply || d.State != storage.GroupRemoved {
		t.Fatalf("removal: %+v", d)
	}
	if d := EvaluateUpdate(&local, upd(5, protocol.GroupDisbanded, owner, self), owner, ownerKey, self); d.State != storage.GroupDisbanded {
		t.Fatalf("disband: %+v", d)
	}
	left := local
	left.State = storage.GroupLeft
	if d := EvaluateUpdate(&left, upd(6, protocol.GroupActive, owner, self), owner, ownerKey, self); d.Action != Ignore {
		t.Fatal("left group silently re-joined")
	}
	round := ToUpdate(&local)
	if round.Version != local.Version || len(round.Members) != 2 || round.Salt != salt || round.Validate() != nil {
		t.Fatalf("ToUpdate: %+v %v", round, round.Validate())
	}
}
