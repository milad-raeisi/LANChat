package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func newPeer(t *testing.T) (identity.PeerID, []byte) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id.ID(), identity.SPKI(id.PublicKey())
}

func TestOpenMigratesAndReopens(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	v, err := s.SchemaVersion(ctx)
	if err != nil || v != LatestSchemaVersion() || v < 1 {
		t.Fatalf("schema version %d err %v", v, err)
	}
	c, err := s.GetConversation(ctx, GeneralRoomID)
	if err != nil || c.Title != "general" || !c.Joined {
		t.Fatalf("general room missing: %+v %v", c, err)
	}
	if err := s.QuickCheck(ctx); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = s2.Close()
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("database permissions too open: %v", st.Mode().Perm())
		}
	}
}

func TestCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.db")
	if err := os.WriteFile(path, []byte("this is definitely not an sqlite database file, just text padding......"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), path)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt, got %v", err)
	}
}

func TestPeersAndTrust(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	id, key := newPeer(t)
	now := time.Now()
	if err := s.RecordPeerSeen(ctx, PeerSeen{ID: id, PublicKey: key, DisplayName: "Maryam", DeviceName: "PC", Address: "10.0.0.2:47777", At: now}); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetPeer(ctx, id)
	if err != nil || p.Trust != TrustUnknown || p.DisplayName != "Maryam" {
		t.Fatalf("got %+v %v", p, err)
	}
	if err := s.SetTrust(ctx, id, TrustTrusted, true, now); err != nil {
		t.Fatal(err)
	}
	// Re-seeing a peer must not change trust.
	if err := s.RecordPeerSeen(ctx, PeerSeen{ID: id, PublicKey: key, DisplayName: "Maryam R", At: now}); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPeer(ctx, id)
	if p.Trust != TrustTrusted || !p.Verified || p.DisplayName != "Maryam R" || p.LastAddress != "10.0.0.2:47777" {
		t.Fatalf("unexpected %+v", p)
	}
	_, otherKey := newPeer(t)
	if err := s.RecordPeerSeen(ctx, PeerSeen{ID: id, PublicKey: otherKey, DisplayName: "x", At: now}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("key change not detected: %v", err)
	}
	named, err := s.TrustedPeersNamed(ctx, "maryam r", "")
	if err != nil || len(named) != 1 {
		t.Fatalf("TrustedPeersNamed = %v %v", named, err)
	}
	if _, err := s.GetPeer(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected ErrNotFound")
	}
}

func TestMessagesDeliveriesAndDedup(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	self, _ := newPeer(t)
	bob, _ := newPeer(t)
	carol, _ := newPeer(t)
	conv := GeneralRoomID

	out := &Message{ID: protocol.NewID(), ConversationID: conv, SenderID: self, SenderName: "me", Body: "hello", SentAt: time.Now(), ReceivedAt: time.Now(), Outgoing: true}
	ok, err := s.InsertMessage(ctx, out, []identity.PeerID{bob, carol})
	if err != nil || !ok || out.Seq == 0 {
		t.Fatalf("insert: %v %v", ok, err)
	}
	dup := *out
	ok, err = s.InsertMessage(ctx, &dup, []identity.PeerID{bob})
	if err != nil || ok {
		t.Fatalf("duplicate inserted: %v %v", ok, err)
	}
	// Same message id from a different sender is a different message.
	in := &Message{ID: out.ID, ConversationID: conv, SenderID: bob, SenderName: "bob", Body: "hi", SentAt: time.Now(), ReceivedAt: time.Now()}
	if ok, err := s.InsertMessage(ctx, in, nil); err != nil || !ok {
		t.Fatalf("message from other sender rejected: %v %v", ok, err)
	}

	pend, err := s.PendingFor(ctx, bob, 0)
	if err != nil || len(pend) != 1 || pend[0].Body != "hello" {
		t.Fatalf("pending = %+v %v", pend, err)
	}
	if err := s.MarkDelivery(ctx, out.Seq, bob, DeliverySent, ""); err != nil {
		t.Fatal(err)
	}
	// Carol cannot acknowledge on Bob's behalf; acks only touch the acking peer's row.
	r, err := s.ApplyAck(ctx, self, bob, out.ID, DeliveryDelivered, "")
	if err != nil || !r.Changed || r.ConversationID != conv {
		t.Fatalf("ack: %+v %v", r, err)
	}
	r, _ = s.ApplyAck(ctx, self, bob, out.ID, DeliveryDelivered, "")
	if r.Changed {
		t.Fatal("second ack changed state")
	}
	if _, err := s.ApplyAck(ctx, self, bob, protocol.NewID(), DeliveryDelivered, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("ack for unknown message accepted")
	}
	// A delivered row is never downgraded.
	_ = s.MarkDelivery(ctx, out.Seq, bob, DeliveryFailed, "late failure")

	msgs, err := s.Messages(ctx, conv, 0, 50)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("messages: %v %v", msgs, err)
	}
	if msgs[0].Seq > msgs[1].Seq {
		t.Fatal("messages not in ascending order")
	}
	if d := msgs[0].Delivery; d.Delivered != 1 || d.Pending != 1 || d.Total() != 2 {
		t.Fatalf("delivery summary %+v", d)
	}

	c, _ := s.GetConversation(ctx, conv)
	if c.Unread != 1 {
		t.Fatalf("unread = %d, want 1 (outgoing messages do not count)", c.Unread)
	}
	_ = s.MarkRead(ctx, conv, c.LastSeq)
	c, _ = s.GetConversation(ctx, conv)
	if c.Unread != 0 {
		t.Fatalf("unread after MarkRead = %d", c.Unread)
	}

	res, err := s.Search(ctx, "HELLO", "", 10)
	if err != nil || len(res) != 1 {
		t.Fatalf("search: %v %v", res, err)
	}
	if res, _ := s.Search(ctx, "%", "", 10); len(res) != 0 {
		t.Fatal("search treats % as wildcard")
	}

	// Expiry: carol's row is pending and created "now"; a cutoff in the
	// future expires it, but the message itself is kept.
	convs, err := s.ExpireDeliveries(ctx, time.Now().Add(time.Hour), 100)
	if err != nil || len(convs) != 1 {
		t.Fatalf("expire: %v %v", convs, err)
	}
	m, _ := s.GetMessage(ctx, out.Seq)
	if m.Delivery.Failed != 1 || m.Delivery.Delivered != 1 {
		t.Fatalf("after expiry %+v", m.Delivery)
	}
	if n, _ := s.RetryFailed(ctx, conv); n != 1 {
		t.Fatalf("RetryFailed = %d", n)
	}
	if n, _ := s.CountQueued(ctx, carol); n != 1 {
		t.Fatalf("CountQueued = %d", n)
	}

	n, err := s.DeleteHistory(ctx, conv)
	if err != nil || n != 2 {
		t.Fatalf("delete: %d %v", n, err)
	}
	if n, _ := s.CountQueued(ctx, carol); n != 0 {
		t.Fatal("deliveries not cascaded on delete")
	}
}

func TestGroupsAndTransfers(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	owner, _ := newPeer(t)
	member, _ := newPeer(t)
	g := Group{ID: protocol.NewID(), Salt: protocol.NewID(), Name: "Project X", OwnerID: owner, Version: 1, State: GroupActive,
		Members: []GroupMember{{PeerID: owner, DisplayName: "Owner"}, {PeerID: member, DisplayName: "Member"}}}
	if err := s.SaveGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	g.Version = 2
	g.Members = g.Members[:1]
	if err := s.SaveGroup(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGroup(ctx, g.ID)
	if err != nil || got.Version != 2 || len(got.Members) != 1 || got.HasMember(member) || got.Salt != g.Salt {
		t.Fatalf("group: %+v %v", got, err)
	}
	c, err := s.GetConversation(ctx, GroupConversationID(g.ID))
	if err != nil || c.Kind != KindGroup || !c.Joined {
		t.Fatalf("group conversation %+v %v", c, err)
	}
	g.State = GroupLeft
	_ = s.SaveGroup(ctx, g)
	c, _ = s.GetConversation(ctx, GroupConversationID(g.ID))
	if c.Joined {
		t.Fatal("left group still joined")
	}
	if list, _ := s.ListGroups(ctx); len(list) != 1 {
		t.Fatal("ListGroups")
	}
	if n, _ := s.CountActiveGroups(ctx); n != 0 {
		t.Fatalf("left group counted as active: %d", n)
	}

	tr := TransferRecord{ID: protocol.NewID(), PeerID: member, Direction: "in", FileName: "a.txt", Size: 3, State: "offered"}
	if err := s.SaveTransfer(ctx, tr); err != nil {
		t.Fatal(err)
	}
	tr.State = "completed"
	tr.Path = "/tmp/a.txt"
	_ = s.SaveTransfer(ctx, tr)
	list, err := s.ListTransfers(ctx, 10)
	if err != nil || len(list) != 1 || list[0].State != "completed" {
		t.Fatalf("transfers %+v %v", list, err)
	}
}

func TestBackup(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	dest := filepath.Join(filepath.Dir(path), "backup.db")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, dest); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	b, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.GetConversation(ctx, GeneralRoomID); err != nil {
		t.Fatal(err)
	}
}

func TestConversationIDs(t *testing.T) {
	k, key, err := ParseConversationID("group:abc")
	if err != nil || k != KindGroup || key != "abc" {
		t.Fatal("parse group")
	}
	for _, bad := range []string{"", "room:", "x:y", "nocolon"} {
		if _, _, err := ParseConversationID(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
