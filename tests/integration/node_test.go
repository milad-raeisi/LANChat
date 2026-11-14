package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/network/transport"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/protocol"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

func TestPairingAndDirectMessage(t *testing.T) {
	milad := startNode(t, "Milad", "")
	maryam := startNode(t, "Maryam", "")
	connect(milad, maryam)
	eventually(t, "connected", 10*time.Second, func() bool { return milad.connectedTo(maryam) })

	// Discovered and connected, but not trusted: no messaging yet.
	dm, err := milad.OpenDirect(context.Background(), maryam.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := milad.SendText(context.Background(), dm, "too early"); !errors.Is(err, node.ErrNotPaired) {
		t.Fatalf("message to unpaired peer: %v", err)
	}

	pair(t, milad, maryam)
	p, _ := maryam.Peer(milad.ID())
	if !p.Verified || p.Trust != storage.TrustTrusted {
		t.Fatalf("trust not persisted: %+v", p)
	}

	sent, err := milad.SendText(context.Background(), dm, "Hello Maryam! 👋")
	if err != nil {
		t.Fatal(err)
	}
	if !sent.Outgoing || sent.Delivery.Total() != 1 {
		t.Fatalf("unexpected sent message %+v", sent)
	}
	back := storage.DirectConversationID(milad.ID())
	eventually(t, "maryam received", 5*time.Second, func() bool { return maryam.hasMessage(back, "Hello Maryam! 👋") })
	eventually(t, "delivered ack", 5*time.Second, func() bool {
		return milad.message(dm, "Hello Maryam! 👋").Delivery.Delivered == 1
	})
	got := maryam.message(back, "Hello Maryam! 👋")
	if got.SenderID != milad.ID() || got.SenderName != "Milad" {
		t.Fatalf("sender not bound to authenticated identity: %+v", got)
	}

	// And the other direction.
	if _, err := maryam.SendText(context.Background(), back, "Hi Milad"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "reply", 5*time.Second, func() bool { return milad.hasMessage(dm, "Hi Milad") })
	rtt, err := milad.Ping(context.Background(), maryam.ID())
	if err != nil || rtt <= 0 {
		t.Fatalf("ping: %v %v", rtt, err)
	}
}

func TestPublicRoomsThreeUsers(t *testing.T) {
	a := startNode(t, "Ali", "")
	b := startNode(t, "Yumna", "")
	c := startNode(t, "Reza", "")
	pair(t, a, b)
	pair(t, a, c)
	pair(t, b, c)

	if _, err := a.SendText(context.Background(), storage.GeneralRoomID, "Good morning!"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []*testNode{b, c} {
		n := n
		eventually(t, n.name+" got room message", 5*time.Second, func() bool { return n.hasMessage(storage.GeneralRoomID, "Good morning!") })
	}
	eventually(t, "delivered to both", 5*time.Second, func() bool {
		return a.message(storage.GeneralRoomID, "Good morning!").Delivery.Delivered == 2
	})

	// Custom room: only members receive messages.
	if _, err := a.JoinRoom(context.Background(), "#Development"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.JoinRoom(context.Background(), "development"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "room membership announced", 5*time.Second, func() bool { return len(a.RoomMembers("development")) == 1 })
	if _, err := a.SendText(context.Background(), storage.RoomConversationID("development"), "standup in 5"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "dev message", 5*time.Second, func() bool { return b.hasMessage(storage.RoomConversationID("development"), "standup in 5") })
	time.Sleep(300 * time.Millisecond)
	if c.hasMessage(storage.RoomConversationID("development"), "standup in 5") {
		t.Fatal("non-member received a room message")
	}
	if err := c.LeaveRoom(context.Background(), "general"); err == nil {
		t.Fatal("general must not be leavable")
	}
}

func TestGroupLifecycle(t *testing.T) {
	owner := startNode(t, "Owner", "")
	m1 := startNode(t, "Member1", "")
	m2 := startNode(t, "Member2", "")
	pair(t, owner, m1)
	pair(t, owner, m2)
	pair(t, m1, m2)

	conv, err := owner.CreateGroup(context.Background(), "Project X", []identity.PeerID{m1.ID(), m2.ID()})
	if err != nil {
		t.Fatal(err)
	}
	groupID := conv[len("group:"):]
	for _, n := range []*testNode{m1, m2} {
		n := n
		eventually(t, n.name+" invited", 5*time.Second, func() bool {
			g, err := n.Group(context.Background(), groupID)
			return err == nil && g.State == storage.GroupActive && len(g.Members) == 3
		})
	}
	if _, err := m1.SendText(context.Background(), conv, "hello group"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "group fan-out", 5*time.Second, func() bool {
		return owner.hasMessage(conv, "hello group") && m2.hasMessage(conv, "hello group")
	})

	// Non-owners cannot change membership.
	if err := m1.RemoveFromGroup(context.Background(), groupID, m2.ID()); err == nil {
		t.Fatal("member removed another member")
	}

	if err := owner.RemoveFromGroup(context.Background(), groupID, m2.ID()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "m2 learns removal", 5*time.Second, func() bool {
		g, _ := m2.Group(context.Background(), groupID)
		return g.State == storage.GroupRemoved
	})
	eventually(t, "m1 sees new membership", 5*time.Second, func() bool {
		g, _ := m1.Group(context.Background(), groupID)
		return len(g.Members) == 2
	})
	if _, err := m2.SendText(context.Background(), conv, "can I still talk?"); err == nil {
		t.Fatal("removed member could send")
	}
	if _, err := m1.SendText(context.Background(), conv, "secret plan"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "owner got secret", 5*time.Second, func() bool { return owner.hasMessage(conv, "secret plan") })
	time.Sleep(300 * time.Millisecond)
	if m2.hasMessage(conv, "secret plan") {
		t.Fatal("removed member received a group message")
	}

	// Member leaves; owner updates membership.
	if err := m1.LeaveGroup(context.Background(), groupID); err != nil {
		t.Fatal(err)
	}
	eventually(t, "owner processed leave", 5*time.Second, func() bool {
		g, _ := owner.Group(context.Background(), groupID)
		return len(g.Members) == 1
	})
	if err := owner.LeaveGroup(context.Background(), groupID); err != nil {
		t.Fatal(err)
	}
	g, _ := owner.Group(context.Background(), groupID)
	if g.State != storage.GroupDisbanded {
		t.Fatalf("owner leave should disband, state=%s", g.State)
	}
}

func TestOfflineQueueAndReconnect(t *testing.T) {
	a := startNode(t, "Sender", "")
	b := startNode(t, "Receiver", "")
	pair(t, a, b)
	dm, _ := a.OpenDirect(context.Background(), b.ID())

	bHome := b.home
	b.stop()
	eventually(t, "a notices b offline", 10*time.Second, func() bool { return !a.connectedTo(b) })

	for i := 0; i < 3; i++ {
		if _, err := a.SendText(context.Background(), dm, "queued "+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	m := a.message(dm, "queued 0")
	if m.Delivery.Pending != 1 {
		t.Fatalf("offline message should be pending: %+v", m.Delivery)
	}

	// Same identity and database, new port: as after a Wi-Fi reconnect.
	b2 := startNode(t, "Receiver", bHome)
	if b2.ID() != b.ID() {
		t.Fatal("identity changed across restart")
	}
	connect(a, b2)
	back := storage.DirectConversationID(a.ID())
	eventually(t, "queued messages delivered", 10*time.Second, func() bool {
		return b2.countMessage(back, "queued 0") == 1 && b2.countMessage(back, "queued 2") == 1
	})
	eventually(t, "acks", 5*time.Second, func() bool {
		return a.message(dm, "queued 2").Delivery.Delivered == 1
	})
	// Trust survived the restart.
	p, _ := b2.Peer(a.ID())
	if !p.Trusted() {
		t.Fatal("trust lost across restart")
	}
	// Force a resend of everything already delivered: still exactly once.
	a.RefreshDiscovery()
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if c := b2.countMessage(back, "queued "+strconv.Itoa(i)); c != 1 {
			t.Fatalf("message %d stored %d times", i, c)
		}
	}
}

func TestSimultaneousConnectionsDeduplicated(t *testing.T) {
	for i := 0; i < 5; i++ {
		a := startNode(t, "A", "")
		b := startNode(t, "B", "")
		// Both sides learn about each other at the same moment and dial.
		connect(a, b)
		eventually(t, "connected", 10*time.Second, func() bool { return a.connectedTo(b) && b.connectedTo(a) })
		time.Sleep(2 * time.Second)
		if !a.connectedTo(b) || !b.connectedTo(a) {
			t.Fatal("deduplication dropped both sessions")
		}
		if st := a.NetworkStatus(); st.Sessions != 1 {
			t.Fatalf("a has %d sessions", st.Sessions)
		}
		a.stop()
		b.stop()
	}
}

func TestFileTransfer(t *testing.T) {
	a := startNode(t, "Alice", "")
	b := startNode(t, "Bob", "")
	pair(t, a, b)

	data := make([]byte, 3*1024*1024+123) // spans many 64 KiB chunks
	_, _ = rand.Read(data)
	src := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := a.SendFile(context.Background(), b.ID(), src)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "offer arrives", 5*time.Second, func() bool {
		for _, tr := range b.Transfers() {
			if tr.ID == id && tr.State == node.TransferIncoming {
				return true
			}
		}
		return false
	})
	// Chat keeps working while the offer is pending.
	dm, _ := a.OpenDirect(context.Background(), b.ID())
	if _, err := a.SendText(context.Background(), dm, "sending you the report"); err != nil {
		t.Fatal(err)
	}
	if err := b.RespondFile(context.Background(), id, true); err != nil {
		t.Fatal(err)
	}
	var final node.TransferInfo
	eventually(t, "transfer completes", 20*time.Second, func() bool {
		for _, tr := range b.Transfers() {
			if tr.ID == id && tr.State == node.TransferCompleted {
				final = tr
				return true
			}
		}
		return false
	})
	got, err := os.ReadFile(final.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("received file differs")
	}
	if filepath.Dir(final.Path) != b.cfg.Transfer.DownloadDir || filepath.Base(final.Path) != "report.pdf" {
		t.Fatalf("unexpected destination %s", final.Path)
	}
	eventually(t, "sender sees completion", 5*time.Second, func() bool {
		for _, tr := range a.Transfers() {
			if tr.ID == id {
				return tr.State == node.TransferCompleted
			}
		}
		return false
	})
	// A second transfer with the same name does not overwrite.
	id2, _ := a.SendFile(context.Background(), b.ID(), src)
	eventually(t, "second offer", 5*time.Second, func() bool {
		for _, tr := range b.Transfers() {
			if tr.ID == id2 {
				return true
			}
		}
		return false
	})
	_ = b.RespondFile(context.Background(), id2, true)
	eventually(t, "second file", 20*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(b.cfg.Transfer.DownloadDir, "report (1).pdf"))
		return err == nil
	})

	// Rejection.
	id3, _ := a.SendFile(context.Background(), b.ID(), src)
	eventually(t, "third offer", 5*time.Second, func() bool {
		for _, tr := range b.Transfers() {
			if tr.ID == id3 {
				return true
			}
		}
		return false
	})
	_ = b.RespondFile(context.Background(), id3, false)
	eventually(t, "sender sees rejection", 5*time.Second, func() bool {
		for _, tr := range a.Transfers() {
			if tr.ID == id3 {
				return tr.State == node.TransferRejected
			}
		}
		return false
	})
}

func TestFileSizeLimitAndCancel(t *testing.T) {
	a := startNode(t, "A", "")
	b := startNode(t, "B", "", func(c *config.Config) { c.Transfer.MaxFileSizeMB = 1 })
	pair(t, a, b)
	big := filepath.Join(t.TempDir(), "big.bin")
	_ = os.WriteFile(big, make([]byte, 2*1024*1024), 0o600)
	id, err := a.SendFile(context.Background(), b.ID(), big)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "auto rejected", 5*time.Second, func() bool {
		for _, tr := range a.Transfers() {
			if tr.ID == id {
				return tr.State == node.TransferRejected
			}
		}
		return false
	})
	small := filepath.Join(t.TempDir(), "small.bin")
	_ = os.WriteFile(small, []byte("x"), 0o600)
	id2, _ := a.SendFile(context.Background(), b.ID(), small)
	eventually(t, "offer", 5*time.Second, func() bool {
		for _, tr := range b.Transfers() {
			if tr.ID == id2 {
				return true
			}
		}
		return false
	})
	if err := a.CancelTransfer(id2); err != nil {
		t.Fatal(err)
	}
	eventually(t, "receiver sees cancel", 5*time.Second, func() bool {
		for _, tr := range b.Transfers() {
			if tr.ID == id2 {
				return tr.State == node.TransferCancelled
			}
		}
		return false
	})
}

// rawPeer connects to a node with a fresh identity using the transport
// package directly, bypassing the node's safety logic, to act as a
// misbehaving or malicious peer.
func rawPeer(t *testing.T, target *testNode, name string) (*transport.Session, *identity.Identity) {
	t.Helper()
	id, _ := identity.Generate()
	cfg, err := transport.NewConfig(id, func() protocol.Hello {
		return protocol.Hello{DisplayName: name, DeviceName: name + "-device", ListenPort: 1, App: "raw"}
	}, 5*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := transport.Dial(context.Background(), cfg, []string{"127.0.0.1:" + strconv.Itoa(target.Self().Port)}, target.ID())
	if err != nil {
		t.Fatal(err)
	}
	return s, id
}

type nopHandler struct{ closed chan error }

func (h *nopHandler) HandleFrame(*transport.Session, *protocol.Frame) error { return nil }
func (h *nopHandler) SessionClosed(_ *transport.Session, err error) {
	if h.closed != nil {
		h.closed <- err
	}
}

func TestUntrustedAndUnsolicitedTrustIsRefused(t *testing.T) {
	victim := startNode(t, "Victim", "")
	s, attacker := rawPeer(t, victim, "Mallory")
	s.Start(&nopHandler{})
	defer s.Close(nil)

	// An unsolicited acceptance must not create trust.
	_ = s.Send(protocol.TypePairAccept, protocol.PairResponse{})
	// A chat message from an unpaired peer must not be stored.
	_ = s.Send(protocol.TypeChat, protocol.ChatMessage{MessageID: protocol.NewID(), Kind: protocol.ConvDirect, Body: "click this link", SentAt: 1})
	// Group invitations from unpaired peers are ignored.
	_ = s.Send(protocol.TypeGroupUpdate, protocol.GroupUpdate{GroupID: protocol.NewID(), Name: "spam", OwnerID: string(attacker.ID()), Version: 1, State: protocol.GroupActive,
		Members: []protocol.GroupMember{{PeerID: string(attacker.ID())}, {PeerID: string(victim.ID())}}})
	eventually(t, "attacker visible as unpaired peer", 5*time.Second, func() bool {
		p, ok := victim.Peer(attacker.ID())
		return ok && p.Connected
	})
	time.Sleep(500 * time.Millisecond)
	p, _ := victim.Peer(attacker.ID())
	if p.Trusted() {
		t.Fatal("unsolicited pair.accept granted trust")
	}
	if victim.hasMessage(storage.DirectConversationID(attacker.ID()), "click this link") {
		t.Fatal("message from unpaired peer was stored")
	}
	convs, _ := victim.Conversations(context.Background())
	for _, c := range convs {
		if c.Kind == storage.KindGroup {
			t.Fatal("group invitation from unpaired peer accepted")
		}
	}
}

func TestMalformedTrafficDoesNotHurtNode(t *testing.T) {
	victim := startNode(t, "Victim", "")
	addr := "127.0.0.1:" + strconv.Itoa(victim.Self().Port)
	// Plain garbage instead of a TLS handshake.
	if c, err := net.Dial("tcp", addr); err == nil {
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = c.Close()
	}
	// An authenticated peer sending a body that violates the schema.
	s, _ := rawPeer(t, victim, "Fuzzer")
	h := &nopHandler{closed: make(chan error, 1)}
	s.Start(h)
	_ = s.Send(protocol.TypeChat, map[string]any{"message_id": "not-an-id", "kind": "room", "room": "../../etc", "body": ""})
	select {
	case <-h.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("protocol violation did not close the session")
	}
	// The node still works for legitimate peers.
	friend := startNode(t, "Friend", "")
	pair(t, victim, friend)
	dm, _ := friend.OpenDirect(context.Background(), victim.ID())
	if _, err := friend.SendText(context.Background(), dm, "still alive?"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "message after attack", 5*time.Second, func() bool {
		return victim.hasMessage(storage.DirectConversationID(friend.ID()), "still alive?")
	})
}

func TestAdvertWithWrongIdentityIsFlagged(t *testing.T) {
	a := startNode(t, "A", "")
	b := startNode(t, "B", "")
	impostorID, _ := identity.Generate()
	// Discovery claims that impostorID lives at B's address.
	a.disc.ch <- discovery.Event{Advert: discovery.Advert{
		Source: discovery.SourceMDNS, Key: "spoof", PeerID: impostorID.ID(), DisplayName: "Trusted Friend",
		Addrs:  []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(b.Self().Port))},
		SeenAt: time.Now(), TTL: time.Hour,
	}}
	eventually(t, "mismatch flagged", 10*time.Second, func() bool {
		p, ok := a.Peer(impostorID.ID())
		return ok && p.Warning != "" && !p.Connected
	})
}

func TestImpersonationWarningAndRevoke(t *testing.T) {
	a := startNode(t, "Alice", "")
	maryam := startNode(t, "Maryam", "")
	pair(t, a, maryam)

	// A different identity using Maryam's exact name and device name.
	fake := startNode(t, "Maryam", "")
	connect(a, fake)
	eventually(t, "impersonation warning", 10*time.Second, func() bool {
		p, ok := a.Peer(fake.ID())
		return ok && p.Connected && p.Warning != "" && !p.Trusted()
	})

	// Revoking stops message exchange.
	if err := a.Revoke(context.Background(), maryam.ID()); err != nil {
		t.Fatal(err)
	}
	dm := storage.DirectConversationID(a.ID())
	if _, err := maryam.OpenDirect(context.Background(), a.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := maryam.SendText(context.Background(), dm, "are we still friends?"); err != nil {
		t.Fatal(err) // Maryam still trusts Alice locally
	}
	eventually(t, "message rejected", 5*time.Second, func() bool {
		return maryam.message(dm, "are we still friends?").Delivery.Failed == 1
	})
	if a.hasMessage(storage.DirectConversationID(maryam.ID()), "are we still friends?") {
		t.Fatal("revoked peer's message stored")
	}
	if _, err := a.SendText(context.Background(), storage.DirectConversationID(maryam.ID()), "x"); !errors.Is(err, node.ErrNotPaired) {
		t.Fatalf("sending to revoked peer: %v", err)
	}
}

func TestExportAndSearch(t *testing.T) {
	a := startNode(t, "A", "")
	b := startNode(t, "B", "")
	pair(t, a, b)
	_, _ = a.SendText(context.Background(), storage.GeneralRoomID, "the quick brown fox")
	_, _ = a.SendText(context.Background(), storage.GeneralRoomID, "evil \x1b[2J escape")
	res, err := a.Search(context.Background(), "QUICK", "")
	if err != nil || len(res) != 1 {
		t.Fatalf("search: %v %v", res, err)
	}
	out := filepath.Join(t.TempDir(), "export.txt")
	n, err := a.ExportConversation(context.Background(), storage.GeneralRoomID, out, "text")
	if err != nil || n != 2 {
		t.Fatalf("export: %d %v", n, err)
	}
	b2, _ := os.ReadFile(out)
	if bytes.Contains(b2, []byte{0x1b}) {
		t.Fatal("text export contains raw escape sequences")
	}
	if _, err := a.ExportConversation(context.Background(), storage.GeneralRoomID, out, "json"); err == nil {
		t.Fatal("export overwrote an existing file")
	}
}
