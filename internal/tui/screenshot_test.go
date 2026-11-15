package tui

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// TestScreenshot renders the real chat screen with sample data and writes
// it as plain text to $LANCHAT_SCREENSHOT. It is used to keep the README
// screenshot accurate: `LANCHAT_SCREENSHOT=/tmp/s.txt go test -run Screenshot ./internal/tui/`.
func TestScreenshot(t *testing.T) {
	path := os.Getenv("LANCHAT_SCREENSHOT")
	if path == "" {
		t.Skip("set LANCHAT_SCREENSHOT to write a screenshot")
	}
	f := newFake(t)
	maryam := f.addPeer("Maryam", true, true)
	f.addPeer("Ali", true, true)
	f.addPeer("Yumna", true, false)
	reza := f.addPeer("Reza", false, true)
	_ = reza
	f.convs = append(f.convs,
		storage.Conversation{ID: storage.DirectConversationID(maryam.ID), Kind: storage.KindDirect, Title: "Maryam", PeerID: maryam.ID, Joined: true, Unread: 2},
		storage.Conversation{ID: "group:00112233445566778899aabbccddeeff", Kind: storage.KindGroup, Title: "Project X", Joined: true},
	)
	now := time.Now()
	base := time.Date(now.Year(), now.Month(), now.Day(), 10, 42, 0, 0, time.Local) // shows as "Today"
	msg := func(seq int64, sender node.PeerInfo, body string, min int, out bool, d storage.DeliverySummary) storage.Message {
		return storage.Message{Seq: seq, ConversationID: storage.GeneralRoomID, SenderID: sender.ID, SenderName: sender.DisplayName,
			Kind: storage.MessageText, Body: body, SentAt: base.Add(time.Duration(min) * time.Minute), Outgoing: out, Delivery: d}
	}
	me := node.PeerInfo{ID: f.self.ID, DisplayName: "Milad"}
	ali := f.peers[1]
	f.msgs[storage.GeneralRoomID] = []storage.Message{
		msg(1, maryam, "Hello everyone!", 0, false, storage.DeliverySummary{}),
		msg(2, ali, "Good morning! The build server is back up.", 1, false, storage.DeliverySummary{}),
		msg(3, me, "Is everyone connected?", 2, true, storage.DeliverySummary{Delivered: 2}),
		msg(4, maryam, "Yes, everything works! 🎉", 3, false, storage.DeliverySummary{}),
		{Seq: 5, ConversationID: storage.GeneralRoomID, SenderID: "system", Kind: storage.MessageSystem, Body: "Reza is nearby but not paired yet.", SentAt: base.Add(4 * time.Minute)},
	}
	f.net = &node.NetworkStatus{Port: 47777, ListenAddr: "[::]:47777", TrustedOnline: 2, Sessions: 3,
		Interfaces: []netif.Interface{{Name: "en0", Up: true, Multicast: true, Addrs: []netif.Addr{{IP: netip.MustParseAddr("192.168.1.10"), Prefix: 24}}}}}
	f.members = []node.PeerInfo{maryam, ali}
	m := NewModel(f, nil)
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 26})
	run(t, m, m.loadState())
	run(t, m, m.loadMessages(m.current))
	out := ansi.Strip(m.View().Content)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		lines = append(lines, strings.TrimRight(l, " "))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
