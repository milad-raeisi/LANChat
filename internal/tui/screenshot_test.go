package tui

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// TestScreenshot renders the real screens with sample data and writes them
// as SVG images to the directory $LANCHAT_SCREENSHOTS. It keeps the README
// screenshots accurate: run `make screenshots`.
func TestScreenshot(t *testing.T) {
	dir := os.Getenv("LANCHAT_SCREENSHOTS")
	if dir == "" {
		t.Skip("set LANCHAT_SCREENSHOTS to a directory to write the screenshots")
	}
	write := func(name, svg string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(svg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const cols, rows = 100, 26

	m, reza := sampleChat(t, cols, rows)
	write("chat.svg", svgScreenshot(screen(m), cols, rows, "LANChat",
		"The LANChat chat screen: a list of rooms, groups and people on the left, the #general room with messages and delivery receipts on the right, and the message box below."))

	m.setDialog(newPairRequestDialog(m, reza.ID, "482 913"))
	time.Sleep(guardDuration + 50*time.Millisecond)
	write("pairing.svg", svgScreenshot(screen(m), cols, rows, "LANChat",
		"A pairing request from Reza: both people compare the same six-digit code before accepting."))

	w := newWizard(platform.Dirs{Config: t.TempDir(), Data: t.TempDir()}, nil)
	w.Update(tea.WindowSizeMsg{Width: 88, Height: 26})
	w.name.SetValue("Milad")
	w.name.CursorEnd()
	out := strings.TrimRight(w.View().Content, "\n ")
	ww, wh := lipgloss.Size(out)
	write("setup.svg", svgScreenshot(out, ww+1, wh+1, "LANChat setup",
		"The first-run setup wizard with the LANChat logo, asking for a display name (step 1 of 4)."))
}

// sampleChat is the chat screen with a few people and messages.
func sampleChat(t *testing.T, w, h int) (*Model, node.PeerInfo) {
	f := newFake(t)
	maryam := f.addPeer("Maryam", true, true)
	ali := f.addPeer("Ali", true, true)
	f.addPeer("Yumna", true, false)
	reza := f.addPeer("Reza", false, true)
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
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	run(t, m, m.loadState())
	run(t, m, m.loadMessages(m.current))
	return m, reza
}
