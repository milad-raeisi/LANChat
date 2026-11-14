package tui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
)

// fakeBackend is an in-memory Backend for UI tests.
type fakeBackend struct {
	mu      sync.Mutex
	cfg     config.Config
	self    node.SelfInfo
	peers   []node.PeerInfo
	convs   []storage.Conversation
	msgs    map[string][]storage.Message
	sent    []string
	paired  map[identity.PeerID]bool
	events  chan node.Event
	net     *node.NetworkStatus
	members []node.PeerInfo
}

func newFake(t *testing.T) *fakeBackend {
	cfg := config.Default()
	cfg.User.DisplayName = "Milad"
	cfg.User.DeviceName = "Milad-MacBook"
	ch := make(chan node.Event)
	close(ch) // waitEvent returns immediately in tests
	id, _ := identity.Generate()
	f := &fakeBackend{
		cfg: cfg, events: ch, msgs: map[string][]storage.Message{}, paired: map[identity.PeerID]bool{},
		self: node.SelfInfo{ID: id.ID(), DisplayName: "Milad", DeviceName: "Milad-MacBook", Fingerprint: identity.FormatFingerprint(id.Fingerprint()), Port: 47777},
		convs: []storage.Conversation{
			{ID: storage.GeneralRoomID, Kind: storage.KindRoom, Title: "general", Joined: true},
			{ID: "room:dev", Kind: storage.KindRoom, Title: "dev", Joined: true, Unread: 3},
		},
	}
	return f
}

func (f *fakeBackend) addPeer(name string, trusted, connected bool) node.PeerInfo {
	id, _ := identity.Generate()
	p := node.PeerInfo{ID: id.ID(), DisplayName: name, DeviceName: name + "-PC", Connected: connected, Discovered: true, Trust: storage.TrustUnknown}
	if trusted {
		p.Trust = storage.TrustTrusted
	}
	f.peers = append(f.peers, p)
	return p
}

func (f *fakeBackend) Self() node.SelfInfo       { return f.self }
func (f *fakeBackend) Config() config.Config     { return f.cfg }
func (f *fakeBackend) Events() <-chan node.Event { return f.events }
func (f *fakeBackend) Peers() []node.PeerInfo    { return append([]node.PeerInfo(nil), f.peers...) }
func (f *fakeBackend) NetworkStatus() node.NetworkStatus {
	if f.net != nil {
		return *f.net
	}
	return node.NetworkStatus{Port: 47777, ListenAddr: "[::]:47777"}
}
func (f *fakeBackend) Peer(id identity.PeerID) (node.PeerInfo, bool) {
	for _, p := range f.peers {
		if p.ID == id {
			return p, true
		}
	}
	return node.PeerInfo{}, false
}
func (f *fakeBackend) ResolvePeer(q string) []node.PeerInfo {
	var out []node.PeerInfo
	for _, p := range f.peers {
		if strings.EqualFold(p.DisplayName, q) {
			out = append(out, p)
		}
	}
	return out
}
func (f *fakeBackend) Conversations(context.Context) ([]storage.Conversation, error) {
	return f.convs, nil
}
func (f *fakeBackend) Messages(_ context.Context, conv string, _ int64, _ int) ([]storage.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]storage.Message(nil), f.msgs[conv]...), nil
}
func (f *fakeBackend) MarkRead(context.Context, string, int64) error { return nil }
func (f *fakeBackend) Search(context.Context, string, string) ([]storage.Message, error) {
	return nil, nil
}
func (f *fakeBackend) SendText(_ context.Context, conv, body string) (storage.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, conv+"|"+body)
	m := storage.Message{Seq: int64(len(f.msgs[conv]) + 1), ID: "x", ConversationID: conv, SenderID: f.self.ID, SenderName: "Milad",
		Kind: storage.MessageText, Body: body, SentAt: time.Now(), Outgoing: true, Delivery: storage.DeliverySummary{Pending: 1}}
	f.msgs[conv] = append(f.msgs[conv], m)
	return m, nil
}
func (f *fakeBackend) OpenDirect(_ context.Context, id identity.PeerID) (string, error) {
	return storage.DirectConversationID(id), nil
}
func (f *fakeBackend) ClearHistory(context.Context, string) (int64, error) { return 0, nil }
func (f *fakeBackend) RetryFailed(context.Context, string) (int64, error)  { return 0, nil }
func (f *fakeBackend) ExportConversation(context.Context, string, string, string) (int, error) {
	return 0, nil
}
func (f *fakeBackend) Rooms() []node.RoomInfo             { return nil }
func (f *fakeBackend) RoomMembers(string) []node.PeerInfo { return f.members }
func (f *fakeBackend) JoinRoom(_ context.Context, n string) (string, error) {
	return storage.RoomConversationID(n), nil
}
func (f *fakeBackend) LeaveRoom(context.Context, string) error { return nil }
func (f *fakeBackend) Group(context.Context, string) (storage.Group, error) {
	return storage.Group{}, errors.New("no")
}
func (f *fakeBackend) CreateGroup(context.Context, string, []identity.PeerID) (string, error) {
	return "", nil
}
func (f *fakeBackend) InviteToGroup(context.Context, string, identity.PeerID) error   { return nil }
func (f *fakeBackend) RemoveFromGroup(context.Context, string, identity.PeerID) error { return nil }
func (f *fakeBackend) LeaveGroup(context.Context, string) error                       { return nil }
func (f *fakeBackend) PairingInfo(id identity.PeerID) (node.PairingInfo, error) {
	return node.PairingInfo{PeerID: id, DisplayName: "x", Code: "123 456", Fingerprint: f.self.Fingerprint, Address: "10.0.0.2:47777"}, nil
}
func (f *fakeBackend) RequestPairing(context.Context, identity.PeerID) error { return nil }
func (f *fakeBackend) RespondPairing(_ context.Context, id identity.PeerID, accept bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paired[id] = accept
	return nil
}
func (f *fakeBackend) Revoke(context.Context, identity.PeerID) error { return nil }
func (f *fakeBackend) Ping(context.Context, identity.PeerID) (time.Duration, error) {
	return time.Millisecond, nil
}
func (f *fakeBackend) RefreshDiscovery() {}
func (f *fakeBackend) SendFile(context.Context, identity.PeerID, string) (string, error) {
	return "", nil
}
func (f *fakeBackend) RespondFile(context.Context, string, bool) error { return nil }
func (f *fakeBackend) CancelTransfer(string) error                     { return nil }
func (f *fakeBackend) Transfers() []node.TransferInfo                  { return nil }

// run executes a command and feeds resulting messages back into the model,
// skipping commands that block (ticks).
func run(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-done:
	case <-time.After(150 * time.Millisecond):
		return // a tick or other timer
	}
	switch msg := msg.(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			run(t, m, c)
		}
	default:
		if _, ok := msg.(tea.QuitMsg); ok {
			return
		}
		_, next := m.Update(msg)
		run(t, m, next)
	}
}

func setup(t *testing.T, w, h int) (*Model, *fakeBackend) {
	f := newFake(t)
	m := NewModel(f, nil)
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	run(t, m, m.loadState())
	run(t, m, m.loadMessages(m.current))
	return m, f
}

func screen(m *Model) string { return m.View().Content }

func press(t *testing.T, m *Model, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "left":
			msg = tea.KeyPressMsg{Code: tea.KeyLeft}
		default:
			r := []rune(k)[0]
			msg = tea.KeyPressMsg{Code: r, Text: k}
		}
		_, cmd := m.Update(msg)
		run(t, m, cmd)
	}
}

func typeText(t *testing.T, m *Model, s string) {
	for _, r := range s {
		_, cmd := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
		run(t, m, cmd)
	}
}

func TestRenderSizes(t *testing.T) {
	for _, size := range [][2]int{{120, 40}, {80, 24}, {60, 18}, {45, 12}} {
		m, f := setup(t, size[0], size[1])
		f.addPeer("Maryam", true, true)
		run(t, m, m.loadState())
		out := screen(m)
		lines := strings.Split(out, "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: rendered %d lines", size[0], size[1], len(lines))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > size[0] {
				t.Errorf("%dx%d: line %d is %d wide", size[0], size[1], i, w)
			}
		}
		if !strings.Contains(out, "LANChat") || !strings.Contains(out, "general") {
			t.Errorf("%dx%d: missing header/title", size[0], size[1])
		}
		if size[0] >= 72 && !strings.Contains(out, "Maryam") {
			t.Errorf("%dx%d: sidebar should list peers", size[0], size[1])
		}
	}
	m, _ := setup(t, 30, 8)
	if !strings.Contains(screen(m), "Terminal too small") {
		t.Fatal("tiny terminal should show a size hint")
	}
}

func TestMaliciousTextIsNeutralised(t *testing.T) {
	m, f := setup(t, 100, 30)
	evil := "\x1b[2J\x1b]0;pwned\x07\u202eexe.txt"
	f.msgs[storage.GeneralRoomID] = []storage.Message{
		{Seq: 1, ConversationID: storage.GeneralRoomID, SenderID: "x", SenderName: "Eve\x1b[31m", Kind: storage.MessageText, Body: evil, SentAt: time.Now()},
		{Seq: 2, ConversationID: storage.GeneralRoomID, SenderID: "y", SenderName: "Long", Kind: storage.MessageText, Body: strings.Repeat("A", 500), SentAt: time.Now()},
	}
	run(t, m, m.loadMessages(storage.GeneralRoomID))
	out := screen(m)
	for _, bad := range []string{"\x1b[2J", "\x1b]0;", "\x07", "\u202e", "\x1b[31mEve"} {
		if strings.Contains(out, bad) {
			t.Fatalf("untrusted control sequence %q reached the terminal", bad)
		}
	}
	for i, l := range strings.Split(out, "\n") {
		if lipgloss.Width(l) > 100 {
			t.Fatalf("line %d overflows (%d columns): long words must wrap", i, lipgloss.Width(l))
		}
	}
}

func TestSendMessageAndCommandsAreLocal(t *testing.T) {
	m, f := setup(t, 100, 30)
	typeText(t, m, "Hello everyone!")
	press(t, m, "enter")
	if len(f.sent) != 1 || f.sent[0] != storage.GeneralRoomID+"|Hello everyone!" {
		t.Fatalf("sent = %v", f.sent)
	}
	if !strings.Contains(screen(m), "Hello everyone!") {
		t.Fatal("sent message not rendered")
	}
	if !strings.Contains(screen(m), "queued") {
		t.Fatal("pending delivery state not shown")
	}
	// Slash commands are not sent as chat messages.
	typeText(t, m, "/whoami")
	press(t, m, "enter")
	if len(f.sent) != 1 {
		t.Fatal("command was sent as a message")
	}
	if !strings.Contains(screen(m), "Who am I") {
		t.Fatal("whoami dialog not shown")
	}
	press(t, m, "esc")
	// "//" escapes a leading slash.
	typeText(t, m, "//shrug")
	press(t, m, "enter")
	if f.sent[len(f.sent)-1] != storage.GeneralRoomID+"|/shrug" {
		t.Fatalf("escaped slash: %v", f.sent)
	}
}

func TestAmbiguousNameRequiresChoice(t *testing.T) {
	m, f := setup(t, 100, 30)
	a := f.addPeer("Ali", true, true)
	f.addPeer("Ali", true, false)
	run(t, m, m.loadState())
	typeText(t, m, "/msg Ali hi")
	press(t, m, "enter")
	if !strings.Contains(screen(m), "Several users match") {
		t.Fatal("ambiguous name did not open a picker")
	}
	if !strings.Contains(screen(m), "#"+a.ID.Short()) {
		t.Fatal("picker must show identities to disambiguate")
	}
	if len(f.sent) != 0 {
		t.Fatal("message sent without choosing the recipient")
	}
}

func TestPairRequestDialogAndTypingNotInterrupted(t *testing.T) {
	m, f := setup(t, 100, 30)
	p := f.addPeer("Maryam", false, true)
	run(t, m, m.loadState())
	// The user is typing: the request must not steal focus.
	typeText(t, m, "half a sentence")
	run(t, m, func() tea.Msg {
		return eventMsg(node.Event{Kind: node.EventPairRequest, PeerID: p.ID, PeerName: "Maryam", Code: "482 913"})
	})
	if m.dialog != nil {
		t.Fatal("dialog opened while the user was typing")
	}
	if len(m.pending) != 1 {
		t.Fatal("request not queued")
	}
	m.input.Reset()
	m.lastKey = time.Time{}
	run(t, m, func() tea.Msg { return tickMsg(time.Now()) })
	if m.dialog == nil || !strings.Contains(screen(m), "482 913") {
		t.Fatal("queued pairing dialog with code not shown when idle")
	}
	// Keys typed right after the dialog opens are ignored (input guard).
	press(t, m, "left", "left", "enter")
	if _, answered := f.paired[p.ID]; answered || m.dialog == nil {
		t.Fatal("dialog answered during the input guard")
	}
	time.Sleep(guardDuration + 50*time.Millisecond)
	// Single letters do nothing; Enter on the default ("Later") does not accept.
	press(t, m, "a", "y")
	if _, answered := f.paired[p.ID]; answered || m.dialog == nil {
		t.Fatal("a letter key answered the pairing request")
	}
	press(t, m, "enter")
	if _, answered := f.paired[p.ID]; answered {
		t.Fatal("Enter on the default button answered the request")
	}
	// Accepting requires selecting Accept explicitly.
	m.setDialog(newPairRequestDialog(m, p.ID, "482 913"))
	time.Sleep(guardDuration + 50*time.Millisecond)
	press(t, m, "left", "left", "enter")
	if !f.paired[p.ID] {
		t.Fatal("explicit accept did not reach the backend")
	}
}

func TestSpoofedNamesShowIdentity(t *testing.T) {
	m, f := setup(t, 100, 30)
	f.addPeer("Ali", true, true)
	run(t, m, m.loadState())
	f.msgs[storage.GeneralRoomID] = []storage.Message{
		{Seq: 1, ConversationID: storage.GeneralRoomID, SenderID: "abcdefabcdefabcdefabcdefabcdefab", SenderName: "Milad (you)", Kind: storage.MessageText, Body: "trust me", SentAt: time.Now()},
		{Seq: 2, ConversationID: storage.GeneralRoomID, SenderID: "bcdefabcdefabcdefabcdefabcdefabc", SenderName: "Milad", Kind: storage.MessageText, Body: "me too", SentAt: time.Now()},
	}
	run(t, m, m.loadMessages(storage.GeneralRoomID))
	out := screen(m)
	if !strings.Contains(out, "Milad (you) #ABCDEF") || !strings.Contains(out, "Milad #BCDEFA") {
		t.Fatalf("impersonating names are not disambiguated:\n%s", out)
	}
}

func TestSplitArgsAndSuggestions(t *testing.T) {
	got := splitArgs(`file send maryam "/tmp/my report.pdf"`)
	if len(got) != 4 || got[3] != "/tmp/my report.pdf" {
		t.Fatalf("splitArgs = %q", got)
	}
	if restAfter("msg maryam hello there  world", 2) != "hello there  world" {
		t.Fatal("restAfter")
	}
	m, _ := setup(t, 100, 30)
	typeText(t, m, "/jo")
	s := m.suggestions()
	if len(s) != 1 || s[0] != "/join" {
		t.Fatalf("suggestions = %v", s)
	}
	press(t, m, "tab")
	if m.input.Value() != "/join " {
		t.Fatalf("completion = %q", m.input.Value())
	}
}

func TestThemesRender(t *testing.T) {
	for _, name := range config.Themes {
		f := newFake(t)
		f.cfg.UI.Theme = name
		m := NewModel(f, nil)
		m.Update(tea.WindowSizeMsg{Width: 90, Height: 25})
		if out := screen(m); !strings.Contains(out, "LANChat") {
			t.Fatalf("theme %s failed to render", name)
		}
	}
}

func TestResizeKeepsWorking(t *testing.T) {
	m, _ := setup(t, 120, 40)
	for _, s := range [][2]int{{50, 15}, {200, 60}, {72, 16}, {39, 9}, {100, 30}} {
		m.Update(tea.WindowSizeMsg{Width: s[0], Height: s[1]})
		_ = screen(m)
	}
	typeText(t, m, "still works")
	if m.input.Value() != "still works" {
		t.Fatal("input broken after resizes")
	}
}
