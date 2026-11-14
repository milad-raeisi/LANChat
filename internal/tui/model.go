package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

type focusArea int

const (
	focusInput focusArea = iota
	focusSidebar
	focusMessages
)

const (
	pageSize     = 200
	sidebarWide  = 28
	sidebarSmall = 22
	minWidth     = 40
	minHeight    = 10
)

type keyMap struct {
	send, newline, palette, search, convs, refresh, next, prev, help, quit map[string]bool
}

func toSet(keys []string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[strings.ToLower(strings.TrimSpace(k))] = true
	}
	return m
}

func newKeyMap(k config.KeyConfig) keyMap {
	return keyMap{
		send: toSet(k.Send), newline: toSet(k.Newline), palette: toSet(k.CommandPalette), search: toSet(k.Search),
		convs: toSet(k.Conversations), refresh: toSet(k.Refresh), next: toSet(k.NextPanel), prev: toSet(k.PrevPanel),
		help: toSet(k.Help), quit: toSet(k.Quit),
	}
}

func matches(set map[string]bool, msg tea.KeyPressMsg) bool {
	return set[msg.String()] || set[msg.Keystroke()]
}

func firstKey(set map[string]bool, fallback string) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return fallback
	}
	return keys[0]
}

type itemKind int

const (
	itemHeader itemKind = iota
	itemConv
	itemPeer
)

type sidebarItem struct {
	kind   itemKind
	title  string
	convID string
	peerID identity.PeerID
	unread int
	icon   string
	state  string // online, offline, nearby, unreachable, warning, revoked, room, group, left, pairing
}

func (it sidebarItem) key() string {
	if it.convID != "" {
		return "c:" + it.convID
	}
	if it.peerID != "" {
		return "p:" + string(it.peerID)
	}
	return "h:" + it.title
}

type toast struct {
	text  string
	level string
	until time.Time
}

// Model is the main chat screen.
type Model struct {
	be    Backend
	cfg   config.Config
	save  func(config.Config) error
	theme Theme
	st    styles
	keys  keyMap

	width, height int
	compact       bool
	focus         focusArea
	self          node.SelfInfo

	peers []node.PeerInfo
	convs []storage.Conversation
	items []sidebarItem
	sel   int

	current   string
	msgs      []storage.Message
	hasOlder  bool
	loading   bool
	follow    bool
	clearedAt map[string]int64
	vp        viewport.Model
	input     textarea.Model
	history   []string
	histPos   int
	draft     string

	dialog    dialog
	pending   []dialog
	toast     toast
	lastKey   time.Time
	transfers map[string]node.TransferInfo
	refreshQ  bool
	dirtyConv bool
	quitting  bool
	err       error
	// pendingCmd is run when a dialog that scheduled work opens.
	pendingCmd tea.Cmd
}

// NewModel creates the chat screen. save persists configuration changes
// made from the UI (theme, bell); it may be nil.
func NewModel(be Backend, save func(config.Config) error) *Model {
	cfg := be.Config()
	theme := ThemeByName(cfg.UI.Theme)
	m := &Model{
		be: be, cfg: cfg, save: save, theme: theme, st: newStyles(theme), keys: newKeyMap(cfg.Keys),
		self: be.Self(), current: storage.GeneralRoomID, follow: true, clearedAt: map[string]int64{},
		histPos: -1, transfers: map[string]node.TransferInfo{}, width: 100, height: 30,
	}
	m.vp = viewport.New(viewport.WithWidth(60), viewport.WithHeight(10))
	m.vp.KeyMap = viewport.KeyMap{}
	m.vp.MouseWheelEnabled = false

	ta := textarea.New()
	ta.Placeholder = "Type a message…  (/ for commands, " + firstKey(m.keys.palette, "ctrl+p") + " for the palette)"
	ta.ShowLineNumbers = false
	ta.Prompt = "› "
	ta.CharLimit = cfg.Chat.MaxMessageBytes
	ta.DynamicHeight = true
	ta.MinHeight = 1
	ta.MaxHeight = 6
	ta.MaxContentHeight = 2000
	km := textarea.DefaultKeyMap()
	var nl []string
	for k := range m.keys.newline {
		nl = append(nl, k)
	}
	km.InsertNewline = key.NewBinding(key.WithKeys(nl...))
	ta.KeyMap = km
	ta.SetStyles(textarea.DefaultStyles(theme.Name != "light"))
	m.input = ta
	m.input.Focus()
	return m
}

// --- messages ------------------------------------------------------------

type eventMsg node.Event
type refreshMsg struct{}
type tickMsg time.Time

type stateMsg struct {
	peers []node.PeerInfo
	convs []storage.Conversation
	err   error
}

type messagesMsg struct {
	conv  string
	msgs  []storage.Message
	older bool
	err   error
}

type sentMsg struct {
	text string
	err  error
}

type toastMsg struct {
	text, level string
}

type openConvMsg struct {
	conv string
	err  error
}

type dialogMsg struct{ d dialog }

func waitEvent(ch <-chan node.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return eventMsg(ev)
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func ctx() context.Context { return context.Background() }

func toastCmd(level, format string, args ...any) tea.Cmd {
	text := fmt.Sprintf(format, args...)
	return func() tea.Msg { return toastMsg{text: text, level: level} }
}

func errCmd(err error) tea.Cmd {
	if err == nil {
		return nil
	}
	return toastCmd("error", "%s", err.Error())
}

func openDialog(d dialog) tea.Cmd { return func() tea.Msg { return dialogMsg{d} } }

func (m *Model) loadState() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		convs, err := be.Conversations(ctx())
		return stateMsg{peers: be.Peers(), convs: convs, err: err}
	}
}

func (m *Model) loadMessages(conv string) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		msgs, err := be.Messages(ctx(), conv, 0, pageSize)
		return messagesMsg{conv: conv, msgs: msgs, err: err}
	}
}

func (m *Model) loadOlder() tea.Cmd {
	if m.loading || !m.hasOlder || len(m.msgs) == 0 {
		return nil
	}
	m.loading = true
	be, conv, before := m.be, m.current, m.msgs[0].Seq
	return func() tea.Msg {
		msgs, err := be.Messages(ctx(), conv, before, pageSize)
		return messagesMsg{conv: conv, msgs: msgs, older: true, err: err}
	}
}

func (m *Model) markRead() tea.Cmd {
	if len(m.msgs) == 0 {
		return nil
	}
	be, conv, seq := m.be, m.current, m.msgs[len(m.msgs)-1].Seq
	return func() tea.Msg {
		_ = be.MarkRead(ctx(), conv, seq)
		return nil
	}
}

// switchTo opens a conversation.
func (m *Model) switchTo(conv string) tea.Cmd {
	if conv == "" {
		return nil
	}
	m.current = conv
	m.msgs = nil
	m.hasOlder = false
	m.follow = true
	m.loading = false
	m.selectKey("c:" + conv)
	m.renderMessages()
	return tea.Batch(m.loadMessages(conv), m.loadState())
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(waitEvent(m.be.Events()), m.loadState(), m.loadMessages(m.current), tick(), m.input.Focus())
}

// --- update ---------------------------------------------------------------

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		m.renderMessages()
		return m, nil

	case tickMsg:
		cmds = append(cmds, tick())
		if m.dialog == nil && len(m.pending) > 0 && m.idle() {
			m.dialog, m.pending = m.pending[0], m.pending[1:]
		}
		if !m.toast.until.IsZero() && time.Now().After(m.toast.until) {
			m.toast = toast{}
		}
		return m, tea.Batch(cmds...)

	case eventMsg:
		cmds = append(cmds, waitEvent(m.be.Events()), m.handleEvent(node.Event(msg)))
		if !m.refreshQ {
			m.refreshQ = true
			cmds = append(cmds, tea.Tick(60*time.Millisecond, func(time.Time) tea.Msg { return refreshMsg{} }))
		}
		return m, tea.Batch(cmds...)

	case refreshMsg:
		m.refreshQ = false
		cmds = append(cmds, m.loadState())
		if m.dirtyConv {
			m.dirtyConv = false
			cmds = append(cmds, m.loadMessages(m.current))
		}
		return m, tea.Batch(cmds...)

	case stateMsg:
		if msg.err != nil {
			return m, errCmd(msg.err)
		}
		m.peers, m.convs = msg.peers, msg.convs
		m.self = m.be.Self()
		m.rebuildItems()
		return m, nil

	case messagesMsg:
		if msg.conv != m.current {
			return m, nil
		}
		if msg.err != nil {
			m.loading = false
			return m, errCmd(msg.err)
		}
		if msg.older {
			m.loading = false
			m.hasOlder = len(msg.msgs) == pageSize
			before := m.vp.TotalLineCount()
			off := m.vp.YOffset()
			m.msgs = append(msg.msgs, m.msgs...)
			m.renderMessages()
			m.vp.SetYOffset(off + (m.vp.TotalLineCount() - before))
			return m, nil
		}
		m.msgs = msg.msgs
		m.hasOlder = len(msg.msgs) == pageSize
		m.renderMessages()
		return m, tea.Batch(m.markRead(), m.loadState())

	case sentMsg:
		if msg.err != nil {
			if strings.TrimSpace(m.input.Value()) == "" {
				m.input.SetValue(msg.text)
			}
			return m, errCmd(msg.err)
		}
		m.follow = true
		return m, m.loadMessages(m.current)

	case openConvMsg:
		if msg.err != nil {
			return m, errCmd(msg.err)
		}
		return m, m.switchTo(msg.conv)

	case toastMsg:
		m.setToast(msg.level, msg.text)
		return m, nil

	case dialogMsg:
		if m.dialog == nil {
			m.dialog = msg.d
		} else {
			m.pending = append(m.pending, msg.d)
		}
		cmd := m.pendingCmd
		m.pendingCmd = nil
		return m, cmd

	case listItemsMsg:
		if d, ok := m.dialog.(*listDialog); ok && d == msg.target {
			d.setItems(msg.items)
		}
		return m, nil

	case tea.PasteMsg:
		if m.dialog != nil {
			if pd, ok := m.dialog.(pasteDialog); ok {
				return m, pd.paste(m, msg.Content)
			}
			return m, nil
		}
		m.focusInput()
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.layout()
		return m, cmd

	case tea.MouseWheelMsg:
		mouse := msg.Mouse()
		if mouse.Button == tea.MouseWheelUp {
			m.scrollUp(3)
			return m, m.maybeLoadOlder()
		}
		if mouse.Button == tea.MouseWheelDown {
			m.scrollDown(3)
		}
		return m, nil

	case tea.KeyPressMsg:
		m.lastKey = time.Now()
		return m, m.handleKey(msg)
	}

	// Cursor blink and other component messages.
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

// idle reports whether the user is not in the middle of typing, so that
// queued dialogs (pairing requests, file offers) may open without
// interrupting.
func (m *Model) idle() bool {
	return strings.TrimSpace(m.input.Value()) == "" || time.Since(m.lastKey) > 4*time.Second
}

func (m *Model) setToast(level, text string) {
	text = textsafe.Line(text, 300)
	m.toast = toast{text: text, level: level, until: time.Now().Add(6 * time.Second)}
}

func (m *Model) handleEvent(ev node.Event) tea.Cmd {
	n := m.cfg.Notifications
	switch ev.Kind {
	case node.EventMessage:
		if ev.ConversationID == m.current {
			m.dirtyConv = true
		}
		if ev.Incoming && ev.ConversationID != m.current && n.Enabled {
			m.notifyIncoming(ev)
			return m.bell()
		}
	case node.EventDelivery, node.EventConversations:
		if ev.ConversationID == "" || ev.ConversationID == m.current {
			m.dirtyConv = true
		}
	case node.EventPeerOnline, node.EventPeerOffline:
		if p, ok := m.be.Peer(ev.PeerID); ok && p.Trusted() && n.Enabled && n.PeerEvents {
			if ev.Kind == node.EventPeerOnline {
				m.setToast("info", "● "+p.DisplayName+" is now online.")
			} else {
				m.setToast("info", "○ "+p.DisplayName+" disconnected.")
			}
		}
	case node.EventPairRequest:
		m.queueDialog(newPairRequestDialog(m, ev.PeerID, ev.Code))
		return m.bell()
	case node.EventPairResult:
		if ev.Accepted {
			m.setToast("success", "✓ Paired with "+ev.PeerName+". You can now exchange messages.")
		} else {
			reason := ev.Text
			if reason == "" {
				reason = "declined"
			}
			m.setToast("warn", "Pairing with "+ev.PeerName+" was not accepted ("+reason+").")
		}
	case node.EventIdentityWarning:
		m.queueDialog(&infoDialog{title: "⚠ Identity warning", warn: true, lines: wrapLines(textsafe.Text(ev.Text), 60)})
		return m.bell()
	case node.EventFileOffer:
		if ev.Transfer != nil {
			m.queueDialog(newFileOfferDialog(m, *ev.Transfer))
			return m.bell()
		}
	case node.EventTransfer:
		if t := ev.Transfer; t != nil {
			m.transfers[t.ID] = *t
			if t.Done() {
				delete(m.transfers, t.ID)
				switch t.State {
				case node.TransferCompleted:
					if t.Outgoing {
						m.setToast("success", "✓ Sent "+t.Name+" to "+t.PeerName+".")
					} else {
						m.setToast("success", "✓ File received successfully: "+t.Name)
					}
				default:
					m.setToast("warn", "File "+t.Name+": "+t.State+" "+t.Error)
				}
			}
		}
	case node.EventNotice:
		m.setToast(ev.Level, ev.Text)
	case node.EventNetwork:
		m.setToast("warn", ev.Text)
	}
	return nil
}

func (m *Model) notifyIncoming(ev node.Event) {
	name := textsafe.Line(ev.PeerName, 32)
	kind, key, _ := storage.ParseConversationID(ev.ConversationID)
	switch kind {
	case storage.KindDirect:
		m.setToast("info", "● "+name+" sent you a private message.")
	case storage.KindRoom:
		m.setToast("info", "● "+name+" in #"+key)
	default:
		title := key
		for _, c := range m.convs {
			if c.ID == ev.ConversationID {
				title = c.Title
			}
		}
		m.setToast("info", "● "+name+" in ◆ "+textsafe.Line(title, 32))
	}
}

func (m *Model) bell() tea.Cmd {
	if !m.cfg.Notifications.Enabled || !m.cfg.Notifications.Bell {
		return nil
	}
	if time.Since(m.lastKey) < 2*time.Second {
		return nil // do not beep while the user is typing
	}
	return tea.Raw("\a")
}

func (m *Model) queueDialog(d dialog) {
	if m.dialog == nil && m.idle() {
		m.dialog = d
		return
	}
	m.pending = append(m.pending, d)
	m.setToast("info", fmt.Sprintf("%d request(s) waiting — they open when you stop typing (Esc to dismiss).", len(m.pending)))
}

func (m *Model) handleKey(msg tea.KeyPressMsg) tea.Cmd {
	if matches(m.keys.quit, msg) {
		m.quitting = true
		return tea.Quit
	}
	if m.dialog != nil {
		done, cmd := m.dialog.update(m, msg)
		if done {
			m.dialog = nil
			if len(m.pending) > 0 && m.idle() {
				m.dialog, m.pending = m.pending[0], m.pending[1:]
			}
		}
		return cmd
	}
	switch {
	case matches(m.keys.palette, msg):
		return openDialog(newPaletteDialog(m))
	case matches(m.keys.search, msg):
		return openDialog(newSearchDialog(m, ""))
	case matches(m.keys.convs, msg):
		return openDialog(newConversationPicker(m))
	case matches(m.keys.refresh, msg):
		m.be.RefreshDiscovery()
		m.setToast("info", "Refreshing discovery and retrying unreachable peers…")
		return m.loadState()
	case matches(m.keys.help, msg):
		return openDialog(helpDialog(m))
	case matches(m.keys.next, msg) && !(m.focus == focusInput && m.completable()):
		m.cycleFocus(1)
		return nil
	case matches(m.keys.prev, msg):
		m.cycleFocus(-1)
		return nil
	}
	switch m.focus {
	case focusSidebar:
		return m.sidebarKey(msg)
	case focusMessages:
		return m.messagesKey(msg)
	default:
		return m.inputKey(msg)
	}
}

func (m *Model) cycleFocus(d int) {
	order := []focusArea{focusInput, focusSidebar, focusMessages}
	if m.compact {
		order = []focusArea{focusInput, focusMessages}
	}
	i := 0
	for j, f := range order {
		if f == m.focus {
			i = j
		}
	}
	m.focus = order[(i+d+len(order))%len(order)]
	if m.focus == focusInput {
		m.input.Focus()
	} else {
		m.input.Blur()
	}
}

func (m *Model) focusInput() {
	m.focus = focusInput
	m.input.Focus()
}

func (m *Model) inputKey(msg tea.KeyPressMsg) tea.Cmd {
	switch {
	case matches(m.keys.send, msg):
		return m.submit()
	case msg.String() == "esc":
		if m.input.Value() != "" && strings.HasPrefix(m.input.Value(), "/") {
			m.input.Reset()
			m.layout()
		}
		return nil
	case msg.String() == "tab" && m.completable():
		m.complete()
		return nil
	case msg.String() == "pgup":
		m.follow = false
		m.vp.PageUp()
		return m.maybeLoadOlder()
	case msg.String() == "pgdown":
		m.vp.PageDown()
		m.follow = m.vp.AtBottom()
		return nil
	case msg.String() == "up" && m.input.Line() == 0 && (m.input.Value() == "" || m.histPos >= 0):
		m.historyStep(-1)
		return nil
	case msg.String() == "down" && m.histPos >= 0 && m.input.Line() == m.input.LineCount()-1:
		m.historyStep(1)
		return nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.layout()
	return cmd
}

func (m *Model) historyStep(d int) {
	if len(m.history) == 0 {
		return
	}
	if m.histPos < 0 {
		if d > 0 {
			return
		}
		m.draft = m.input.Value()
		m.histPos = len(m.history)
	}
	m.histPos += d
	if m.histPos >= len(m.history) {
		m.histPos = -1
		m.input.SetValue(m.draft)
		return
	}
	if m.histPos < 0 {
		m.histPos = 0
	}
	m.input.SetValue(m.history[m.histPos])
	m.input.CursorEnd()
}

func (m *Model) submit() tea.Cmd {
	text := m.input.Value()
	if strings.TrimSpace(text) == "" {
		return nil
	}
	m.input.Reset()
	m.histPos = -1
	if len(m.history) == 0 || m.history[len(m.history)-1] != text {
		m.history = append(m.history, text)
		if len(m.history) > 100 {
			m.history = m.history[1:]
		}
	}
	m.layout()
	if strings.HasPrefix(text, "/") && !strings.HasPrefix(text, "//") {
		return m.runCommand(strings.TrimSpace(text))
	}
	if strings.HasPrefix(text, "//") {
		text = text[1:] // "//" sends a message that starts with a slash
	}
	return m.send(m.current, text)
}

func (m *Model) send(conv, text string) tea.Cmd {
	be := m.be
	m.follow = true
	return func() tea.Msg {
		_, err := be.SendText(ctx(), conv, text)
		return sentMsg{text: text, err: err}
	}
}

func (m *Model) sidebarKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "up", "k":
		m.moveSel(-1)
	case "down", "j":
		m.moveSel(1)
	case "home", "g":
		m.sel = -1
		m.moveSel(1)
	case "end", "G":
		m.sel = len(m.items)
		m.moveSel(-1)
	case "enter", "space", " ":
		return m.activateItem()
	case "esc":
		m.focusInput()
	default:
		if t := msg.Key().Text; t != "" && t != " " {
			// Typing while the sidebar is focused goes to the input.
			m.focusInput()
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return cmd
		}
	}
	return nil
}

func (m *Model) moveSel(d int) {
	if len(m.items) == 0 {
		return
	}
	i := m.sel
	for steps := 0; steps < len(m.items); steps++ {
		i += d
		if i < 0 || i >= len(m.items) {
			return
		}
		if m.items[i].kind != itemHeader {
			m.sel = i
			return
		}
	}
}

func (m *Model) activateItem() tea.Cmd {
	if m.sel < 0 || m.sel >= len(m.items) {
		return nil
	}
	it := m.items[m.sel]
	switch it.kind {
	case itemConv:
		m.focusInput()
		return m.switchTo(it.convID)
	case itemPeer:
		return m.openPeer(it.peerID)
	}
	return nil
}

// openPeer opens a direct conversation with a trusted peer or starts the
// pairing flow for an unpaired one.
func (m *Model) openPeer(id identity.PeerID) tea.Cmd {
	p, ok := m.be.Peer(id)
	if !ok {
		return nil
	}
	if p.IncomingPairing {
		return openDialog(newPairRequestDialog(m, id, ""))
	}
	if p.Trusted() || p.Trust == storage.TrustRevoked && !p.Connected {
		be := m.be
		m.focusInput()
		return func() tea.Msg {
			conv, err := be.OpenDirect(ctx(), id)
			return openConvMsg{conv: conv, err: err}
		}
	}
	return openDialog(newPairDialog(m, id))
}

func (m *Model) messagesKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "up", "k":
		m.scrollUp(1)
		return m.maybeLoadOlder()
	case "down", "j":
		m.scrollDown(1)
	case "pgup", "b":
		m.follow = false
		m.vp.PageUp()
		return m.maybeLoadOlder()
	case "pgdown", "f", "space":
		m.vp.PageDown()
		m.follow = m.vp.AtBottom()
	case "home", "g":
		m.follow = false
		m.vp.GotoTop()
		return m.maybeLoadOlder()
	case "end", "G":
		m.vp.GotoBottom()
		m.follow = true
	case "esc":
		m.focusInput()
	default:
		if t := msg.Key().Text; t != "" {
			m.focusInput()
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return cmd
		}
	}
	return nil
}

func (m *Model) scrollUp(n int) {
	m.follow = false
	m.vp.ScrollUp(n)
}

func (m *Model) scrollDown(n int) {
	m.vp.ScrollDown(n)
	m.follow = m.vp.AtBottom()
}

func (m *Model) maybeLoadOlder() tea.Cmd {
	if m.vp.AtTop() {
		return m.loadOlder()
	}
	return nil
}

// --- sidebar construction --------------------------------------------------

func (m *Model) peerLabel(p node.PeerInfo) string {
	name := textsafe.Line(p.DisplayName, 32)
	dups := 0
	for _, o := range m.peers {
		if strings.EqualFold(textsafe.Line(o.DisplayName, 32), name) {
			dups++
		}
	}
	if dups > 1 || !p.Trusted() && name == p.ID.Short() {
		if name != p.ID.Short() {
			name += " #" + p.ID.Short()
		}
	}
	return name
}

func (m *Model) rebuildItems() {
	prevKey := ""
	if m.sel >= 0 && m.sel < len(m.items) {
		prevKey = m.items[m.sel].key()
	}
	unread := map[string]int{}
	convByID := map[string]storage.Conversation{}
	for _, c := range m.convs {
		unread[c.ID] = c.Unread
		convByID[c.ID] = c
	}
	var items []sidebarItem
	add := func(it sidebarItem) { items = append(items, it) }

	// Rooms: general first, then alphabetical.
	var rooms []storage.Conversation
	for _, c := range m.convs {
		if c.Kind == storage.KindRoom && c.Joined {
			rooms = append(rooms, c)
		}
	}
	sort.Slice(rooms, func(i, j int) bool {
		if rooms[i].ID == storage.GeneralRoomID {
			return true
		}
		if rooms[j].ID == storage.GeneralRoomID {
			return false
		}
		return rooms[i].Title < rooms[j].Title
	})
	add(sidebarItem{kind: itemHeader, title: fmt.Sprintf("ROOMS (%d)", len(rooms))})
	for _, c := range rooms {
		add(sidebarItem{kind: itemConv, title: textsafe.Line(c.Title, 32), convID: c.ID, unread: c.Unread, icon: "#", state: "room"})
	}

	var groups []storage.Conversation
	for _, c := range m.convs {
		if c.Kind == storage.KindGroup {
			groups = append(groups, c)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Joined != groups[j].Joined {
			return groups[i].Joined
		}
		return strings.ToLower(groups[i].Title) < strings.ToLower(groups[j].Title)
	})
	if len(groups) > 0 {
		add(sidebarItem{kind: itemHeader, title: fmt.Sprintf("GROUPS (%d)", len(groups))})
		for _, c := range groups {
			st := "group"
			if !c.Joined {
				st = "left"
			}
			add(sidebarItem{kind: itemConv, title: textsafe.Line(c.Title, 32), convID: c.ID, unread: c.Unread, icon: "◆", state: st})
		}
	}

	var trusted, nearby []node.PeerInfo
	for _, p := range m.peers {
		switch {
		case p.Trusted():
			trusted = append(trusted, p)
		case p.Connected || p.Discovered || p.IncomingPairing:
			nearby = append(nearby, p)
		case p.Trust == storage.TrustRevoked:
			if _, ok := convByID[storage.DirectConversationID(p.ID)]; ok {
				nearby = append(nearby, p)
			}
		}
	}
	online := 0
	for _, p := range trusted {
		if p.Connected {
			online++
		}
	}
	add(sidebarItem{kind: itemHeader, title: fmt.Sprintf("PEOPLE (%d/%d online)", online, len(trusted))})
	for _, p := range trusted {
		icon, state := "○", "offline"
		if p.Connected {
			icon, state = "●", "online"
		}
		if p.Warning != "" {
			icon, state = "⚠", "warning"
		}
		conv := storage.DirectConversationID(p.ID)
		add(sidebarItem{kind: itemPeer, title: m.peerLabel(p), peerID: p.ID, convID: "", unread: unread[conv], icon: icon, state: state})
	}
	if len(nearby) > 0 {
		add(sidebarItem{kind: itemHeader, title: fmt.Sprintf("NEARBY – NOT PAIRED (%d)", len(nearby))})
		for _, p := range nearby {
			icon, state := "◌", "nearby"
			switch {
			case p.Warning != "":
				icon, state = "⚠", "warning"
			case p.IncomingPairing:
				icon, state = "?", "pairing"
			case p.Trust == storage.TrustRevoked:
				icon, state = "⊘", "revoked"
			case !p.Connected:
				icon, state = "×", "unreachable"
			}
			add(sidebarItem{kind: itemPeer, title: m.peerLabel(p), peerID: p.ID, icon: icon, state: state})
		}
	}
	m.items = items
	m.sel = -1
	if prevKey != "" {
		m.selectKey(prevKey)
	}
	if m.sel < 0 {
		m.selectKey("c:" + m.current)
	}
	if m.sel < 0 {
		m.moveSel(1)
	}
}

func (m *Model) selectKey(k string) {
	for i, it := range m.items {
		if it.key() == k {
			m.sel = i
			return
		}
		if strings.HasPrefix(k, "c:dm:") && it.kind == itemPeer && "c:"+storage.DirectConversationID(it.peerID) == k {
			m.sel = i
			return
		}
	}
}

func (m *Model) currentConversation() (storage.Conversation, bool) {
	for _, c := range m.convs {
		if c.ID == m.current {
			return c, true
		}
	}
	return storage.Conversation{}, false
}

// currentPeer returns the peer of the current direct conversation.
func (m *Model) currentPeer() (identity.PeerID, bool) {
	kind, key, err := storage.ParseConversationID(m.current)
	if err != nil || kind != storage.KindDirect {
		return "", false
	}
	return identity.PeerID(key), true
}

func (m *Model) currentGroupID() (string, bool) {
	kind, key, err := storage.ParseConversationID(m.current)
	if err != nil || kind != storage.KindGroup {
		return "", false
	}
	return key, true
}
