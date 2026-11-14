package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

// dialog is a modal overlay that receives key presses while open.
type dialog interface {
	update(m *Model, msg tea.KeyPressMsg) (done bool, cmd tea.Cmd)
	view(m *Model, maxW, maxH int) string
}

type pasteDialog interface {
	paste(m *Model, s string) tea.Cmd
}

func frame(m *Model, title string, body []string, footer string, maxW int, warn bool) string {
	st := m.st
	innerW := 0
	for _, l := range append([]string{title, footer}, body...) {
		innerW = max(innerW, lipgloss.Width(l))
	}
	innerW = min(innerW, maxW-6)
	titleStyle := st.dialogTitle
	box := st.dialog.Width(innerW + 4)
	if warn {
		titleStyle = st.warn
		box = box.BorderForeground(m.theme.Warn)
	}
	var lines []string
	lines = append(lines, titleStyle.Render(ansi.Truncate(title, innerW, "…")), "")
	for _, l := range body {
		lines = append(lines, ansi.Truncate(l, innerW, "…"))
	}
	if footer != "" {
		lines = append(lines, "", st.muted.Render(ansi.Truncate(footer, innerW, "…")))
	}
	return box.Render(strings.Join(lines, "\n"))
}

// --- info -----------------------------------------------------------------

type infoDialog struct {
	title  string
	lines  []string
	warn   bool
	offset int
}

func (d *infoDialog) update(_ *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", "q", "space":
		return true, nil
	case "up", "k":
		d.offset = max(0, d.offset-1)
	case "down", "j":
		d.offset++
	case "pgup":
		d.offset = max(0, d.offset-10)
	case "pgdown":
		d.offset += 10
	}
	return false, nil
}

func (d *infoDialog) view(m *Model, maxW, maxH int) string {
	visible := max(3, maxH-8)
	var wrapped []string
	for _, l := range d.lines {
		wrapped = append(wrapped, strings.Split(ansi.Wrap(l, maxW-8, ""), "\n")...)
	}
	if d.offset > max(0, len(wrapped)-visible) {
		d.offset = max(0, len(wrapped)-visible)
	}
	end := min(len(wrapped), d.offset+visible)
	body := wrapped[d.offset:end]
	footer := "Enter/Esc close"
	if len(wrapped) > visible {
		footer = fmt.Sprintf("↑↓ scroll (%d–%d of %d) · Enter/Esc close", d.offset+1, end, len(wrapped))
	}
	return frame(m, d.title, body, footer, maxW, d.warn)
}

// --- buttons ----------------------------------------------------------------

type button struct {
	label  string
	key    string
	action func(m *Model) tea.Cmd
}

type choiceDialog struct {
	title   string
	lines   []string
	buttons []button
	sel     int
	warn    bool
	escIdx  int // button activated by Esc; -1 = just close
}

func (d *choiceDialog) update(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	activate := func(i int) (bool, tea.Cmd) {
		if i < 0 || i >= len(d.buttons) {
			return true, nil
		}
		if d.buttons[i].action == nil {
			return true, nil
		}
		return true, d.buttons[i].action(m)
	}
	switch msg.String() {
	case "left", "shift+tab", "h":
		d.sel = (d.sel - 1 + len(d.buttons)) % len(d.buttons)
	case "right", "tab", "l":
		d.sel = (d.sel + 1) % len(d.buttons)
	case "enter":
		return activate(d.sel)
	case "esc":
		return activate(d.escIdx)
	default:
		for i, b := range d.buttons {
			if b.key != "" && strings.EqualFold(msg.String(), b.key) {
				return activate(i)
			}
		}
	}
	return false, nil
}

func (d *choiceDialog) view(m *Model, maxW, _ int) string {
	var btns []string
	for i, b := range d.buttons {
		label := "[ " + b.label + " ]"
		if i == d.sel {
			btns = append(btns, m.st.btnSel.Render(label))
		} else {
			btns = append(btns, m.st.button.Render(label))
		}
	}
	body := append(append([]string{}, d.lines...), "", strings.Join(btns, " "))
	return frame(m, d.title, body, "←→ choose · Enter confirm · Esc cancel", maxW, d.warn)
}

type confirmDialog struct {
	title string
	lines []string
	yes   string
	onYes func(m *Model) tea.Cmd
	inner *choiceDialog
}

func (d *confirmDialog) build() *choiceDialog {
	if d.inner == nil {
		d.inner = &choiceDialog{title: d.title, lines: d.lines, warn: true, escIdx: 1,
			buttons: []button{{label: d.yes, key: "y", action: d.onYes}, {label: "Cancel", key: "n"}}, sel: 1}
	}
	return d.inner
}

func (d *confirmDialog) update(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	return d.build().update(m, msg)
}

func (d *confirmDialog) view(m *Model, maxW, maxH int) string { return d.build().view(m, maxW, maxH) }

func fingerprintLines(fp string) []string {
	f := strings.Fields(fp)
	var out []string
	for i := 0; i < len(f); i += 8 {
		out = append(out, "  "+strings.Join(f[i:min(i+8, len(f))], " "))
	}
	return out
}

// newPairDialog starts outgoing pairing: the user compares the code with
// the other person before sending the request.
func newPairDialog(m *Model, id identity.PeerID) dialog {
	info, err := m.be.PairingInfo(id)
	p, _ := m.be.Peer(id)
	name := textsafe.Line(p.DisplayName, 32)
	if err != nil {
		reason := "it has not connected yet"
		if p.LastError != "" {
			reason = textsafe.Line(p.LastError, 120)
		}
		lines := []string{
			name + " was discovered but is not reachable right now: " + reason + ".",
			"",
			"Pairing needs a direct connection. Check that both computers are on the same",
			"network and that a firewall allows LANChat (see `lanchat doctor`).",
		}
		return &infoDialog{title: "Cannot pair with " + name + " yet", lines: lines}
	}
	st := m.st
	lines := []string{
		"Device:       " + textsafe.Line(info.DeviceName, 48),
		"Address:      " + info.Address,
		"Fingerprint:",
	}
	lines = append(lines, fingerprintLines(info.Fingerprint)...)
	lines = append(lines, "", "Verification code:  "+st.code.Render(info.Code), "",
		"Ask "+name+" to read out the code shown on their screen.",
		"Continue only if it matches exactly. A different code means",
		"someone may be intercepting the connection.")
	if info.Warning != "" {
		lines = append(lines, "", st.warn.Render("⚠ ")+st.warn.Render(textsafe.Line(info.Warning, 400)))
	}
	return &choiceDialog{
		title: "Pair with " + name + "?", lines: lines, warn: info.Warning != "", escIdx: 1,
		buttons: []button{
			{label: "Codes match – send request", key: "y", action: func(m *Model) tea.Cmd {
				be := m.be
				return func() tea.Msg {
					if err := be.RequestPairing(ctx(), id); err != nil {
						return toastMsg{level: "error", text: err.Error()}
					}
					return toastMsg{level: "info", text: "Pairing request sent to " + name + ". Waiting for them to accept…"}
				}
			}},
			{label: "Cancel", key: "n"},
		},
	}
}

// newPairRequestDialog answers an incoming pairing request.
func newPairRequestDialog(m *Model, id identity.PeerID, code string) dialog {
	info, err := m.be.PairingInfo(id)
	p, _ := m.be.Peer(id)
	name := textsafe.Line(p.DisplayName, 32)
	if code == "" && err == nil {
		code = info.Code
	}
	st := m.st
	lines := []string{"Device:       " + textsafe.Line(p.DeviceName, 48)}
	if err == nil {
		lines = append(lines, "Address:      "+info.Address, "Fingerprint:")
		lines = append(lines, fingerprintLines(info.Fingerprint)...)
	}
	lines = append(lines, "", "Verification code:  "+st.code.Render(code), "",
		"Make sure "+name+" sees exactly the same code before accepting.",
		"Accepting lets this identity exchange messages and files with you.")
	if p.Warning != "" {
		lines = append(lines, "", st.warn.Render("⚠ "+textsafe.Line(p.Warning, 400)))
	}
	respond := func(accept bool) func(m *Model) tea.Cmd {
		return func(m *Model) tea.Cmd {
			be := m.be
			return func() tea.Msg {
				if err := be.RespondPairing(ctx(), id, accept); err != nil {
					return toastMsg{level: "error", text: err.Error()}
				}
				if accept {
					return toastMsg{level: "success", text: "✓ Paired with " + name + "."}
				}
				return toastMsg{level: "info", text: "Pairing request from " + name + " rejected."}
			}
		}
	}
	return &choiceDialog{
		title: "Pairing request from " + name, lines: lines, warn: p.Warning != "", escIdx: 2,
		buttons: []button{
			{label: "Accept", key: "a", action: respond(true)},
			{label: "Reject", key: "r", action: respond(false)},
			{label: "Later", key: "l"},
		},
	}
}

func newFileOfferDialog(m *Model, t node.TransferInfo) dialog {
	dirs, _ := platform.ResolveDirs("")
	lines := []string{
		"From:  " + textsafe.Line(t.PeerName, 32),
		"File:  " + textsafe.Line(t.Name, 80),
		"Size:  " + node.HumanSize(t.Size),
		"",
		"Saved to: " + m.cfg.DownloadDir(dirs),
		"Received files are never opened or executed automatically.",
		"The SHA-256 checksum is verified before the file is kept.",
	}
	respond := func(accept bool) func(m *Model) tea.Cmd {
		return func(m *Model) tea.Cmd {
			be := m.be
			return func() tea.Msg {
				if err := be.RespondFile(ctx(), t.ID, accept); err != nil {
					return toastMsg{level: "error", text: err.Error()}
				}
				if accept {
					return toastMsg{level: "info", text: "Receiving " + t.Name + "…"}
				}
				return nil
			}
		}
	}
	return &choiceDialog{title: "Incoming file request", lines: lines, escIdx: -1,
		buttons: []button{{label: "Accept", key: "a", action: respond(true)}, {label: "Reject", key: "r", action: respond(false)}}}
}

// --- lists ----------------------------------------------------------------

type listItem struct {
	title string
	desc  string
	value any
}

type listItemsMsg struct {
	target *listDialog
	items  []listItem
}

type listDialog struct {
	title    string
	input    textinput.Model
	items    []listItem
	filtered []int
	sel      int
	onSelect func(m *Model, it listItem) tea.Cmd
	// query, when set, loads items asynchronously for the filter text
	// instead of filtering locally.
	query func(q string) tea.Cmd
	empty string
}

func newFilterInput() textinput.Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.Placeholder = "type to filter"
	ti.CharLimit = 200
	ti.Focus()
	return ti
}

func (d *listDialog) refilter() {
	q := strings.ToLower(strings.TrimSpace(d.input.Value()))
	d.filtered = d.filtered[:0]
	for i, it := range d.items {
		if d.query != nil || q == "" || strings.Contains(strings.ToLower(it.title+" "+it.desc), q) {
			d.filtered = append(d.filtered, i)
		}
	}
	if d.sel >= len(d.filtered) {
		d.sel = max(0, len(d.filtered)-1)
	}
}

func (d *listDialog) update(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if d.filtered == nil {
		d.refilter()
	}
	switch msg.String() {
	case "esc":
		return true, nil
	case "up", "ctrl+k":
		d.sel = max(0, d.sel-1)
		return false, nil
	case "down", "ctrl+j":
		d.sel = min(max(0, len(d.filtered)-1), d.sel+1)
		return false, nil
	case "pgup":
		d.sel = max(0, d.sel-8)
		return false, nil
	case "pgdown":
		d.sel = min(max(0, len(d.filtered)-1), d.sel+8)
		return false, nil
	case "enter":
		if len(d.filtered) == 0 || d.onSelect == nil {
			return true, nil
		}
		return true, d.onSelect(m, d.items[d.filtered[d.sel]])
	}
	before := d.input.Value()
	var cmd tea.Cmd
	d.input, cmd = d.input.Update(msg)
	if d.input.Value() != before {
		d.sel = 0
		if d.query != nil {
			return false, tea.Batch(cmd, d.query(d.input.Value()))
		}
		d.refilter()
	}
	return false, cmd
}

func (d *listDialog) paste(_ *Model, s string) tea.Cmd {
	d.input.SetValue(d.input.Value() + textsafe.Line(s, 200))
	d.input.CursorEnd()
	if d.query != nil {
		return d.query(d.input.Value())
	}
	d.refilter()
	return nil
}

func (d *listDialog) setItems(items []listItem) {
	d.items = items
	d.filtered = nil
	d.refilter()
}

func (d *listDialog) view(m *Model, maxW, maxH int) string {
	if d.filtered == nil {
		d.refilter()
	}
	st := m.st
	w := min(maxW-6, 70)
	d.input.SetWidth(w - 4)
	body := []string{d.input.View(), ""}
	visible := max(3, maxH-10)
	start := 0
	if d.sel >= visible {
		start = d.sel - visible + 1
	}
	if len(d.filtered) == 0 {
		empty := d.empty
		if empty == "" {
			empty = "Nothing matches."
		}
		body = append(body, st.muted.Render(empty))
	}
	for i := start; i < len(d.filtered) && i < start+visible; i++ {
		it := d.items[d.filtered[i]]
		title := ansi.Truncate(textsafe.Line(it.title, 80), w/2, "…")
		desc := ansi.Truncate(textsafe.Line(it.desc, 200), max(4, w-lipgloss.Width(title)-3), "…")
		line := title + "  " + st.muted.Render(desc)
		if i == d.sel {
			plain := title + "  " + desc
			line = st.itemSel.Render(plain + strings.Repeat(" ", max(0, w-lipgloss.Width(plain))))
		}
		body = append(body, line)
	}
	footer := fmt.Sprintf("↑↓ select · Enter open · Esc close · %d item(s)", len(d.filtered))
	return frame(m, d.title, body, footer, maxW, false)
}

func newPaletteDialog(m *Model) dialog {
	var items []listItem
	for _, c := range commands {
		title := "/" + c.name
		if c.args != "" {
			title += " " + c.args
		}
		items = append(items, listItem{title: title, desc: c.desc, value: c})
	}
	return &listDialog{title: "Command palette", items: items, input: newFilterInput(),
		onSelect: func(m *Model, it listItem) tea.Cmd {
			c := it.value.(command)
			if c.args != "" && !strings.HasPrefix(c.args, "[") {
				m.focusInput()
				m.input.SetValue("/" + c.name + " ")
				m.input.CursorEnd()
				return nil
			}
			return c.run(m, nil, "")
		}}
}

func newConversationPicker(m *Model) dialog {
	var items []listItem
	seenDM := map[string]bool{}
	for _, c := range m.convs {
		var title string
		switch c.Kind {
		case storage.KindRoom:
			if !c.Joined {
				continue
			}
			title = "# " + c.Title
		case storage.KindGroup:
			title = "◆ " + c.Title
		case storage.KindDirect:
			seenDM[c.ID] = true
			name := c.Title
			if p, ok := m.be.Peer(c.PeerID); ok {
				name = p.DisplayName
			}
			title = "@ " + name
		}
		desc := ""
		if c.Unread > 0 {
			desc = fmt.Sprintf("%d unread · ", c.Unread)
		}
		if !c.LastActivity.IsZero() {
			desc += "last activity " + c.LastActivity.Local().Format("2 Jan 15:04")
		}
		if c.Kind == storage.KindGroup && !c.Joined {
			desc += " · left"
		}
		items = append(items, listItem{title: textsafe.Line(title, 40), desc: desc, value: c.ID})
	}
	for _, p := range m.peers {
		if p.Trusted() && !seenDM[storage.DirectConversationID(p.ID)] {
			items = append(items, listItem{title: "@ " + textsafe.Line(p.DisplayName, 32), desc: "start a private conversation", value: p.ID})
		}
	}
	return &listDialog{title: "Conversations", items: items, input: newFilterInput(),
		onSelect: func(m *Model, it listItem) tea.Cmd {
			switch v := it.value.(type) {
			case string:
				m.focusInput()
				return m.switchTo(v)
			case identity.PeerID:
				return m.openPeer(v)
			}
			return nil
		}}
}

func peerStatus(p node.PeerInfo) string {
	var s string
	switch {
	case p.Online():
		s = "● online · paired"
	case p.Trusted():
		s = "○ offline · paired"
	case p.Trust == storage.TrustRevoked:
		s = "⊘ trust revoked"
	case p.IncomingPairing:
		s = "? wants to pair"
	case p.Connected:
		s = "◌ nearby · not paired"
	case p.Discovered:
		s = "× discovered but unreachable"
		if p.LastError != "" {
			s += ": " + p.LastError
		}
	default:
		s = "○ not seen recently"
	}
	if p.Warning != "" {
		s = "⚠ " + s
	}
	return s + " · #" + p.ID.Short()
}

func newPeerPicker(m *Model, title string, peers []node.PeerInfo, f func(node.PeerInfo) tea.Cmd) dialog {
	var items []listItem
	for _, p := range peers {
		items = append(items, listItem{title: textsafe.Line(p.DisplayName, 32) + "  " + textsafe.Line(p.DeviceName, 24), desc: peerStatus(p), value: p})
	}
	return &listDialog{title: title, items: items, input: newFilterInput(), empty: "No users known yet. Peers appear here when discovered.",
		onSelect: func(m *Model, it listItem) tea.Cmd { return f(it.value.(node.PeerInfo)) }}
}

func newSearchDialog(m *Model, q string) dialog {
	d := &listDialog{title: "Search messages", input: newFilterInput(), empty: "Type to search all stored messages."}
	d.input.Placeholder = "search text"
	d.input.SetValue(q)
	be := m.be
	titles := map[string]string{}
	for _, c := range m.convs {
		titles[c.ID] = c.Title
	}
	d.query = func(q string) tea.Cmd {
		return func() tea.Msg {
			res, err := be.Search(ctx(), q, "")
			if err != nil {
				return toastMsg{level: "error", text: err.Error()}
			}
			var items []listItem
			for _, r := range res {
				body := strings.ReplaceAll(textsafe.Line(r.Body, 200), "\n", " ")
				items = append(items, listItem{
					title: r.SentAt.Local().Format("02 Jan 15:04") + " " + textsafe.Line(r.SenderName, 20),
					desc:  body + "  (" + textsafe.Line(titles[r.ConversationID], 24) + ")",
					value: r.ConversationID,
				})
			}
			return listItemsMsg{target: d, items: items}
		}
	}
	d.onSelect = func(m *Model, it listItem) tea.Cmd {
		m.focusInput()
		return m.switchTo(it.value.(string))
	}
	if q != "" {
		m.pendingCmd = d.query(q)
	}
	return d
}

func helpDialog(m *Model) dialog {
	k := m.keys
	lines := []string{
		"Keyboard",
		fmt.Sprintf("  %-18s send message", pretty(firstKey(k.send, "enter"))),
		fmt.Sprintf("  %-18s new line (also Alt+Enter / Ctrl+J; Shift+Enter where supported)", pretty(firstKey(k.newline, "alt+enter"))),
		fmt.Sprintf("  %-18s switch panel (sidebar, messages, input)", "Tab / Shift+Tab"),
		fmt.Sprintf("  %-18s command palette", pretty(firstKey(k.palette, "ctrl+p"))),
		fmt.Sprintf("  %-18s search messages", pretty(firstKey(k.search, "ctrl+f"))),
		fmt.Sprintf("  %-18s conversation selector", pretty(firstKey(k.convs, "ctrl+l"))),
		fmt.Sprintf("  %-18s refresh discovery / retry peers", pretty(firstKey(k.refresh, "ctrl+r"))),
		fmt.Sprintf("  %-18s scroll messages", "PgUp / PgDn"),
		fmt.Sprintf("  %-18s previous messages you typed", "↑ / ↓ in input"),
		fmt.Sprintf("  %-18s close dialog", "Esc"),
		fmt.Sprintf("  %-18s quit", pretty(firstKey(k.quit, "ctrl+c"))),
		"",
		"Sidebar symbols",
		"  ● online · ○ offline · ◌ nearby, not paired · × unreachable · ? wants to pair · ⚠ warning · ⊘ revoked",
		"  Message status: ◷ queued · ✓ sent (written to network) · ✓✓ delivered (acknowledged) · ✗ failed",
		"",
		"Commands (local only – they never run shell commands)",
	}
	for _, c := range commands {
		lines = append(lines, fmt.Sprintf("  /%-14s %-20s %s", c.name, c.args, c.desc))
	}
	lines = append(lines, "", "Start a message with // to send text that begins with a slash.",
		"Key bindings can be changed in the [keys] section of the config file.")
	return &infoDialog{title: "LANChat help", lines: lines}
}
