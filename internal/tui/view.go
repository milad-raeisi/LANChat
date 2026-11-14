package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/milad-raeisi/LANChat/internal/buildinfo"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

func (m *Model) sidebarWidth() int {
	if m.compact {
		return 0
	}
	if m.width < 100 {
		return sidebarSmall
	}
	return sidebarWide
}

func (m *Model) suggestionLines() int {
	if len(m.suggestions()) > 0 && m.focus == focusInput && m.dialog == nil {
		return 1
	}
	return 0
}

// layout recomputes component sizes for the terminal size.
func (m *Model) layout() {
	m.compact = m.width < 72 || m.height < 16
	if m.compact && m.focus == focusSidebar {
		m.focus = focusInput
		m.input.Focus()
	}
	m.input.SetWidth(max(10, m.width-2))
	inputH := m.input.Height()
	bodyH := m.height - 1 /*header*/ - 1 /*footer*/ - 1 /*input rule*/ - inputH - m.suggestionLines()
	sw := m.sidebarWidth()
	mainW := m.width
	if sw > 0 {
		mainW = m.width - sw - 1
	}
	m.vp.SetWidth(max(10, mainW))
	m.vp.SetHeight(max(1, bodyH-1 /*conversation title*/))
}

// View implements tea.Model.
func (m *Model) View() tea.View {
	var content string
	if m.width < minWidth || m.height < minHeight {
		content = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			fmt.Sprintf("Terminal too small (%d×%d).\nLANChat needs at least %d×%d.", m.width, m.height, minWidth, minHeight))
	} else {
		content = m.render()
		if m.dialog != nil {
			content = m.overlay(content, m.dialog.view(m, min(m.width-4, 76), m.height-4))
		}
	}
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "LANChat – " + m.convTitlePlain()
	if m.cfg.UI.Mouse {
		v.MouseMode = tea.MouseModeCellMotion
	}
	return v
}

func (m *Model) overlay(base, dlg string) string {
	c := lipgloss.NewCanvas(m.width, m.height)
	c.Compose(lipgloss.NewLayer(base))
	w, h := lipgloss.Size(dlg)
	x := max(0, (m.width-w)/2)
	y := max(0, (m.height-h)/3)
	c.Compose(lipgloss.NewLayer(dlg).X(x).Y(y).Z(1))
	return c.Render()
}

func (m *Model) render() string {
	m.layout()
	header := m.renderHeader()
	sw := m.sidebarWidth()
	mainW := m.vp.Width()
	bodyH := m.vp.Height() + 1
	main := lipgloss.JoinVertical(lipgloss.Left, m.renderConvTitle(mainW), m.vp.View())
	main = lipgloss.NewStyle().Width(mainW).Height(bodyH).MaxHeight(bodyH).Render(main)
	body := main
	if sw > 0 {
		sep := m.st.separator.Render(strings.TrimRight(strings.Repeat("│\n", bodyH), "\n"))
		body = lipgloss.JoinHorizontal(lipgloss.Top, m.renderSidebar(sw, bodyH), sep, main)
	}
	rule := m.st.separator.Render(strings.Repeat("─", m.width))
	parts := []string{header, body, rule}
	if s := m.renderSuggestions(); s != "" {
		parts = append(parts, s)
	}
	parts = append(parts, m.input.View(), m.renderFooter())
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) > w {
		return ansi.Truncate(s, w, "…")
	}
	return s + strings.Repeat(" ", w-lipgloss.Width(s))
}

func (m *Model) renderHeader() string {
	st := m.st
	net := m.be.NetworkStatus()
	status := st.header.Foreground(m.theme.Success).Render("● Online")
	if m.theme.Mono {
		status = st.header.Render("● Online")
	}
	if net.InterfaceError != "" {
		status = st.header.Foreground(m.theme.Warn).Render("○ No LAN")
	}
	lan := "LAN: "
	if len(net.Interfaces) > 0 {
		it := net.Interfaces[0]
		lan += it.Name
		if v4 := it.IPv4(); len(v4) > 0 {
			lan += " " + v4[0].String()
		}
	} else {
		lan += "none"
	}
	lan += fmt.Sprintf(":%d", net.Port)
	sep := st.headerMuted.Render(" │ ")
	segs := []string{
		st.headerAccent.Render(" LANChat ") + st.headerMuted.Render(buildinfo.Short()),
		st.header.Render(textsafe.Line(m.self.DisplayName, 32)) + " " + status,
		st.header.Render(fmt.Sprintf("%d online", net.TrustedOnline)),
	}
	if !m.compact {
		segs = append(segs, st.headerMuted.Render(lan))
	}
	segs = append(segs, st.header.Render(m.convTitlePlain()))
	line := strings.Join(segs, sep)
	return st.header.Render(fit(line, m.width))
}

func (m *Model) convTitlePlain() string {
	kind, key, _ := storage.ParseConversationID(m.current)
	switch kind {
	case storage.KindRoom:
		return "# " + key
	case storage.KindDirect:
		if p, ok := m.be.Peer(identityID(key)); ok {
			return "@ " + textsafe.Line(p.DisplayName, 32)
		}
	case storage.KindGroup:
		if c, ok := m.currentConversation(); ok {
			return "◆ " + textsafe.Line(c.Title, 32)
		}
	}
	return m.current
}

func (m *Model) renderConvTitle(w int) string {
	st := m.st
	kind, key, _ := storage.ParseConversationID(m.current)
	title := st.title.Render(m.convTitlePlain())
	var info string
	switch kind {
	case storage.KindRoom:
		n := len(m.be.RoomMembers(key))
		info = fmt.Sprintf("%d paired peer(s) online in this room", n)
	case storage.KindDirect:
		if p, ok := m.be.Peer(identityID(key)); ok {
			switch {
			case !p.Trusted():
				info = st.warn.Render("not paired") + st.subtitle.Render(" – messages cannot be exchanged")
			case p.Connected:
				info = st.online.Render("● online") + st.subtitle.Render(" · paired")
				if p.Verified {
					info += st.subtitle.Render(" · code verified")
				}
			default:
				info = st.offline.Render("○ offline") + st.subtitle.Render(" · messages are queued until they reconnect")
			}
		}
	case storage.KindGroup:
		if c, ok := m.currentConversation(); ok && !c.Joined {
			info = st.warn.Render("you are no longer a member")
		} else {
			info = "private group · /group members"
		}
	}
	line := " " + title
	if info != "" {
		line += st.subtitle.Render("  ") + st.subtitle.Render(info)
	}
	return fit(line, w)
}

func (m *Model) renderSidebar(w, h int) string {
	st := m.st
	lines := make([]string, 0, len(m.items))
	for i, it := range m.items {
		lines = append(lines, m.renderItem(i, it, w))
	}
	// Keep the selection visible.
	offset := 0
	if m.sel >= h {
		offset = m.sel - h + 1
	}
	if offset > 0 && offset < len(lines) {
		lines = lines[offset:]
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	_ = st
	return strings.Join(lines, "\n")
}

func (m *Model) renderItem(i int, it sidebarItem, w int) string {
	st := m.st
	if it.kind == itemHeader {
		return fit(" "+st.section.Render(it.title), w)
	}
	iconStyle := st.muted
	switch it.state {
	case "online":
		iconStyle = st.online
	case "warning", "pairing":
		iconStyle = st.warn
	case "unreachable", "revoked":
		iconStyle = st.err
	case "room", "group":
		iconStyle = st.accent
	}
	badge := ""
	if it.unread > 0 {
		badge = fmt.Sprintf(" (%d)", it.unread)
		if it.unread > 99 {
			badge = " (99+)"
		}
	}
	suffix := ""
	switch it.state {
	case "left":
		suffix = " (left)"
	case "pairing":
		suffix = " wants to pair"
	case "unreachable":
		suffix = " unreachable"
	case "revoked":
		suffix = " revoked"
	}
	nameW := w - 4 - lipgloss.Width(badge)
	name := ansi.Truncate(it.title+suffix, max(1, nameW), "…")
	selected := i == m.sel && m.focus == focusSidebar
	current := it.convID == m.current || (it.kind == itemPeer && "dm:"+string(it.peerID) == m.current)
	if selected {
		plain := " " + it.icon + " " + name
		pad := w - lipgloss.Width(plain) - lipgloss.Width(badge)
		return st.itemSel.Render(plain + strings.Repeat(" ", max(0, pad)) + badge)
	}
	nameStyle := st.item
	if current {
		nameStyle = st.accent
	}
	if it.state == "left" || it.state == "offline" || it.state == "unreachable" {
		nameStyle = st.itemMuted
	}
	if it.unread > 0 {
		nameStyle = nameStyle.Bold(true)
	}
	marker := " "
	if current {
		marker = st.accent.Render("▌")
	}
	line := marker + iconStyle.Render(it.icon) + " " + nameStyle.Render(name)
	pad := w - lipgloss.Width(line) - lipgloss.Width(badge)
	return line + strings.Repeat(" ", max(0, pad)) + st.unread.Render(badge)
}

// renderMessages renders the conversation into the viewport.
func (m *Model) renderMessages() {
	st := m.st
	w := max(10, m.vp.Width()-1)
	var lines []string
	if m.hasOlder {
		lines = append(lines, st.muted.Render("  ↑ older messages – scroll up to load more"))
	}
	cleared := m.clearedAt[m.current]
	lastDay := ""
	var lastSender string
	var lastTime time.Time
	shown := 0
	for _, msg := range m.msgs {
		if msg.Seq <= cleared {
			continue
		}
		shown++
		t := msg.SentAt.Local()
		day := t.Format("2006-01-02")
		if day != lastDay {
			label := t.Format("Monday, 2 January 2006")
			if day == time.Now().Format("2006-01-02") {
				label = "Today"
			} else if day == time.Now().AddDate(0, 0, -1).Format("2006-01-02") {
				label = "Yesterday"
			}
			if len(lines) > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, st.dateSep.Render(center("─── "+label+" ───", w)))
			lastDay, lastSender = day, ""
		}
		if msg.Kind == storage.MessageSystem {
			for _, l := range strings.Split(ansi.Wrap(textsafe.Text(msg.Body), w-4, ""), "\n") {
				lines = append(lines, "  "+st.system.Render("· "+l))
			}
			lastSender = ""
			continue
		}
		grouped := string(msg.SenderID) == lastSender && t.Sub(lastTime) < 5*time.Minute && !msg.Outgoing
		if !grouped {
			if len(lines) > 0 && lines[len(lines)-1] != "" {
				lines = append(lines, "")
			}
			name := textsafe.Line(msg.SenderName, 32)
			nameStyle := st.userStyle(string(msg.SenderID))
			if msg.Outgoing {
				name = name + " (you)"
			} else if m.ambiguousName(name) || m.nameCount[strings.ToLower(name)] == 0 {
				// Names are not identities: show the short peer ID whenever a
				// name collides with someone else's, imitates "(you)", or
				// belongs to nobody currently known.
				name += " #" + identityID(string(msg.SenderID)).Short()
			}
			left := nameStyle.Render(name)
			right := st.timestamp.Render(m.formatTime(t))
			if msg.Outgoing {
				status, sst := m.deliveryStatus(msg)
				right = sst.Render(status) + st.timestamp.Render("  "+m.formatTime(t))
			}
			gap := w - lipgloss.Width(left) - lipgloss.Width(right)
			if gap < 1 {
				lines = append(lines, left, right)
			} else {
				lines = append(lines, left+strings.Repeat(" ", gap)+right)
			}
		}
		body := textsafe.Text(msg.Body)
		const maxLines = 400
		wrapped := strings.Split(ansi.Wrap(body, w-2, ""), "\n")
		if len(wrapped) > maxLines {
			wrapped = append(wrapped[:maxLines], st.muted.Render(fmt.Sprintf("… %d more lines (use /export to see everything)", len(wrapped)-maxLines)))
		}
		for _, l := range wrapped {
			lines = append(lines, "  "+st.body.Render(l))
		}
		lastSender, lastTime = string(msg.SenderID), t
	}
	if shown == 0 {
		lines = append(lines, "", st.muted.Render(center(m.emptyText(), w)))
	}
	m.vp.SetContent(strings.Join(lines, "\n"))
	if m.follow {
		m.vp.GotoBottom()
	}
}

func (m *Model) emptyText() string {
	if _, ok := m.clearedAt[m.current]; ok {
		return "View cleared. Stored history is kept – use /history to show it again."
	}
	kind, _, _ := storage.ParseConversationID(m.current)
	switch kind {
	case storage.KindDirect:
		return "No messages yet. Say hello!"
	case storage.KindGroup:
		return "No messages in this group yet."
	}
	return "No messages yet. Messages go to paired peers who joined this room."
}

func center(s string, w int) string {
	sw := lipgloss.Width(s)
	if sw >= w {
		return s
	}
	return strings.Repeat(" ", (w-sw)/2) + s
}

func (m *Model) formatTime(t time.Time) string {
	if m.cfg.UI.TimeFormat == "12h" {
		return t.Format("3:04 PM")
	}
	return t.Format("15:04")
}

// deliveryStatus describes an outgoing message honestly: "sent" means
// written to the network, "delivered" means the recipient acknowledged
// storing it. Read receipts do not exist.
func (m *Model) deliveryStatus(msg storage.Message) (string, lipgloss.Style) {
	d := msg.Delivery
	t := d.Total()
	st := m.st
	switch {
	case t == 0:
		return "· nobody online received this", st.muted
	case d.Delivered == t && t == 1:
		return "✓✓ delivered", st.success
	case d.Delivered == t:
		return fmt.Sprintf("✓✓ delivered to all %d", t), st.success
	case d.Failed == t:
		return "✗ failed", st.err
	case d.Delivered > 0:
		s := fmt.Sprintf("✓✓ %d/%d delivered", d.Delivered, t)
		if d.Failed > 0 {
			s += fmt.Sprintf(", %d failed", d.Failed)
		}
		return s, st.success
	case d.Sent > 0:
		return "✓ sent", st.muted
	case d.Failed > 0:
		return fmt.Sprintf("◷ pending, %d failed", d.Failed), st.warn
	default:
		return "◷ queued", st.warn
	}
}

func (m *Model) renderSuggestions() string {
	if m.suggestionLines() == 0 {
		return ""
	}
	s := m.suggestions()
	line := " " + m.st.muted.Render("Tab ⇥ ") + m.st.accent.Render(strings.Join(s, "  "))
	return fit(line, m.width)
}

func (m *Model) renderFooter() string {
	st := m.st
	if m.toast.text != "" {
		style := st.text
		switch m.toast.level {
		case "error":
			style = st.err
		case "warn":
			style = st.warn
		case "success":
			style = st.success
		}
		return fit(" "+style.Render(m.toast.text), m.width)
	}
	k := func(key, desc string) string { return st.footerKey.Render(key) + " " + st.footer.Render(desc) }
	var parts []string
	switch m.focus {
	case focusSidebar:
		parts = []string{k("↑↓", "move"), k("Enter", "open / pair"), k("Tab", "next panel"), k("Esc", "back to input")}
	case focusMessages:
		parts = []string{k("↑↓", "scroll"), k("PgUp/PgDn", "page"), k("Home/End", "top/bottom"), k("Esc", "input")}
	default:
		parts = []string{k(pretty(firstKey(m.keys.send, "enter")), "send"), k(pretty(firstKey(m.keys.newline, "alt+enter")), "newline"),
			k("Tab", "panels"), k(pretty(firstKey(m.keys.palette, "ctrl+p")), "commands"), k(pretty(firstKey(m.keys.search, "ctrl+f")), "search"),
			k(pretty(firstKey(m.keys.convs, "ctrl+l")), "chats"), k(pretty(firstKey(m.keys.help, "f1")), "help"), k(pretty(firstKey(m.keys.quit, "ctrl+c")), "quit")}
	}
	sep := st.footer.Render(" │ ")
	left := " " + strings.Join(parts, sep)
	if len(m.pending) > 0 {
		left = " " + st.warn.Render(fmt.Sprintf("%d request(s) waiting", len(m.pending))) + sep + strings.Join(parts, sep)
	}
	right := m.transferSummary()
	if right != "" && lipgloss.Width(left)+lipgloss.Width(right)+2 <= m.width {
		return left + strings.Repeat(" ", m.width-lipgloss.Width(left)-lipgloss.Width(right)) + right
	}
	return fit(left, m.width)
}

func pretty(k string) string {
	parts := strings.Split(k, "+")
	for i, p := range parts {
		switch p {
		case "ctrl":
			parts[i] = "Ctrl"
		case "alt":
			parts[i] = "Alt"
		case "shift":
			parts[i] = "Shift"
		case "enter":
			parts[i] = "Enter"
		default:
			if len(p) == 1 {
				parts[i] = strings.ToUpper(p)
			} else {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
	}
	return strings.Join(parts, "+")
}

func (m *Model) transferSummary() string {
	if len(m.transfers) == 0 {
		return ""
	}
	var list []node.TransferInfo
	for _, t := range m.transfers {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].StartedAt.Before(list[j].StartedAt) })
	t := list[0]
	arrow := "↓"
	if t.Outgoing {
		arrow = "↑"
	}
	pct := 0
	if t.Size > 0 {
		pct = int(t.Transferred * 100 / t.Size)
	}
	s := fmt.Sprintf("%s %s %d%% ", arrow, textsafe.Line(t.Name, 24), pct)
	if len(list) > 1 {
		s += fmt.Sprintf("+%d ", len(list)-1)
	}
	return m.st.accent.Render(s)
}

func wrapLines(s string, w int) []string {
	return strings.Split(ansi.Wrap(s, w, ""), "\n")
}
