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

// Layout (wide terminals): a header bar; a "Chats" panel and a conversation
// panel with rounded borders and titles in the top border (the focused panel
// is highlighted); a rounded message box; a footer with key hints. Narrow
// terminals (compact) drop the sidebar and the panel borders.

func (m *Model) sidebarWidth() int {
	if m.compact {
		return 0
	}
	if m.width < 100 {
		return sidebarSmall + 4
	}
	return sidebarWide + 4
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
	if m.compact {
		m.input.SetWidth(max(10, m.width-2))
	} else {
		m.input.SetWidth(max(10, m.width-4)) // panel borders and one space of padding
	}
	inputBox := m.input.Height() + 1 // compact: rule above the input
	if !m.compact {
		inputBox = m.input.Height() + 2 // rounded box
	}
	bodyH := max(3, m.height-1-1-inputBox-m.suggestionLines())
	mainW := m.width - m.sidebarWidth()
	m.vp.FillHeight = true
	if m.compact {
		m.vp.SetWidth(max(10, mainW))
		m.vp.SetHeight(max(1, bodyH-1))
	} else {
		m.vp.SetWidth(max(10, mainW-3))
		m.vp.SetHeight(max(1, bodyH-2))
	}
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

// overlay draws the dialog over the screen, centred horizontally and a
// third of the way down. Positions must go through a Compositor: a Layer
// composed directly onto a Canvas ignores its X/Y and repaints the whole
// canvas, which would hide the screen behind the dialog.
func (m *Model) overlay(base, dlg string) string {
	w, h := lipgloss.Size(dlg)
	x := max(0, (m.width-w)/2)
	y := max(0, (m.height-h)/3)
	c := lipgloss.NewCanvas(m.width, m.height)
	c.Compose(lipgloss.NewCompositor(
		lipgloss.NewLayer(base),
		lipgloss.NewLayer(dlg).X(x).Y(y).Z(1),
	))
	return c.Render()
}

func (m *Model) render() string {
	m.layout()
	sw := m.sidebarWidth()
	mainW := m.width - sw
	var body string
	if m.compact {
		bodyH := m.vp.Height() + 1
		main := lipgloss.JoinVertical(lipgloss.Left, fit(" "+m.convTitleLine(mainW-2), mainW), strings.Join(m.messageLines(), "\n"))
		body = lipgloss.NewStyle().Width(mainW).Height(bodyH).MaxHeight(bodyH).Render(main)
	} else {
		bodyH := m.vp.Height() + 2
		var lines []string
		for _, l := range m.messageLines() {
			lines = append(lines, " "+l)
		}
		side := m.panel(m.st.panelTitle.Render("Chats"), m.sidebarLines(sw-2, bodyH-2), sw, bodyH, m.focus == focusSidebar)
		main := m.panel(m.convTitleLine(mainW-8), lines, mainW, bodyH, m.focus == focusMessages)
		body = lipgloss.JoinHorizontal(lipgloss.Top, side, main)
	}
	parts := []string{m.renderHeader(), body}
	if s := m.renderSuggestions(); s != "" {
		parts = append(parts, s)
	}
	parts = append(parts, m.renderInput(), m.renderFooter())
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// messageLines is the visible part of the conversation. A conversation
// shorter than the viewport sits at the bottom, next to the input, like in
// any chat app; the empty-state card is centred instead.
func (m *Model) messageLines() []string {
	lines := strings.Split(m.vp.View(), "\n")
	n := m.vp.TotalLineCount()
	if n <= 0 || n >= len(lines) {
		return lines
	}
	pad := len(lines) - n
	if m.empty {
		pad /= 2
	}
	out := make([]string, 0, len(lines))
	for range pad {
		out = append(out, "")
	}
	out = append(out, lines[:n]...)
	return append(out, lines[n+pad:]...)
}

// panel draws a rounded box of exactly w×h cells with title embedded in the
// top border. The border is highlighted when the panel has focus.
func (m *Model) panel(title string, lines []string, w, h int, focused bool) string {
	bc := m.st.panelBorder
	if focused {
		bc = m.st.panelFocus
	}
	inner := max(1, w-2)
	t := ""
	if title != "" {
		t = ansi.Truncate(" "+title+" ", max(0, inner-2), "…")
	}
	fill := max(0, inner-1-lipgloss.Width(t))
	out := make([]string, 0, h)
	out = append(out, bc.Render("╭─")+t+bc.Render(strings.Repeat("─", fill)+"╮"))
	for i := 0; i < h-2; i++ {
		l := ""
		if i < len(lines) {
			l = lines[i]
		}
		out = append(out, bc.Render("│")+fit(l, inner)+bc.Render("│"))
	}
	out = append(out, bc.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return strings.Join(out, "\n")
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
	bar := st.header
	left := bar.Render(" ") + st.gradient("◆ LANChat", st.header.Bold(true)) + st.headerMuted.Render(" "+buildinfo.Short()+" ")
	status := st.pillOK.Render("● ONLINE")
	if net.InterfaceError != "" {
		status = st.pillWarn.Render("○ NO LAN")
	}
	lan := "no LAN"
	if len(net.Interfaces) > 0 {
		it := net.Interfaces[0]
		lan = it.Name
		if v4 := it.IPv4(); len(v4) > 0 {
			lan += " " + v4[0].String()
		}
	}
	lan += fmt.Sprintf(":%d", net.Port)
	name := bar.Bold(true).Render(textsafe.Line(m.self.DisplayName, 32) + " ")
	info := fmt.Sprintf("  %d online", net.TrustedOnline)
	if !m.compact {
		info += " · " + lan
	}
	right := name + status + st.headerMuted.Render(info+" ")
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		right = status + bar.Render(" ")
		gap = m.width - lipgloss.Width(left) - lipgloss.Width(right)
	}
	if gap < 1 {
		return fit(left, m.width)
	}
	return left + bar.Render(strings.Repeat(" ", gap)) + right
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

// convTitleLine is the styled title and status of the open conversation.
func (m *Model) convTitleLine(maxW int) string {
	st := m.st
	kind, key, _ := storage.ParseConversationID(m.current)
	title := st.title.Render(m.convTitlePlain())
	var info string
	switch kind {
	case storage.KindRoom:
		n := len(m.be.RoomMembers(key))
		info = st.subtitle.Render(fmt.Sprintf("%d paired peer(s) online in this room", n))
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
			info = st.subtitle.Render("private group · /group members")
		}
	}
	line := title
	if info != "" {
		line += "  " + info
	}
	if lipgloss.Width(line) > maxW {
		line = ansi.Truncate(line, max(1, maxW), "…")
	}
	return line
}

func (m *Model) sidebarLines(w, h int) []string {
	var lines []string
	selLine := -1
	for i, it := range m.items {
		if it.kind == itemHeader && len(lines) > 0 {
			lines = append(lines, "")
		}
		if i == m.sel {
			selLine = len(lines)
		}
		lines = append(lines, m.renderItem(i, it, w))
	}
	if selLine >= h {
		lines = lines[selLine-h+1:]
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return lines
}

func (m *Model) renderItem(i int, it sidebarItem, w int) string {
	st := m.st
	if it.kind == itemHeader {
		title, count, _ := strings.Cut(it.title, " ")
		return fit(" "+st.section.Render(title)+" "+st.muted.Render(count), w)
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
		n := fmt.Sprint(it.unread)
		if it.unread > 99 {
			n = "99+"
		}
		badge = st.badge.Render(n)
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
	nameW := max(1, w-4-lipgloss.Width(badge))
	name := ansi.Truncate(it.title+suffix, nameW, "…")
	selected := i == m.sel && m.focus == focusSidebar
	current := it.convID == m.current || (it.kind == itemPeer && "dm:"+string(it.peerID) == m.current)
	if selected {
		return st.itemSel.Render(fit(" "+it.icon+" "+name, w-lipgloss.Width(badge))) + badge
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
		marker = st.accent.Render("▍")
	}
	return fit(marker+iconStyle.Render(it.icon)+" "+nameStyle.Render(name), w-lipgloss.Width(badge)) + badge
}

// renderMessages renders the conversation into the viewport. Every message
// line carries a coloured gutter bar in the sender's colour; message text
// is indented after it, so a message can never imitate a sender line.
func (m *Model) renderMessages() {
	st := m.st
	w := max(10, m.vp.Width()-1)
	var lines []string
	if m.hasOlder {
		lines = append(lines, st.muted.Render(center("↑ older messages – scroll up to load more", w)))
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
			lines = append(lines, m.daySeparator(label, w))
			lastDay, lastSender = day, ""
		}
		if msg.Kind == storage.MessageSystem {
			lines = append(lines, "")
			for _, l := range strings.Split(ansi.Wrap(textsafe.Text(msg.Body), w-4, ""), "\n") {
				lines = append(lines, "  "+st.system.Render("ⓘ "+l))
			}
			lastSender = ""
			continue
		}
		bar := st.userStyle(string(msg.SenderID)).Render("▎")
		if msg.Outgoing {
			bar = st.accent.Render("▎")
		}
		grouped := string(msg.SenderID) == lastSender && t.Sub(lastTime) < 5*time.Minute && !msg.Outgoing
		if !grouped {
			lines = append(lines, "")
			name := textsafe.Line(msg.SenderName, 32)
			nameStyle := st.userStyle(string(msg.SenderID))
			if msg.Outgoing {
				name += " (you)"
				nameStyle = st.accent
			} else if strings.EqualFold(name, textsafe.Line(m.self.DisplayName, 32)) || m.ambiguousName(name) || m.nameCount[strings.ToLower(name)] == 0 {
				// Names are not identities: show the short peer ID whenever a
				// name collides with someone else's, imitates "(you)", or
				// belongs to nobody currently known.
				name += " #" + identityID(string(msg.SenderID)).Short()
			}
			left := bar + " " + nameStyle.Render(name)
			right := st.timestamp.Render(m.formatTime(t))
			if msg.Outgoing {
				status, sst := m.deliveryStatus(msg)
				right = sst.Render(status) + st.timestamp.Render("  "+m.formatTime(t))
			}
			gap := w - lipgloss.Width(left) - lipgloss.Width(right)
			if gap < 1 {
				lines = append(lines, left, bar+"  "+right)
			} else {
				lines = append(lines, left+strings.Repeat(" ", gap)+right)
			}
		}
		const maxLines = 400
		wrapped := strings.Split(ansi.Wrap(textsafe.Text(msg.Body), w-3, ""), "\n")
		if len(wrapped) > maxLines {
			wrapped = append(wrapped[:maxLines], st.muted.Render(fmt.Sprintf("… %d more lines (use /export to see everything)", len(wrapped)-maxLines)))
		}
		for _, l := range wrapped {
			lines = append(lines, bar+"  "+st.body.Render(l))
		}
		lastSender, lastTime = string(msg.SenderID), t
	}
	m.empty = shown == 0
	if m.empty {
		lines = append(lines, m.emptyState(w)...)
	}
	m.vp.SetContent(strings.Join(lines, "\n"))
	if m.follow {
		m.vp.GotoBottom()
	}
}

func (m *Model) daySeparator(label string, w int) string {
	st := m.st
	l := " " + label + " "
	side := (w - lipgloss.Width(l)) / 2
	if side < 2 {
		return st.dateLabel.Render(l)
	}
	return st.dateSep.Render(strings.Repeat("─", side)) + st.dateLabel.Render(l) + st.dateSep.Render(strings.Repeat("─", w-side-lipgloss.Width(l)))
}

// emptyState shows a welcome card in an empty room and a short hint
// elsewhere.
func (m *Model) emptyState(w int) []string {
	st := m.st
	kind, _, _ := storage.ParseConversationID(m.current)
	_, cleared := m.clearedAt[m.current]
	if kind != storage.KindRoom || cleared {
		return []string{"", st.muted.Render(center(m.emptyText(), w))}
	}
	key := func(k string) string { return st.keycap.Render(k) }
	body := strings.Join([]string{
		st.gradient("Welcome to LANChat, "+textsafe.Line(m.self.DisplayName, 32)+"!", lipgloss.NewStyle().Bold(true)),
		"",
		st.text.Render("• People on your network appear under ") + st.accent.Render("NEARBY") + st.text.Render("."),
		st.text.Render("• Select someone with ") + key("Tab") + st.text.Render(" ") + key("↑↓") + st.text.Render(" ") + key("Enter") + st.text.Render(" to pair."),
		st.text.Render("• Compare the six-digit code, then chat right here."),
		st.text.Render("• ") + key(pretty(firstKey(m.keys.palette, "ctrl+p"))) + st.text.Render(" opens every command, ") + key("/help") + st.text.Render(" lists them."),
		"",
		st.muted.Render("Encrypted with TLS 1.3 · stays on your LAN · no accounts"),
	}, "\n")
	card := st.card.Render(body)
	if lipgloss.Width(card) > w {
		return []string{"", st.muted.Render(center(m.emptyText(), w))}
	}
	out := []string{""}
	for _, l := range strings.Split(card, "\n") {
		out = append(out, strings.Repeat(" ", max(0, (w-lipgloss.Width(card))/2))+l)
	}
	return out
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
	var parts []string
	for _, s := range m.suggestions() {
		parts = append(parts, m.st.accent.Render(s))
	}
	return fit(" "+m.st.keycap.Render("Tab")+" "+strings.Join(parts, m.st.muted.Render("  ")), m.width)
}

func (m *Model) renderInput() string {
	if m.compact {
		return lipgloss.JoinVertical(lipgloss.Left, m.st.separator.Render(strings.Repeat("─", m.width)), m.input.View())
	}
	var lines []string
	for _, l := range strings.Split(m.input.View(), "\n") {
		lines = append(lines, " "+l)
	}
	title := m.st.panelTitle.Render("Message") + m.st.muted.Render(" "+m.convTitlePlain())
	return m.panel(title, lines, m.width, len(lines)+2, m.focus == focusInput)
}

func (m *Model) renderFooter() string {
	st := m.st
	if m.toast.text != "" {
		icon, style := st.accent.Render("ℹ"), st.text
		switch m.toast.level {
		case "error":
			icon, style = st.err.Render("✗"), st.err
		case "warn":
			icon, style = st.warn.Render("⚠"), st.warn
		case "success":
			icon, style = st.success.Render("✓"), st.success
		}
		return fit(" "+icon+" "+style.Render(m.toast.text), m.width)
	}
	k := func(key, desc string) string { return st.keycap.Render(key) + st.footer.Render(" "+desc) }
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
	left := " "
	if len(m.pending) > 0 {
		left += st.pillWarn.Render(fmt.Sprintf("%d waiting", len(m.pending))) + "  "
	}
	right := m.transferSummary()
	room := m.width
	if right != "" {
		room -= lipgloss.Width(right) + 2
	}
	// Whole hints only: drop the ones that do not fit rather than cutting
	// one in half.
	for i, p := range parts {
		sep := ""
		if i > 0 {
			sep = "  "
		}
		if lipgloss.Width(left)+lipgloss.Width(sep+p) > room {
			break
		}
		left += sep + p
	}
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
	const barW = 10
	filled := pct * barW / 100
	bar := m.st.accent.Render(strings.Repeat("█", filled)) + m.st.muted.Render(strings.Repeat("░", barW-filled))
	s := fmt.Sprintf("%s %s ", arrow, textsafe.Line(t.Name, 20)) + bar + fmt.Sprintf(" %3d%% ", pct)
	if len(list) > 1 {
		s += fmt.Sprintf("+%d ", len(list)-1)
	}
	return s
}

func wrapLines(s string, w int) []string {
	return strings.Split(ansi.Wrap(s, w, ""), "\n")
}
