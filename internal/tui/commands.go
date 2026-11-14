package tui

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/storage"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

func identityID(s string) identity.PeerID { return identity.PeerID(s) }

// command describes a slash command. Commands are local UI actions; none of
// them executes shell commands or anything received from the network.
type command struct {
	name string
	args string
	desc string
	run  func(m *Model, args []string, rest string) tea.Cmd
}

var commands []command

func init() {
	commands = []command{
		{"help", "", "Show commands and keyboard shortcuts", func(m *Model, _ []string, _ string) tea.Cmd { return openDialog(helpDialog(m)) }},
		{"users", "", "List everyone LANChat knows about", cmdUsers},
		{"online", "", "List paired peers that are online", cmdOnline},
		{"rooms", "", "List public rooms", cmdRooms},
		{"join", "<room>", "Join a public room", cmdJoin},
		{"create", "<room>", "Create (and join) a public room", cmdJoin},
		{"leave", "[room]", "Leave the current room or group", cmdLeave},
		{"msg", "<user> [text]", "Open a private conversation (and send text)", cmdMsg},
		{"pair", "<user>", "Verify and pair with a nearby user", cmdPair},
		{"unpair", "<user>", "Revoke trust in a paired user", cmdUnpair},
		{"group", "create|invite|remove|members|leave …", "Manage private groups", cmdGroup},
		{"file", "send <user> <path>", "Send a file to a paired user", cmdFile},
		{"transfers", "", "Show file transfers (cancel active ones)", cmdTransfers},
		{"whoami", "", "Show your identity and fingerprint", cmdWhoami},
		{"status", "", "Show connection status", cmdStatus},
		{"network", "", "Show network and discovery details", cmdNetwork},
		{"ping", "[user]", "Measure round-trip time to a peer", cmdPing},
		{"search", "<text>", "Search stored messages", func(m *Model, _ []string, rest string) tea.Cmd { return openDialog(newSearchDialog(m, rest)) }},
		{"history", "", "Browse stored conversations", cmdHistory},
		{"clear", "", "Clear the visible conversation (history is kept)", cmdClear},
		{"retry", "", "Retry failed messages in this conversation", cmdRetry},
		{"export", "[json|text] [path]", "Export this conversation to a file", cmdExport},
		{"delete-history", "", "Permanently delete this conversation's history", cmdDeleteHistory},
		{"refresh", "", "Rediscover peers and retry connections", func(m *Model, _ []string, _ string) tea.Cmd {
			m.be.RefreshDiscovery()
			return toastCmd("info", "Refreshing discovery…")
		}},
		{"theme", "[dark|light|minimal|monochrome]", "Change the colour theme", cmdTheme},
		{"bell", "[on|off]", "Toggle the terminal bell for notifications", cmdBell},
		{"settings", "", "Show settings and where to change them", cmdSettings},
		{"quit", "", "Exit LANChat", func(m *Model, _ []string, _ string) tea.Cmd { m.quitting = true; return tea.Quit }},
	}
}

// splitArgs splits a command line on spaces, honouring double quotes so
// paths with spaces can be given.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			has = true
		case r == ' ' && !inQuote:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

// restAfter returns the raw text after the first n space-separated fields.
func restAfter(s string, n int) string {
	s = strings.TrimLeft(s, " ")
	for i := 0; i < n; i++ {
		j := strings.IndexByte(s, ' ')
		if j < 0 {
			return ""
		}
		s = strings.TrimLeft(s[j:], " ")
	}
	return s
}

func findCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func (m *Model) runCommand(line string) tea.Cmd {
	body := strings.TrimPrefix(line, "/")
	fields := splitArgs(body)
	if len(fields) == 0 {
		return nil
	}
	name := strings.ToLower(fields[0])
	switch name { // aliases
	case "q", "exit":
		name = "quit"
	case "revoke":
		name = "unpair"
	case "m", "dm":
		name = "msg"
	case "?":
		name = "help"
	}
	c, ok := findCommand(name)
	if !ok {
		return toastCmd("warn", "Unknown command /%s – type /help for the list.", textsafe.Line(fields[0], 20))
	}
	return c.run(m, fields[1:], restAfter(body, 1))
}

// suggestions returns completions for the current input.
func (m *Model) suggestions() []string {
	v := m.input.Value()
	if !strings.HasPrefix(v, "/") || strings.Contains(v, "\n") {
		return nil
	}
	if !strings.Contains(v, " ") {
		prefix := strings.ToLower(v[1:])
		var out []string
		for _, c := range commands {
			if strings.HasPrefix(c.name, prefix) {
				out = append(out, "/"+c.name)
			}
		}
		if len(out) == 1 && out[0] == v {
			return nil
		}
		return out
	}
	if base, partial, ok := m.peerArgContext(v); ok {
		_ = base
		var out []string
		for _, p := range m.peers {
			label := strings.ReplaceAll(textsafe.Line(p.DisplayName, 32), " ", "_")
			if strings.HasPrefix(strings.ToLower(label), strings.ToLower(partial)) {
				out = append(out, label)
			}
		}
		sort.Strings(out)
		if len(out) > 8 {
			out = out[:8]
		}
		if len(out) == 1 && strings.EqualFold(out[0], partial) {
			return nil
		}
		return out
	}
	return nil
}

// peerArgContext reports whether the cursor is at a user-name argument.
func (m *Model) peerArgContext(v string) (base, partial string, ok bool) {
	for _, prefix := range []string{"/msg ", "/pair ", "/unpair ", "/revoke ", "/ping ", "/file send ", "/group invite ", "/group remove "} {
		if strings.HasPrefix(strings.ToLower(v), prefix) {
			rest := v[len(prefix):]
			if !strings.Contains(rest, " ") {
				return v[:len(prefix)], rest, true
			}
		}
	}
	return "", "", false
}

func (m *Model) completable() bool { return len(m.suggestions()) > 0 }

func (m *Model) complete() {
	s := m.suggestions()
	if len(s) == 0 {
		return
	}
	v := m.input.Value()
	if !strings.Contains(v, " ") {
		m.input.SetValue(commonPrefix(s) + map[bool]string{true: " ", false: ""}[len(s) == 1])
		m.input.CursorEnd()
		return
	}
	if base, _, ok := m.peerArgContext(v); ok {
		m.input.SetValue(base + commonPrefix(s) + map[bool]string{true: " ", false: ""}[len(s) == 1])
		m.input.CursorEnd()
	}
}

func commonPrefix(list []string) string {
	if len(list) == 0 {
		return ""
	}
	p := list[0]
	for _, s := range list[1:] {
		for !strings.HasPrefix(strings.ToLower(s), strings.ToLower(p)) && p != "" {
			p = p[:len(p)-1]
		}
	}
	return p
}

// withPeer resolves a user reference and runs f, asking the user to choose
// when the name is ambiguous. Display names are not identities.
func (m *Model) withPeer(ref string, filter func(node.PeerInfo) bool, f func(p node.PeerInfo) tea.Cmd) tea.Cmd {
	ref = strings.ReplaceAll(ref, "_", " ")
	matches := m.be.ResolvePeer(ref)
	if len(matches) == 0 {
		matches = m.be.ResolvePeer(strings.ReplaceAll(ref, " ", "_"))
	}
	var out []node.PeerInfo
	for _, p := range matches {
		if filter == nil || filter(p) {
			out = append(out, p)
		}
	}
	switch len(out) {
	case 0:
		return toastCmd("warn", "No matching user %q. /users lists everyone LANChat knows.", textsafe.Line(ref, 32))
	case 1:
		return f(out[0])
	}
	return openDialog(newPeerPicker(m, "Several users match "+textsafe.Line(ref, 32)+" – choose one", out, f))
}

func needArgs(usage string) tea.Cmd { return toastCmd("warn", "Usage: %s", usage) }

func cmdUsers(m *Model, _ []string, _ string) tea.Cmd {
	return openDialog(newPeerPicker(m, "Users", m.be.Peers(), func(p node.PeerInfo) tea.Cmd { return m.openPeer(p.ID) }))
}

func cmdOnline(m *Model, _ []string, _ string) tea.Cmd {
	var list []node.PeerInfo
	for _, p := range m.be.Peers() {
		if p.Online() {
			list = append(list, p)
		}
	}
	if len(list) == 0 {
		return toastCmd("info", "No paired peers are online right now.")
	}
	return openDialog(newPeerPicker(m, "Online", list, func(p node.PeerInfo) tea.Cmd { return m.openPeer(p.ID) }))
}

func cmdRooms(m *Model, _ []string, _ string) tea.Cmd {
	var items []listItem
	for _, r := range m.be.Rooms() {
		desc := fmt.Sprintf("%d paired peer(s) online", r.Members)
		if r.Joined {
			desc = "joined · " + desc
		}
		items = append(items, listItem{title: "# " + r.Name, desc: desc, value: r.Name})
	}
	return openDialog(&listDialog{title: "Rooms (Enter to join/open)", items: items, input: newFilterInput(),
		onSelect: func(m *Model, it listItem) tea.Cmd { return joinRoom(m, it.value.(string)) }})
}

func joinRoom(m *Model, name string) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		conv, err := be.JoinRoom(ctx(), name)
		return openConvMsg{conv: conv, err: err}
	}
}

func cmdJoin(m *Model, args []string, _ string) tea.Cmd {
	if len(args) == 0 {
		return needArgs("/join <room>")
	}
	return joinRoom(m, args[0])
}

func cmdLeave(m *Model, args []string, _ string) tea.Cmd {
	be := m.be
	if len(args) > 0 {
		name := args[0]
		return func() tea.Msg {
			if err := be.LeaveRoom(ctx(), name); err != nil {
				return toastMsg{level: "error", text: err.Error()}
			}
			return openConvMsg{conv: storage.GeneralRoomID}
		}
	}
	kind, key, _ := storage.ParseConversationID(m.current)
	switch kind {
	case storage.KindRoom:
		return func() tea.Msg {
			if err := be.LeaveRoom(ctx(), key); err != nil {
				return toastMsg{level: "error", text: err.Error()}
			}
			return openConvMsg{conv: storage.GeneralRoomID}
		}
	case storage.KindGroup:
		return cmdGroup(m, []string{"leave"}, "leave")
	}
	return toastCmd("warn", "Private conversations cannot be left. Use /unpair to revoke trust.")
}

func cmdMsg(m *Model, args []string, rest string) tea.Cmd {
	if len(args) == 0 {
		return needArgs("/msg <user> [text]")
	}
	text := restAfter(rest, 1)
	return m.withPeer(args[0], nil, func(p node.PeerInfo) tea.Cmd {
		if !p.Trusted() {
			return tea.Batch(toastCmd("warn", "%s is not paired yet – verify the code to pair first.", p.DisplayName), openDialog(newPairDialog(m, p.ID)))
		}
		be := m.be
		return func() tea.Msg {
			conv, err := be.OpenDirect(ctx(), p.ID)
			if err != nil {
				return openConvMsg{err: err}
			}
			if strings.TrimSpace(text) != "" {
				if _, err := be.SendText(ctx(), conv, text); err != nil {
					return toastMsg{level: "error", text: err.Error()}
				}
			}
			return openConvMsg{conv: conv}
		}
	})
}

func cmdPair(m *Model, args []string, _ string) tea.Cmd {
	if len(args) == 0 {
		return needArgs("/pair <user>")
	}
	return m.withPeer(args[0], nil, func(p node.PeerInfo) tea.Cmd {
		if p.Trusted() {
			return toastCmd("info", "You are already paired with %s.", p.DisplayName)
		}
		if p.IncomingPairing {
			return openDialog(newPairRequestDialog(m, p.ID, ""))
		}
		return openDialog(newPairDialog(m, p.ID))
	})
}

func cmdUnpair(m *Model, args []string, _ string) tea.Cmd {
	if len(args) == 0 {
		if id, ok := m.currentPeer(); ok {
			args = []string{string(id)}
		} else {
			return needArgs("/unpair <user>")
		}
	}
	return m.withPeer(args[0], func(p node.PeerInfo) bool { return p.Trusted() }, func(p node.PeerInfo) tea.Cmd {
		return openDialog(&confirmDialog{
			title: "Revoke trust in " + textsafe.Line(p.DisplayName, 32) + "?",
			lines: []string{"Messages from this identity will be rejected and undelivered messages to it are marked failed.",
				"Your conversation history is kept. You can pair again later."},
			yes: "Revoke",
			onYes: func(m *Model) tea.Cmd {
				be := m.be
				return func() tea.Msg {
					if err := be.Revoke(ctx(), p.ID); err != nil {
						return toastMsg{level: "error", text: err.Error()}
					}
					return toastMsg{level: "success", text: "Trust in " + p.DisplayName + " revoked."}
				}
			},
		})
	})
}

func cmdGroup(m *Model, args []string, rest string) tea.Cmd {
	usage := "/group create <name> [user …] | invite <user> | remove <user> | members | leave"
	if len(args) == 0 {
		return needArgs(usage)
	}
	be := m.be
	gid, inGroup := m.currentGroupID()
	switch strings.ToLower(args[0]) {
	case "create":
		if len(args) < 2 {
			return needArgs("/group create <name> [user …]")
		}
		name := args[1]
		var members []identity.PeerID
		for _, ref := range args[2:] {
			matches := m.be.ResolvePeer(strings.ReplaceAll(ref, "_", " "))
			var trusted []node.PeerInfo
			for _, p := range matches {
				if p.Trusted() {
					trusted = append(trusted, p)
				}
			}
			if len(trusted) != 1 {
				return toastCmd("warn", "%q must match exactly one paired user (found %d).", textsafe.Line(ref, 32), len(trusted))
			}
			members = append(members, trusted[0].ID)
		}
		return func() tea.Msg {
			conv, err := be.CreateGroup(ctx(), name, members)
			return openConvMsg{conv: conv, err: err}
		}
	case "invite", "add", "remove", "kick":
		if !inGroup {
			return toastCmd("warn", "Open the group first, then use /group %s <user>.", args[0])
		}
		if len(args) < 2 {
			return needArgs("/group " + args[0] + " <user>")
		}
		remove := args[0] == "remove" || args[0] == "kick"
		return m.withPeer(args[1], func(p node.PeerInfo) bool { return remove || p.Trusted() }, func(p node.PeerInfo) tea.Cmd {
			return func() tea.Msg {
				var err error
				if remove {
					err = be.RemoveFromGroup(ctx(), gid, p.ID)
				} else {
					err = be.InviteToGroup(ctx(), gid, p.ID)
				}
				if err != nil {
					return toastMsg{level: "error", text: err.Error()}
				}
				return toastMsg{level: "success", text: "Group updated."}
			}
		})
	case "members":
		if !inGroup {
			return toastCmd("warn", "Open a group first.")
		}
		return func() tea.Msg {
			g, err := be.Group(ctx(), gid)
			if err != nil {
				return toastMsg{level: "error", text: err.Error()}
			}
			var lines []string
			lines = append(lines, fmt.Sprintf("State: %s · version %d", g.State, g.Version), "")
			for _, mem := range g.Members {
				role := ""
				if mem.PeerID == g.OwnerID {
					role = " (owner)"
				}
				status := "not paired"
				if p, ok := be.Peer(mem.PeerID); ok {
					switch {
					case mem.PeerID == be.Self().ID:
						status = "you"
					case p.Online():
						status = "● online"
					case p.Trusted():
						status = "○ offline"
					}
				} else if mem.PeerID == be.Self().ID {
					status = "you"
				}
				lines = append(lines, fmt.Sprintf("%-24s %-12s #%s%s", textsafe.Line(mem.DisplayName, 24), status, mem.PeerID.Short(), role))
			}
			return dialogMsg{&infoDialog{title: "◆ " + textsafe.Line(g.Name, 40) + " – members", lines: lines}}
		}
	case "leave":
		if !inGroup {
			return toastCmd("warn", "Open the group you want to leave first.")
		}
		return openDialog(&confirmDialog{
			title: "Leave this group?",
			lines: []string{"If you own the group, leaving disbands it for everyone."},
			yes:   "Leave",
			onYes: func(m *Model) tea.Cmd {
				return func() tea.Msg {
					if err := be.LeaveGroup(ctx(), gid); err != nil {
						return toastMsg{level: "error", text: err.Error()}
					}
					return toastMsg{level: "info", text: "You left the group."}
				}
			},
		})
	}
	return needArgs(usage)
}

func cmdFile(m *Model, args []string, rest string) tea.Cmd {
	if len(args) > 0 && args[0] == "send" {
		args = args[1:]
	}
	if len(args) < 2 {
		if len(args) == 1 {
			if id, ok := m.currentPeer(); ok {
				args = []string{string(id), args[0]}
			}
		}
		if len(args) < 2 {
			return needArgs("/file send <user> <path>   (quote paths with spaces)")
		}
	}
	path := strings.Join(args[1:], " ")
	return m.withPeer(args[0], func(p node.PeerInfo) bool { return p.Trusted() }, func(p node.PeerInfo) tea.Cmd {
		be := m.be
		return func() tea.Msg {
			if _, err := be.SendFile(ctx(), p.ID, path); err != nil {
				if errors.Is(err, node.ErrNotConnected) {
					return toastMsg{level: "warn", text: p.DisplayName + " is offline; files can only be sent while both of you are online."}
				}
				return toastMsg{level: "error", text: err.Error()}
			}
			return toastMsg{level: "info", text: "Offered " + filepath.Base(path) + " to " + p.DisplayName + " – waiting for them to accept."}
		}
	})
}

func cmdTransfers(m *Model, _ []string, _ string) tea.Cmd {
	var items []listItem
	for _, t := range m.be.Transfers() {
		dir := "← from " + t.PeerName
		if t.Outgoing {
			dir = "→ to " + t.PeerName
		}
		pct := ""
		if t.Size > 0 {
			pct = fmt.Sprintf(" %d%%", t.Transferred*100/t.Size)
		}
		desc := fmt.Sprintf("%s · %s · %s%s", dir, node.HumanSize(t.Size), t.State, pct)
		if t.Error != "" {
			desc += " · " + t.Error
		}
		items = append(items, listItem{title: textsafe.Line(t.Name, 50), desc: textsafe.Line(desc, 120), value: t})
	}
	if len(items) == 0 {
		return toastCmd("info", "No file transfers in this session.")
	}
	return openDialog(&listDialog{title: "File transfers (Enter cancels an active transfer)", items: items, input: newFilterInput(),
		onSelect: func(m *Model, it listItem) tea.Cmd {
			t := it.value.(node.TransferInfo)
			if t.Done() {
				if t.Path != "" {
					return toastCmd("info", "Saved at %s", t.Path)
				}
				return nil
			}
			if err := m.be.CancelTransfer(t.ID); err != nil {
				return errCmd(err)
			}
			return toastCmd("info", "Transfer cancelled.")
		}})
}

func cmdWhoami(m *Model, _ []string, _ string) tea.Cmd {
	s := m.be.Self()
	lines := []string{
		"Display name:  " + textsafe.Line(s.DisplayName, 32),
		"Device:        " + textsafe.Line(s.DeviceName, 64),
		"Peer ID:       " + string(s.ID),
		"Fingerprint:",
	}
	fp := strings.Fields(s.Fingerprint)
	for i := 0; i < len(fp); i += 8 {
		end := min(i+8, len(fp))
		lines = append(lines, "  "+strings.Join(fp[i:end], " "))
	}
	lines = append(lines, "", "Listening on:  "+s.ListenAddr, "Mode:          "+s.Mode,
		"", "Others verify you by comparing the six-digit pairing code shown during pairing.")
	return openDialog(&infoDialog{title: "Who am I", lines: lines})
}

func cmdStatus(m *Model, _ []string, _ string) tea.Cmd {
	st := m.be.NetworkStatus()
	paired, online, nearby := 0, 0, 0
	for _, p := range m.be.Peers() {
		switch {
		case p.Online():
			online++
			paired++
		case p.Trusted():
			paired++
		case p.Connected || p.Discovered:
			nearby++
		}
	}
	lines := []string{
		fmt.Sprintf("Listening:        %s", st.ListenAddr),
		fmt.Sprintf("Paired peers:     %d (%d online)", paired, online),
		fmt.Sprintf("Unpaired nearby:  %d", nearby),
		fmt.Sprintf("Open sessions:    %d", st.Sessions),
	}
	if st.InterfaceError != "" {
		lines = append(lines, "", "Network problem:  "+st.InterfaceError)
	}
	return openDialog(&infoDialog{title: "Status", lines: lines})
}

func cmdNetwork(m *Model, _ []string, _ string) tea.Cmd {
	st := m.be.NetworkStatus()
	lines := []string{"Listener: " + st.ListenAddr, "", "Interfaces used for discovery:"}
	if len(st.Interfaces) == 0 {
		lines = append(lines, "  none – "+st.InterfaceError)
	}
	for _, it := range st.Interfaces {
		var addrs []string
		for _, a := range it.Addrs {
			addrs = append(addrs, a.String())
		}
		lines = append(lines, "  "+it.Name+"  "+strings.Join(addrs, ", "))
	}
	lines = append(lines, "", "Discovery:")
	for _, d := range st.Discovery {
		state := "inactive"
		switch {
		case d.Active && d.Announcing:
			state = "announcing and browsing"
		case d.Active:
			state = "browsing"
		}
		line := fmt.Sprintf("  %-8s %s, %d seen in last round", d.Name, state, d.Seen)
		if d.LastError != "" {
			line += " – last error: " + d.LastError
		}
		lines = append(lines, line)
	}
	lines = append(lines, "", fmt.Sprintf("Sessions: %d (%d paired)", st.Sessions, st.TrustedOnline),
		"", "Discovery finds peers; it does not prove identity or reachability.",
		"mDNS does not cross routers/VLANs – use managed discovery or static_peers there.")
	return openDialog(&infoDialog{title: "Network", lines: lines})
}

func cmdPing(m *Model, args []string, _ string) tea.Cmd {
	ping := func(p node.PeerInfo) tea.Cmd {
		be := m.be
		return func() tea.Msg {
			rtt, err := be.Ping(ctx(), p.ID)
			if err != nil {
				return toastMsg{level: "warn", text: "Ping " + p.DisplayName + ": " + err.Error()}
			}
			return toastMsg{level: "success", text: fmt.Sprintf("Pong from %s: %.1f ms (application round trip over TLS)", p.DisplayName, float64(rtt.Microseconds())/1000)}
		}
	}
	if len(args) == 0 {
		id, ok := m.currentPeer()
		if !ok {
			return needArgs("/ping <user>")
		}
		p, _ := m.be.Peer(id)
		return ping(p)
	}
	return m.withPeer(args[0], func(p node.PeerInfo) bool { return p.Connected }, ping)
}

func cmdHistory(m *Model, _ []string, _ string) tea.Cmd {
	delete(m.clearedAt, m.current)
	m.renderMessages()
	return openDialog(newConversationPicker(m))
}

func cmdClear(m *Model, _ []string, _ string) tea.Cmd {
	if len(m.msgs) > 0 {
		m.clearedAt[m.current] = m.msgs[len(m.msgs)-1].Seq
	} else {
		m.clearedAt[m.current] = 0
	}
	m.renderMessages()
	return toastCmd("info", "View cleared. Stored history is kept (/history shows it again).")
}

func cmdRetry(m *Model, _ []string, _ string) tea.Cmd {
	be, conv := m.be, m.current
	return func() tea.Msg {
		n, err := be.RetryFailed(ctx(), conv)
		if err != nil {
			return toastMsg{level: "error", text: err.Error()}
		}
		return toastMsg{level: "info", text: fmt.Sprintf("Re-queued %d failed delivery(ies).", n)}
	}
}

func cmdExport(m *Model, args []string, _ string) tea.Cmd {
	format := "text"
	path := ""
	for _, a := range args {
		switch strings.ToLower(a) {
		case "json", "text", "txt":
			format = map[string]string{"txt": "text"}[strings.ToLower(a)]
			if format == "" {
				format = strings.ToLower(a)
			}
		default:
			path = a
		}
	}
	if path == "" {
		ext := map[string]string{"json": "json", "text": "txt"}[format]
		name := strings.NewReplacer(":", "-", "/", "-").Replace(m.current)
		dirs, _ := platform.ResolveDirs("")
		path = filepath.Join(m.cfg.DownloadDir(dirs), fmt.Sprintf("lanchat-%s-%s.%s", name, time.Now().Format("20060102-150405"), ext))
	}
	be, conv := m.be, m.current
	return func() tea.Msg {
		n, err := be.ExportConversation(ctx(), conv, path, format)
		if err != nil {
			return toastMsg{level: "error", text: "Export failed: " + err.Error()}
		}
		return toastMsg{level: "success", text: fmt.Sprintf("Exported %d message(s) to %s", n, path)}
	}
}

func cmdDeleteHistory(m *Model, _ []string, _ string) tea.Cmd {
	conv := m.current
	return openDialog(&confirmDialog{
		title: "Delete the stored history of " + m.convTitlePlain() + "?",
		lines: []string{"This permanently deletes the messages stored on this computer for this conversation,",
			"including undelivered outgoing messages. Other people's copies are not affected."},
		yes: "Delete",
		onYes: func(m *Model) tea.Cmd {
			be := m.be
			return func() tea.Msg {
				n, err := be.ClearHistory(ctx(), conv)
				if err != nil {
					return toastMsg{level: "error", text: err.Error()}
				}
				return toastMsg{level: "success", text: fmt.Sprintf("Deleted %d message(s).", n)}
			}
		},
	})
}

func (m *Model) applyConfig(cfg config.Config, msg string) tea.Cmd {
	m.cfg = cfg
	m.theme = ThemeByName(cfg.UI.Theme)
	m.st = newStyles(m.theme)
	m.renderMessages()
	save := m.save
	return func() tea.Msg {
		if save != nil {
			if err := save(cfg); err != nil {
				return toastMsg{level: "error", text: "Could not save settings: " + err.Error()}
			}
		}
		return toastMsg{level: "success", text: msg}
	}
}

func cmdTheme(m *Model, args []string, _ string) tea.Cmd {
	if len(args) == 0 {
		var items []listItem
		for _, t := range config.Themes {
			desc := ""
			if t == m.cfg.UI.Theme {
				desc = "current"
			}
			items = append(items, listItem{title: t, desc: desc, value: t})
		}
		return openDialog(&listDialog{title: "Theme", items: items, input: newFilterInput(),
			onSelect: func(m *Model, it listItem) tea.Cmd { return cmdTheme(m, []string{it.value.(string)}, "") }})
	}
	name := strings.ToLower(args[0])
	valid := false
	for _, t := range config.Themes {
		valid = valid || t == name
	}
	if !valid {
		return toastCmd("warn", "Unknown theme %q. Choose: %s", textsafe.Line(name, 20), strings.Join(config.Themes, ", "))
	}
	cfg := m.cfg
	cfg.UI.Theme = name
	return m.applyConfig(cfg, "Theme set to "+name+".")
}

func cmdBell(m *Model, args []string, _ string) tea.Cmd {
	cfg := m.cfg
	on := !cfg.Notifications.Bell
	if len(args) > 0 {
		on = args[0] == "on" || args[0] == "true"
	}
	cfg.Notifications.Bell = on
	return m.applyConfig(cfg, map[bool]string{true: "Terminal bell enabled.", false: "Terminal bell disabled."}[on])
}

func cmdSettings(m *Model, _ []string, _ string) tea.Cmd {
	c := m.cfg
	dirs, _ := platform.ResolveDirs("")
	lines := []string{
		"Display name:       " + textsafe.Line(c.User.DisplayName, 32),
		"Device name:        " + textsafe.Line(c.User.DeviceName, 64),
		fmt.Sprintf("Network:            mode=%s interface=%s port=%d IPv4=%v IPv6=%v", c.Network.Mode, c.Network.Interface, c.Network.Port, c.Network.EnableIPv4, c.Network.EnableIPv6),
		fmt.Sprintf("Discovery:          mDNS=%v static=%d managed=%q", c.Discovery.MDNSEnabled, len(c.Discovery.StaticPeers), c.Discovery.ManagedServer),
		fmt.Sprintf("History:            save=%v offline queue=%v (%dh)", c.Chat.SaveHistory, c.Chat.QueueOfflineMessages, c.Chat.OfflineQueueTTLHours),
		"Downloads:          " + c.DownloadDir(dirs),
		fmt.Sprintf("Max file size:      %d MB", c.Transfer.MaxFileSizeMB),
		fmt.Sprintf("Notifications:      on=%v bell=%v peer events=%v", c.Notifications.Enabled, c.Notifications.Bell, c.Notifications.PeerEvents),
		"Theme:              " + c.UI.Theme + " (change with /theme)",
		"",
		"Config file: " + dirs.ConfigFile(),
		"Edit with `lanchat config edit` or rerun the wizard with `lanchat --setup`.",
		"Network changes take effect after restarting LANChat.",
	}
	return openDialog(&infoDialog{title: "Settings", lines: lines})
}
