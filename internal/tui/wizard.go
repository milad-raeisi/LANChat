package tui

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/milad-raeisi/LANChat/internal/config"
	"github.com/milad-raeisi/LANChat/internal/network/discovery"
	"github.com/milad-raeisi/LANChat/internal/network/netif"
	"github.com/milad-raeisi/LANChat/internal/node"
	"github.com/milad-raeisi/LANChat/internal/platform"
	"github.com/milad-raeisi/LANChat/internal/security/identity"
	"github.com/milad-raeisi/LANChat/internal/textsafe"
)

type wizardStep int

const (
	wsName wizardStep = iota
	wsDevice
	wsMode
	wsInterface
	wsPort
	wsManaged
	wsChecks
)

type checkResult struct {
	name, status, detail string // status: ok, warn, fail
}

type checksMsg struct {
	results     []checkResult
	fingerprint string
	peerID      string
	created     bool
}

type wizard struct {
	dirs  platform.Dirs
	cfg   config.Config
	st    styles
	theme Theme
	step  wizardStep

	name, device, port, managed, pin textinput.Model
	managedField                     int
	modeSel                          int
	ifaces                           []netif.Interface
	ifaceSel                         int
	recommended                      string

	checks   []checkResult
	checking bool
	fp       string
	peerID   string
	created  bool

	errText       string
	width, height int
	completed     bool
	saveErr       error
}

func newInput(placeholder, value string, limit int) textinput.Model {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.Placeholder = placeholder
	ti.CharLimit = limit
	ti.SetValue(value)
	ti.CursorEnd()
	return ti
}

func newWizard(dirs platform.Dirs, existing *config.Config) *wizard {
	cfg := config.Default()
	if existing != nil {
		cfg = *existing
	}
	host, _ := os.Hostname()
	host = textsafe.Line(strings.TrimSuffix(host, ".local"), config.MaxDeviceNameRunes)
	device := cfg.User.DeviceName
	if device == "" {
		device = host
	}
	theme := ThemeByName(cfg.UI.Theme)
	w := &wizard{
		dirs: dirs, cfg: cfg, theme: theme, st: newStyles(theme),
		name:    newInput("your name, as others will see it", cfg.User.DisplayName, config.MaxDisplayNameRunes),
		device:  newInput("this computer's name", device, config.MaxDeviceNameRunes),
		port:    newInput("47777", strconv.Itoa(cfg.Network.Port), 5),
		managed: newInput("discovery.example.lan:47780 (optional)", cfg.Discovery.ManagedServer, 255),
		pin:     newInput("64 hex digits from `lanchat-discovery fingerprint`", cfg.Discovery.ManagedServerFingerprint, 100),
		width:   80, height: 24,
	}
	if cfg.Network.Interface != "auto" || cfg.Network.Mode == config.ModeManaged {
		w.modeSel = 1
	}
	w.name.Focus()
	if list, err := netif.List(); err == nil {
		w.ifaces = list
		if r := netif.Recommend(list); r != nil {
			w.recommended = r.Name
		}
		for i, it := range list {
			if it.Name == cfg.Network.Interface {
				w.ifaceSel = i + 1
			}
		}
	}
	return w
}

func (w *wizard) Init() tea.Cmd { return textinput.Blink }

func (w *wizard) focusStep() tea.Cmd {
	for _, ti := range []*textinput.Model{&w.name, &w.device, &w.port, &w.managed, &w.pin} {
		ti.Blur()
	}
	switch w.step {
	case wsName:
		return w.name.Focus()
	case wsDevice:
		return w.device.Focus()
	case wsPort:
		return w.port.Focus()
	case wsManaged:
		if w.managedField == 1 {
			return w.pin.Focus()
		}
		return w.managed.Focus()
	}
	return nil
}

func (w *wizard) runChecks() tea.Cmd {
	w.checking = true
	w.checks = nil
	dirs, cfg := w.dirs, w.cfg
	return func() tea.Msg {
		var res []checkResult
		out := checksMsg{}
		if err := dirs.Ensure(); err != nil {
			res = append(res, checkResult{"Data directories", "fail", err.Error()})
			return checksMsg{results: res}
		}
		id, created, err := identity.LoadOrCreate(dirs.IdentityFile())
		if err != nil {
			res = append(res, checkResult{"Identity", "fail", err.Error()})
		} else {
			detail := "existing identity loaded (not regenerated)"
			if created {
				detail = "new Ed25519 identity generated and stored with owner-only permissions"
			}
			res = append(res, checkResult{"Identity", "ok", detail})
			out.fingerprint = identity.FormatFingerprint(id.Fingerprint())
			out.peerID = string(id.ID())
			out.created = created
		}
		list, err := netif.List()
		if err != nil {
			res = append(res, checkResult{"Network interfaces", "fail", err.Error()})
		} else if sel, err := netif.Select(list, cfg.Network.Interface); err != nil {
			res = append(res, checkResult{"Network interfaces", "warn", err.Error()})
		} else {
			var names []string
			for _, it := range sel {
				addr := ""
				if v4 := it.IPv4(); len(v4) > 0 {
					addr = " " + v4[0].String()
				}
				names = append(names, it.Name+addr)
			}
			res = append(res, checkResult{"Network interfaces", "ok", strings.Join(names, ", ")})
		}
		network, addr := node.ListenAddress(cfg.Network)
		if ln, err := net.Listen(network, addr); err != nil {
			res = append(res, checkResult{"TCP port " + strconv.Itoa(cfg.Network.Port), "fail",
				"cannot listen: " + err.Error() + " – choose another port (Advanced) or stop the other program"})
		} else {
			_ = ln.Close()
			res = append(res, checkResult{"TCP port " + strconv.Itoa(cfg.Network.Port), "ok", "available"})
		}
		if cfg.Discovery.MDNSEnabled {
			if err := discovery.ProbeMulticast(); err != nil {
				res = append(res, checkResult{"Multicast (mDNS)", "warn", "socket could not be opened: " + err.Error()})
			} else {
				res = append(res, checkResult{"Multicast (mDNS)", "ok", "socket initialised; discovery is confirmed once a peer appears"})
			}
		}
		if cfg.Discovery.ManagedServer != "" {
			res = append(res, checkResult{"Managed discovery", "ok", "will register with " + cfg.Discovery.ManagedServer + " (verified at startup)"})
		}
		res = append(res, checkResult{"Encryption", "ok", "TLS 1.3 with mutual authentication (always on)"})
		out.results = res
		return out
	}
}

func (w *wizard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		w.width, w.height = msg.Width, msg.Height
		return w, nil
	case checksMsg:
		w.checking = false
		w.checks = msg.results
		w.fp, w.peerID, w.created = msg.fingerprint, msg.peerID, msg.created
		return w, nil
	case tea.KeyPressMsg:
		return w.key(msg)
	}
	var cmd tea.Cmd
	switch w.step {
	case wsName:
		w.name, cmd = w.name.Update(msg)
	case wsDevice:
		w.device, cmd = w.device.Update(msg)
	case wsPort:
		w.port, cmd = w.port.Update(msg)
	case wsManaged:
		if w.managedField == 0 {
			w.managed, cmd = w.managed.Update(msg)
		} else {
			w.pin, cmd = w.pin.Update(msg)
		}
	}
	return w, cmd
}

func (w *wizard) back() tea.Cmd {
	w.errText = ""
	switch w.step {
	case wsDevice:
		w.step = wsName
	case wsMode:
		w.step = wsDevice
	case wsInterface:
		w.step = wsMode
	case wsPort:
		w.step = wsInterface
	case wsManaged:
		w.step = wsPort
	case wsChecks:
		if w.modeSel == 1 {
			w.step = wsManaged
		} else {
			w.step = wsMode
		}
	}
	return w.focusStep()
}

func (w *wizard) key(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return w, tea.Quit
	case "esc":
		if w.step == wsName {
			return w, tea.Quit
		}
		return w, w.back()
	}
	w.errText = ""
	var cmd tea.Cmd
	switch w.step {
	case wsName:
		if msg.String() == "enter" {
			v := strings.TrimSpace(w.name.Value())
			if err := config.ValidateDisplayName(v); err != nil {
				w.errText = "Display name " + err.Error()
				return w, nil
			}
			w.cfg.User.DisplayName = v
			w.step = wsDevice
			return w, w.focusStep()
		}
		w.name, cmd = w.name.Update(msg)
	case wsDevice:
		if msg.String() == "enter" {
			v := strings.TrimSpace(w.device.Value())
			if err := config.ValidateDeviceName(v); err != nil {
				w.errText = "Device name " + err.Error()
				return w, nil
			}
			w.cfg.User.DeviceName = v
			w.step = wsMode
			return w, w.focusStep()
		}
		w.device, cmd = w.device.Update(msg)
	case wsMode:
		switch msg.String() {
		case "up", "k", "down", "j", "tab", "space":
			w.modeSel = 1 - w.modeSel
		case "enter":
			if w.modeSel == 0 {
				w.cfg.Network.Mode = config.ModeAuto
				w.cfg.Network.Interface = "auto"
				w.step = wsChecks
				return w, w.runChecks()
			}
			w.step = wsInterface
		}
	case wsInterface:
		switch msg.String() {
		case "up", "k":
			w.ifaceSel = max(0, w.ifaceSel-1)
		case "down", "j":
			w.ifaceSel = min(len(w.ifaces), w.ifaceSel+1)
		case "enter":
			if w.ifaceSel == 0 {
				w.cfg.Network.Interface = "auto"
			} else {
				w.cfg.Network.Interface = w.ifaces[w.ifaceSel-1].Name
			}
			w.step = wsPort
			return w, w.focusStep()
		}
	case wsPort:
		if msg.String() == "enter" {
			p, err := strconv.Atoi(strings.TrimSpace(w.port.Value()))
			if err != nil || p < 1024 || p > 65535 {
				w.errText = "Port must be a number between 1024 and 65535."
				return w, nil
			}
			w.cfg.Network.Port = p
			w.step = wsManaged
			return w, w.focusStep()
		}
		w.port, cmd = w.port.Update(msg)
	case wsManaged:
		switch msg.String() {
		case "tab", "down", "up", "shift+tab":
			w.managedField = 1 - w.managedField
			return w, w.focusStep()
		case "enter":
			srv := strings.TrimSpace(w.managed.Value())
			pin := identity.NormalizeFingerprint(w.pin.Value())
			w.cfg.Discovery.ManagedServer = srv
			w.cfg.Discovery.ManagedServerFingerprint = ""
			w.cfg.Network.Mode = config.ModeAuto
			if srv != "" {
				w.cfg.Discovery.ManagedServerFingerprint = pin
				w.cfg.Network.Mode = config.ModeManaged
			}
			if err := w.cfg.Validate(); err != nil {
				w.errText = strings.TrimPrefix(err.Error(), "invalid configuration: ")
				return w, nil
			}
			w.step = wsChecks
			return w, w.runChecks()
		}
		if w.managedField == 0 {
			w.managed, cmd = w.managed.Update(msg)
		} else {
			w.pin, cmd = w.pin.Update(msg)
		}
	case wsChecks:
		if w.checking {
			return w, nil
		}
		switch msg.String() {
		case "r":
			return w, w.runChecks()
		case "enter":
			for _, c := range w.checks {
				if c.status == "fail" {
					w.errText = "Fix the failed check first (Esc to go back, R to re-run the checks)."
					return w, nil
				}
			}
			if err := w.cfg.Validate(); err != nil {
				w.errText = err.Error()
				return w, nil
			}
			if err := config.Save(w.dirs.ConfigFile(), w.cfg); err != nil {
				w.saveErr = err
				w.errText = "Could not save the configuration: " + err.Error()
				return w, nil
			}
			w.completed = true
			return w, tea.Quit
		}
	}
	return w, cmd
}

func (w *wizard) View() tea.View {
	st := w.st
	width := min(max(40, w.width-4), 78)
	banner := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(w.theme.Accent).
		Width(width).Align(lipgloss.Center).Padding(1, 0).
		Render(st.accent.Render("LANChat") + "\n" + st.text.Render("Local Network Messenger") + "\n\n" + st.muted.Render("Private. Local. Simple."))
	var b []string
	b = append(b, banner, "")
	stepTitle := func(n int, t string) string {
		return st.accent.Render(fmt.Sprintf("Step %d of 4 · %s", n, t))
	}
	switch w.step {
	case wsName:
		b = append(b, "Welcome to LANChat! Let's set up local messaging.", "", stepTitle(1, "Display name"),
			st.muted.Render("Shown to people on your network. Names are not unique – identities are verified by key."), "", w.name.View())
	case wsDevice:
		b = append(b, stepTitle(2, "Device name"), st.muted.Render("Helps people tell your computers apart."), "", w.device.View())
	case wsMode:
		opts := []string{"Automatic network discovery (recommended)", "Advanced network configuration"}
		b = append(b, stepTitle(3, "Network configuration"), "")
		for i, o := range opts {
			mark := "○ "
			if i == w.modeSel {
				mark = st.accent.Render("● ")
				o = st.accent.Render(o)
			}
			b = append(b, "  "+mark+o)
		}
		b = append(b, "", st.muted.Render("Automatic uses mDNS on your LAN interfaces and port 47777. No IP addresses to enter."))
	case wsInterface:
		b = append(b, stepTitle(3, "Network interface"), st.muted.Render("Interfaces used to announce yourself and discover others."), "")
		label := "auto – every suitable LAN interface"
		if w.recommended != "" {
			label += " (recommended: " + w.recommended + ")"
		}
		b = append(b, w.ifaceLine(0, label))
		for i, it := range w.ifaces {
			b = append(b, w.ifaceLine(i+1, ansi.Truncate(it.Summary(), width-6, "…")))
		}
	case wsPort:
		b = append(b, stepTitle(3, "Listening port"), st.muted.Render("TCP port for encrypted peer connections (default 47777)."), "", w.port.View())
	case wsManaged:
		b = append(b, stepTitle(3, "Managed discovery (optional)"),
			st.muted.Render("Only for networks where multicast is blocked (VLANs, segmented offices)."),
			st.muted.Render("Leave empty to use local discovery only. Chat never goes through the server."), "",
			"Server  "+w.managed.View(), "Pin     "+w.pin.View(), st.muted.Render("Tab switches fields."))
	case wsChecks:
		b = append(b, stepTitle(4, "Checking your setup"), "")
		if w.checking {
			b = append(b, st.muted.Render("Running checks…"))
		}
		for _, c := range w.checks {
			tag := st.success.Render("[ OK ]")
			switch c.status {
			case "warn":
				tag = st.warn.Render("[WARN]")
			case "fail":
				tag = st.err.Render("[FAIL]")
			}
			b = append(b, ansi.Truncate(tag+" "+c.name+": "+st.muted.Render(c.detail), width, "…"))
		}
		if w.fp != "" {
			b = append(b, "", "Your identity fingerprint:")
			for _, l := range fingerprintLines(w.fp) {
				b = append(b, st.accent.Render(l))
			}
		}
		if !w.checking {
			b = append(b, "", st.muted.Render("Firewall notes:"))
			for _, l := range platform.FirewallAdvice(w.cfg.Network.Port) {
				b = append(b, st.muted.Render("  "+l))
			}
		}
	}
	if w.errText != "" {
		b = append(b, "", st.err.Render(w.errText))
	}
	help := "Enter continue · Esc back · Ctrl+C cancel"
	if w.step == wsChecks {
		help = "Enter save and start · R re-run checks · Esc back · Ctrl+C cancel"
	}
	if w.step == wsMode || w.step == wsInterface {
		help = "↑↓ choose · " + help
	}
	b = append(b, "", st.muted.Render(help))
	content := lipgloss.NewStyle().Padding(1, 2).Render(strings.Join(b, "\n"))
	v := tea.NewView(content)
	v.AltScreen = true
	v.WindowTitle = "LANChat setup"
	return v
}

func (w *wizard) ifaceLine(i int, label string) string {
	if i == w.ifaceSel {
		return "  " + w.st.itemSel.Render("● "+label)
	}
	return "  ○ " + label
}

// RunWizard runs the interactive setup. It returns the saved configuration
// and whether the user completed the wizard.
func RunWizard(dirs platform.Dirs, existing *config.Config) (config.Config, bool, error) {
	w := newWizard(dirs, existing)
	final, err := tea.NewProgram(w).Run()
	if err != nil {
		return config.Config{}, false, err
	}
	fw := final.(*wizard)
	return fw.cfg, fw.completed, fw.saveErr
}
