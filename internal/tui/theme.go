package tui

import (
	"hash/fnv"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// Theme is a colour palette. Colours are downsampled automatically on
// terminals with limited colour support; the monochrome theme uses only
// text attributes. Essential state is never conveyed by colour alone: every
// status also has a symbol or a word.
type Theme struct {
	Name     string
	Mono     bool
	Minimal  bool
	Accent   color.Color
	Muted    color.Color
	Text     color.Color
	Border   color.Color
	Error    color.Color
	Warn     color.Color
	Success  color.Color
	Unread   color.Color
	SelBg    color.Color
	SelFg    color.Color
	HeaderBg color.Color
	HeaderFg color.Color
	KeyBg    color.Color
	Users    []color.Color
	// Gradient colours the logo and the welcome title; empty for themes
	// meant for limited terminals.
	Gradient []color.Color
}

var none = lipgloss.NoColor{}

// ThemeByName returns a theme, defaulting to dark.
func ThemeByName(name string) Theme {
	switch name {
	case "light":
		return Theme{Name: "light",
			Accent: lipgloss.Color("#2E59A8"), Muted: lipgloss.Color("#6B7280"), Text: lipgloss.Color("#1F2937"),
			Border: lipgloss.Color("#C7CDD6"), Error: lipgloss.Color("#B91C1C"), Warn: lipgloss.Color("#B45309"),
			Success: lipgloss.Color("#15803D"), Unread: lipgloss.Color("#C2410C"), SelBg: lipgloss.Color("#DBEAFE"),
			SelFg: lipgloss.Color("#111827"), HeaderBg: lipgloss.Color("#E5E7EB"), HeaderFg: lipgloss.Color("#111827"),
			KeyBg: lipgloss.Color("#D1D5DB"),
			Users: []color.Color{lipgloss.Color("#1D4ED8"), lipgloss.Color("#047857"), lipgloss.Color("#9D174D"),
				lipgloss.Color("#6D28D9"), lipgloss.Color("#B45309"), lipgloss.Color("#0E7490")},
			Gradient: []color.Color{lipgloss.Color("#2E59A8"), lipgloss.Color("#7C3AED"), lipgloss.Color("#DB2777")},
		}
	case "minimal":
		return Theme{Name: "minimal", Minimal: true,
			Accent: lipgloss.Color("6"), Muted: lipgloss.Color("8"), Text: none, Border: lipgloss.Color("8"),
			Error: lipgloss.Color("1"), Warn: lipgloss.Color("3"), Success: lipgloss.Color("2"), Unread: lipgloss.Color("3"),
			SelBg: none, SelFg: none, HeaderBg: none, HeaderFg: none, KeyBg: none,
			Users: []color.Color{lipgloss.Color("4"), lipgloss.Color("2"), lipgloss.Color("5"), lipgloss.Color("6")},
		}
	case "monochrome":
		return Theme{Name: "monochrome", Mono: true,
			Accent: none, Muted: none, Text: none, Border: none, Error: none, Warn: none, Success: none,
			Unread: none, SelBg: none, SelFg: none, HeaderBg: none, HeaderFg: none, KeyBg: none, Users: []color.Color{none},
		}
	default:
		return Theme{Name: "dark",
			Accent: lipgloss.Color("#7AA2F7"), Muted: lipgloss.Color("#7A82A8"), Text: lipgloss.Color("#C8D0F0"),
			Border: lipgloss.Color("#3B4261"), Error: lipgloss.Color("#F7768E"), Warn: lipgloss.Color("#E0AF68"),
			Success: lipgloss.Color("#9ECE6A"), Unread: lipgloss.Color("#FF9E64"), SelBg: lipgloss.Color("#2E3C64"),
			SelFg: lipgloss.Color("#FFFFFF"), HeaderBg: lipgloss.Color("#1F2335"), HeaderFg: lipgloss.Color("#C8D0F0"),
			KeyBg: lipgloss.Color("#2F3549"),
			Users: []color.Color{lipgloss.Color("#7AA2F7"), lipgloss.Color("#9ECE6A"), lipgloss.Color("#BB9AF7"),
				lipgloss.Color("#7DCFFF"), lipgloss.Color("#E0AF68"), lipgloss.Color("#F7768E"), lipgloss.Color("#73DACA")},
			Gradient: []color.Color{lipgloss.Color("#7AA2F7"), lipgloss.Color("#BB9AF7"), lipgloss.Color("#F7768E")},
		}
	}
}

// styles are the Lip Gloss styles derived from a theme.
type styles struct {
	header, headerAccent, headerMuted   lipgloss.Style
	section, item, itemSel, itemMuted   lipgloss.Style
	unread, online, offline, warn, err  lipgloss.Style
	success, muted, accent, text        lipgloss.Style
	title, subtitle                     lipgloss.Style
	timestamp, body, system, dateSep    lipgloss.Style
	separator                           lipgloss.Style
	footer, footerKey                   lipgloss.Style
	dialog, dialogTitle, button, btnSel lipgloss.Style
	code                                lipgloss.Style
	panelBorder, panelFocus, panelTitle lipgloss.Style
	badge, keycap, pillOK, pillWarn     lipgloss.Style
	dateLabel, card                     lipgloss.Style
	theme                               Theme
}

func newStyles(t Theme) styles {
	s := styles{theme: t}
	base := lipgloss.NewStyle()
	fg := func(c color.Color) lipgloss.Style { return base.Foreground(c) }

	s.text = fg(t.Text)
	s.muted = fg(t.Muted)
	s.accent = fg(t.Accent).Bold(true)
	s.unread = fg(t.Unread).Bold(true)
	s.online = fg(t.Success)
	s.offline = fg(t.Muted)
	s.warn = fg(t.Warn).Bold(true)
	s.err = fg(t.Error).Bold(true)
	s.success = fg(t.Success)

	s.header = base.Background(t.HeaderBg).Foreground(t.HeaderFg)
	s.headerAccent = s.header.Foreground(t.Accent).Bold(true)
	s.headerMuted = s.header.Foreground(t.Muted)
	if t.Mono {
		s.header = base.Reverse(true)
		s.headerAccent = base.Reverse(true).Bold(true)
		s.headerMuted = base.Reverse(true)
	}

	s.section = fg(t.Muted).Bold(true)
	s.item = s.text
	s.itemSel = base.Background(t.SelBg).Foreground(t.SelFg).Bold(true)
	if t.Mono || t.Minimal {
		s.itemSel = base.Reverse(true).Bold(true)
	}
	s.itemMuted = s.muted

	s.title = fg(t.Accent).Bold(true)
	s.subtitle = s.muted
	s.timestamp = s.muted
	s.body = s.text
	s.system = fg(t.Muted).Italic(true)
	s.dateSep = s.muted
	s.separator = fg(t.Border)
	s.footer = s.muted
	s.footerKey = fg(t.Accent).Bold(true)

	border := lipgloss.RoundedBorder()
	if t.Mono {
		border = lipgloss.NormalBorder()
	}
	s.dialog = base.Border(border).BorderForeground(t.Accent).Padding(1, 2)
	s.dialogTitle = fg(t.Accent).Bold(true)
	s.button = base.Padding(0, 1).Foreground(t.Text)
	s.btnSel = base.Padding(0, 1).Background(t.Accent).Foreground(lipgloss.Color("#000000")).Bold(true)
	if t.Mono || t.Minimal {
		s.btnSel = base.Padding(0, 1).Reverse(true).Bold(true)
	}
	s.code = fg(t.Warn).Bold(true)

	s.panelBorder = fg(t.Border)
	s.panelFocus = fg(t.Accent)
	s.panelTitle = fg(t.Accent).Bold(true)
	s.dateLabel = fg(t.Muted).Bold(true)
	s.card = base.Border(border).BorderForeground(t.Border).Padding(1, 3)
	dark := lipgloss.Color("#16161E")
	s.badge = base.Background(t.Unread).Foreground(dark).Bold(true).Padding(0, 1)
	s.keycap = base.Background(t.KeyBg).Foreground(t.Text).Bold(true).Padding(0, 1)
	s.pillOK = base.Background(t.Success).Foreground(dark).Bold(true).Padding(0, 1)
	s.pillWarn = base.Background(t.Warn).Foreground(dark).Bold(true).Padding(0, 1)
	if t.Minimal {
		s.badge = fg(t.Unread).Reverse(true).Bold(true).Padding(0, 1)
		s.keycap = fg(t.Accent).Bold(true)
		s.pillOK = fg(t.Success).Bold(true)
		s.pillWarn = fg(t.Warn).Bold(true)
	}
	if t.Mono {
		s.panelFocus = base.Bold(true)
		s.panelTitle = base.Bold(true)
		s.dateLabel = base.Bold(true)
		s.badge = base.Reverse(true).Bold(true).Padding(0, 1)
		s.keycap = base.Bold(true).Underline(true)
		s.pillOK = base.Bold(true)
		s.pillWarn = base.Bold(true).Underline(true)
	}
	if t.Mono {
		s.code = base.Bold(true).Underline(true)
		s.warn = base.Bold(true)
		s.err = base.Bold(true).Underline(true)
		s.unread = base.Bold(true)
		s.accent = base.Bold(true)
		s.title = base.Bold(true)
	}
	return s
}

// gradient renders text with the theme's gradient, one colour per rune,
// on top of base (which supplies the background and attributes). Themes
// without a gradient fall back to the accent colour.
func (s styles) gradient(text string, base lipgloss.Style) string {
	if s.theme.Mono {
		return base.Bold(true).Render(text)
	}
	runes := []rune(text)
	if len(s.theme.Gradient) < 2 || len(runes) < 2 {
		return base.Foreground(s.theme.Accent).Bold(true).Render(text)
	}
	cols := lipgloss.Blend1D(len(runes), s.theme.Gradient...)
	var b strings.Builder
	for i, r := range runes {
		if r == ' ' {
			b.WriteString(base.Render(" "))
			continue
		}
		b.WriteString(base.Foreground(cols[i]).Bold(true).Render(string(r)))
	}
	return b.String()
}

// userStyle returns a stable per-identity colour for sender names.
func (s styles) userStyle(id string) lipgloss.Style {
	if s.theme.Mono || len(s.theme.Users) == 0 {
		return lipgloss.NewStyle().Bold(true)
	}
	h := fnv.New32a()
	h.Write([]byte(id))
	return lipgloss.NewStyle().Foreground(s.theme.Users[int(h.Sum32())%len(s.theme.Users)]).Bold(true)
}
