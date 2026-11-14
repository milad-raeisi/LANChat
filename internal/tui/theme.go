package tui

import (
	"hash/fnv"
	"image/color"

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
	Users    []color.Color
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
			Users: []color.Color{lipgloss.Color("#1D4ED8"), lipgloss.Color("#047857"), lipgloss.Color("#9D174D"),
				lipgloss.Color("#6D28D9"), lipgloss.Color("#B45309"), lipgloss.Color("#0E7490")},
		}
	case "minimal":
		return Theme{Name: "minimal", Minimal: true,
			Accent: lipgloss.Color("6"), Muted: lipgloss.Color("8"), Text: none, Border: lipgloss.Color("8"),
			Error: lipgloss.Color("1"), Warn: lipgloss.Color("3"), Success: lipgloss.Color("2"), Unread: lipgloss.Color("3"),
			SelBg: none, SelFg: none, HeaderBg: none, HeaderFg: none,
			Users: []color.Color{lipgloss.Color("4"), lipgloss.Color("2"), lipgloss.Color("5"), lipgloss.Color("6")},
		}
	case "monochrome":
		return Theme{Name: "monochrome", Mono: true,
			Accent: none, Muted: none, Text: none, Border: none, Error: none, Warn: none, Success: none,
			Unread: none, SelBg: none, SelFg: none, HeaderBg: none, HeaderFg: none, Users: []color.Color{none},
		}
	default:
		return Theme{Name: "dark",
			Accent: lipgloss.Color("#7AA2F7"), Muted: lipgloss.Color("#7A82A8"), Text: lipgloss.Color("#C8D0F0"),
			Border: lipgloss.Color("#3B4261"), Error: lipgloss.Color("#F7768E"), Warn: lipgloss.Color("#E0AF68"),
			Success: lipgloss.Color("#9ECE6A"), Unread: lipgloss.Color("#FF9E64"), SelBg: lipgloss.Color("#2E3C64"),
			SelFg: lipgloss.Color("#FFFFFF"), HeaderBg: lipgloss.Color("#1F2335"), HeaderFg: lipgloss.Color("#C8D0F0"),
			Users: []color.Color{lipgloss.Color("#7AA2F7"), lipgloss.Color("#9ECE6A"), lipgloss.Color("#BB9AF7"),
				lipgloss.Color("#7DCFFF"), lipgloss.Color("#E0AF68"), lipgloss.Color("#F7768E"), lipgloss.Color("#73DACA")},
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

// userStyle returns a stable per-identity colour for sender names.
func (s styles) userStyle(id string) lipgloss.Style {
	if s.theme.Mono || len(s.theme.Users) == 0 {
		return lipgloss.NewStyle().Bold(true)
	}
	h := fnv.New32a()
	h.Write([]byte(id))
	return lipgloss.NewStyle().Foreground(s.theme.Users[int(h.Sum32())%len(s.theme.Users)]).Bold(true)
}
