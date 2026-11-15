package tui

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

// Test-only helper: renders terminal output (text with SGR colour
// sequences, as produced by the views) as an SVG picture of a terminal
// window. The README screenshots are made with it, so they always show
// the real interface. Box-drawing and block characters are drawn as shapes
// so borders join up regardless of the viewer's font.

const (
	svgFont     = `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "DejaVu Sans Mono", monospace`
	svgFontSize = 14.0
	svgCellW    = 8.4
	svgLineH    = 18.0
	svgPadX     = 18.0
	svgBarH     = 36.0
	svgPadB     = 16.0
	svgMargin   = 24.0
	svgDefFg    = "#c0caf5"
	svgDefBg    = "#1a1b26"
)

var svgBasic = [16]string{
	"#15161e", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#a9b1d6",
	"#414868", "#ff7a93", "#b9f27c", "#ff9e64", "#7da6ff", "#bb9af7", "#0db9d7", "#c0caf5",
}

type svgPen struct {
	fg, bg                           string
	bold, italic, underline, reverse bool
}

type svgCell struct {
	text   string // "" for the right half of a wide character
	wide   bool
	fg, bg string // bg "" is the terminal background
	pen    svgPen
}

func svgColor256(n int) string {
	switch {
	case n < 16:
		return svgBasic[n]
	case n < 232:
		n -= 16
		f := func(v int) int {
			if v == 0 {
				return 0
			}
			return 55 + v*40
		}
		return fmt.Sprintf("#%02x%02x%02x", f(n/36), f(n/6%6), f(n%6))
	default:
		v := 8 + (n-232)*10
		return fmt.Sprintf("#%02x%02x%02x", v, v, v)
	}
}

func (p *svgPen) apply(params string) {
	f := strings.Split(params, ";")
	num := func(i int) int {
		if i >= len(f) {
			return 0
		}
		s, _, _ := strings.Cut(f[i], ":")
		n, _ := strconv.Atoi(s)
		return n
	}
	for i := 0; i < len(f); i++ {
		switch c := num(i); {
		case c == 0:
			*p = svgPen{}
		case c == 1:
			p.bold = true
		case c == 3:
			p.italic = true
		case c == 4:
			p.underline = true
		case c == 7:
			p.reverse = true
		case c == 22:
			p.bold = false
		case c == 23:
			p.italic = false
		case c == 24:
			p.underline = false
		case c == 27:
			p.reverse = false
		case c >= 30 && c <= 37:
			p.fg = svgBasic[c-30]
		case c >= 90 && c <= 97:
			p.fg = svgBasic[c-90+8]
		case c >= 40 && c <= 47:
			p.bg = svgBasic[c-40]
		case c >= 100 && c <= 107:
			p.bg = svgBasic[c-100+8]
		case c == 39:
			p.fg = ""
		case c == 49:
			p.bg = ""
		case c == 38 || c == 48 || c == 58:
			var col string
			switch num(i + 1) {
			case 2:
				col = fmt.Sprintf("#%02x%02x%02x", num(i+2), num(i+3), num(i+4))
				i += 4
			case 5:
				col = svgColor256(num(i + 2))
				i += 2
			}
			if c == 38 {
				p.fg = col
			} else if c == 48 {
				p.bg = col
			}
		}
	}
}

// svgParse turns terminal output into rows of cells.
func svgParse(s string) [][]svgCell {
	var rows [][]svgCell
	var p svgPen
	for _, line := range strings.Split(s, "\n") {
		var row []svgCell
		for i := 0; i < len(line); {
			if line[i] == 0x1b && i+1 < len(line) {
				switch line[i+1] {
				case '[': // CSI; only SGR matters
					j := i + 2
					for j < len(line) && (line[j] < 0x40 || line[j] > 0x7e) {
						j++
					}
					if j < len(line) && line[j] == 'm' {
						p.apply(line[i+2 : j])
					}
					i = j + 1
				case ']': // OSC, ended by BEL or ST
					j := i + 2
					for j < len(line) && line[j] != 0x07 && (line[j] != 0x1b || j+1 >= len(line) || line[j+1] != '\\') {
						j++
					}
					if j < len(line) && line[j] == 0x07 {
						i = j + 1
					} else {
						i = j + 2
					}
				default:
					i += 2
				}
				continue
			}
			r, size := utf8.DecodeRuneInString(line[i:])
			i += size
			w := ansi.StringWidth(string(r))
			if w == 0 {
				if n := len(row); n > 0 {
					row[n-1].text += string(r)
				}
				continue
			}
			fg, bg := p.fg, p.bg
			if fg == "" {
				fg = svgDefFg
			}
			if p.reverse {
				fg, bg = bg, fg
				if fg == "" {
					fg = svgDefBg
				}
			}
			if bg == svgDefBg {
				bg = ""
			}
			c := svgCell{text: string(r), wide: w > 1, fg: fg, bg: bg, pen: p}
			row = append(row, c)
			if w > 1 {
				c.text = ""
				row = append(row, c)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

var svgEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

func svgNum(f float64) string { return strconv.FormatFloat(math.Round(f*100)/100, 'f', -1, 64) }

// svgShape draws box-drawing and block characters as geometry. It reports
// false for characters that are rendered as text.
func svgShape(b *strings.Builder, r string, x, y float64, col string) bool {
	w, h := svgCellW, svgLineH
	cx, cy := x+w/2, y+h/2
	rad := w / 2
	line := func(d string) {
		fmt.Fprintf(b, `<path d="%s" stroke="%s" stroke-width="1.3" fill="none"/>`, d, col)
	}
	rect := func(rx, ry, rw, rh, opacity float64) {
		op := ""
		if opacity < 1 {
			op = fmt.Sprintf(` fill-opacity="%s"`, svgNum(opacity))
		}
		fmt.Fprintf(b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"%s/>`,
			svgNum(rx), svgNum(ry), svgNum(rw+0.15), svgNum(rh+0.15), col, op)
	}
	p := func(f float64) string { return svgNum(f) }
	switch r {
	case "─":
		line("M" + p(x) + " " + p(cy) + "H" + p(x+w))
	case "│":
		line("M" + p(cx) + " " + p(y) + "V" + p(y+h))
	case "╭":
		line(fmt.Sprintf("M%s %sV%sA%s %s 0 0 1 %s %sH%s", p(cx), p(y+h), p(cy+rad), p(rad), p(rad), p(cx+rad), p(cy), p(x+w)))
	case "╮":
		line(fmt.Sprintf("M%s %sH%sA%s %s 0 0 1 %s %sV%s", p(x), p(cy), p(cx-rad), p(rad), p(rad), p(cx), p(cy+rad), p(y+h)))
	case "╰":
		line(fmt.Sprintf("M%s %sV%sA%s %s 0 0 0 %s %sH%s", p(cx), p(y), p(cy-rad), p(rad), p(rad), p(cx+rad), p(cy), p(x+w)))
	case "╯":
		line(fmt.Sprintf("M%s %sH%sA%s %s 0 0 0 %s %sV%s", p(x), p(cy), p(cx-rad), p(rad), p(rad), p(cx), p(cy-rad), p(y)))
	case "█":
		rect(x, y, w, h, 1)
	case "▀":
		rect(x, y, w, h/2, 1)
	case "▄":
		rect(x, y+h/2, w, h/2, 1)
	case "▌":
		rect(x, y, w/2, h, 1)
	case "▐":
		rect(x+w/2, y, w/2, h, 1)
	case "▎":
		rect(x, y, w/4, h, 1)
	case "▍":
		rect(x, y, w*3/8, h, 1)
	case "░":
		rect(x, y, w, h, 0.25)
	case "▒":
		rect(x, y, w, h, 0.5)
	case "▓":
		rect(x, y, w, h, 0.75)
	default:
		return false
	}
	return true
}

// svgScreenshot renders s in a cols×rows terminal window titled title.
func svgScreenshot(s string, cols, rows int, title, desc string) string {
	grid := svgParse(s)
	if len(grid) > rows {
		grid = grid[:rows]
	}
	winW := svgPadX*2 + float64(cols)*svgCellW
	winH := svgBarH + float64(rows)*svgLineH + svgPadB
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s" role="img">`,
		svgNum(winW+2*svgMargin), svgNum(winH+2*svgMargin), svgNum(winW+2*svgMargin), svgNum(winH+2*svgMargin))
	fmt.Fprintf(&b, "\n<title>%s</title><desc>%s</desc>\n", svgEscape.Replace(title), svgEscape.Replace(desc))
	b.WriteString(`<defs><filter id="shadow" x="-10%" y="-10%" width="120%" height="130%">` +
		`<feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#000" flood-opacity="0.35"/></filter></defs>` + "\n")
	fmt.Fprintf(&b, `<g transform="translate(%s %s)">`+"\n", svgNum(svgMargin), svgNum(svgMargin))
	fmt.Fprintf(&b, `<rect width="%s" height="%s" rx="10" fill="%s" stroke="#2f334d" filter="url(#shadow)"/>`+"\n", svgNum(winW), svgNum(winH), svgDefBg)
	for i, c := range []string{"#ff5f57", "#febc2e", "#28c840"} {
		fmt.Fprintf(&b, `<circle cx="%d" cy="18" r="6" fill="%s"/>`, 22+i*20, c)
	}
	fmt.Fprintf(&b, "\n"+`<text x="%s" y="23" text-anchor="middle" fill="#7a82a8" font-family='%s' font-size="13">%s</text>`+"\n",
		svgNum(winW/2), svgFont, svgEscape.Replace(title))
	fmt.Fprintf(&b, `<g font-family='%s' font-size="%s" xml:space="preserve" shape-rendering="crispEdges">`+"\n", svgFont, svgNum(svgFontSize))

	cellX := func(col int) float64 { return svgPadX + float64(col)*svgCellW }
	rowY := func(row int) float64 { return svgBarH + float64(row)*svgLineH }

	// Backgrounds.
	for ri, row := range grid {
		for ci := 0; ci < len(row) && ci < cols; {
			bg := row[ci].bg
			j := ci + 1
			for j < len(row) && j < cols && row[j].bg == bg {
				j++
			}
			if bg != "" {
				fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>`,
					svgNum(cellX(ci)), svgNum(rowY(ri)), svgNum(float64(j-ci)*svgCellW+0.15), svgNum(svgLineH+0.15), bg)
			}
			ci = j
		}
	}
	b.WriteString("\n")

	// Shapes and text.
	for ri, row := range grid {
		y := rowY(ri)
		base := y + svgLineH*0.72
		for ci := 0; ci < len(row) && ci < cols; {
			c := row[ci]
			if c.text == "" {
				ci++
				continue
			}
			if svgShape(&b, c.text, cellX(ci), y, c.fg) {
				ci++
				continue
			}
			if c.wide {
				fmt.Fprintf(&b, `<text x="%s" y="%s" fill="%s">%s</text>`, svgNum(cellX(ci)), svgNum(base), c.fg, svgEscape.Replace(c.text))
				ci += 2
				continue
			}
			// A run of narrow text cells with the same look.
			j := ci
			var run strings.Builder
			for j < len(row) && j < cols {
				d := row[j]
				if d.wide || d.text == "" || d.fg != c.fg || d.pen.bold != c.pen.bold || d.pen.italic != c.pen.italic ||
					d.pen.underline != c.pen.underline {
					break
				}
				var tmp strings.Builder
				if svgShape(&tmp, d.text, 0, 0, "") {
					break
				}
				run.WriteString(d.text)
				j++
			}
			attrs := ""
			if c.pen.bold {
				attrs += ` font-weight="bold"`
			}
			if c.pen.italic {
				attrs += ` font-style="italic"`
			}
			if c.pen.underline {
				attrs += ` text-decoration="underline"`
			}
			// SVG renderers collapse repeated spaces, so every stretch of
			// words separated by single spaces gets its own exact position.
			cells := row[ci:j]
			for k := 0; k < len(cells); {
				if cells[k].text == " " {
					k++
					continue
				}
				e := k
				var seg strings.Builder
				for e < len(cells) && (cells[e].text != " " || (e+1 < len(cells) && cells[e+1].text != " " && e > k)) {
					seg.WriteString(cells[e].text)
					e++
				}
				fmt.Fprintf(&b, `<text x="%s" y="%s" fill="%s"%s textLength="%s" lengthAdjust="spacingAndGlyphs">%s</text>`,
					svgNum(cellX(ci+k)), svgNum(base), c.fg, attrs, svgNum(float64(e-k)*svgCellW), svgEscape.Replace(seg.String()))
				k = e
			}
			if j == ci {
				j++
			}
			ci = j
		}
		b.WriteString("\n")
	}
	b.WriteString("</g>\n</g>\n</svg>\n")
	return b.String()
}
