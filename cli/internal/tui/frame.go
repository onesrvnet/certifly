package tui

import (
	"hash/fnv"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Rounded border pieces, drawn by hand so titles and key hints can sit inside the border lines.
const (
	cornerTL, cornerTR, cornerBL, cornerBR = "╭", "╮", "╰", "╯"
	edgeH, edgeV                           = "─", "│"
)

// gradient colours text from the first to the last stop, one colour per character.
func gradient(s string, bold bool, stops ...color.Color) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}
	colors := lipgloss.Blend1D(max(len(runes), 2), stops...)
	var b strings.Builder
	for i, r := range runes {
		st := lipgloss.NewStyle().Foreground(colors[i])
		if bold {
			st = st.Bold(true)
		}
		b.WriteString(st.Render(string(r)))
	}
	return b.String()
}

// logo is "◆ certifly" in the brand gradient.
func (t Theme) logo() string { return gradient("◆ certifly", true, t.Brand, t.Accent) }

// fit pads or cuts a styled line to exactly width cells.
func fit(line string, width int) string {
	w := ansi.StringWidth(line)
	switch {
	case w > width:
		return ansi.Truncate(line, width, "…")
	case w < width:
		return line + strings.Repeat(" ", width-w)
	}
	return line
}

// borderLine draws ╭─ left ───── right ─╮ (or the bottom variant) at the given width.
func (t Theme) borderLine(width int, leftCorner, rightCorner, left, right string) string {
	edge := lipgloss.NewStyle().Foreground(t.Border)
	inner := width - 2
	used := 0
	var b strings.Builder
	b.WriteString(edge.Render(leftCorner))
	if left != "" {
		b.WriteString(edge.Render(edgeH) + " " + left + " ")
		used += 3 + ansi.StringWidth(left)
	}
	rightPart := ""
	if right != "" {
		rightPart = " " + right + " " + edge.Render(edgeH)
	}
	rightW := ansi.StringWidth(rightPart)
	fill := inner - used - rightW
	if fill < 1 {
		// Too narrow for the right part: drop it.
		rightPart, fill = "", inner-used
	}
	b.WriteString(edge.Render(strings.Repeat(edgeH, max(fill, 0))))
	b.WriteString(rightPart)
	b.WriteString(edge.Render(rightCorner))
	return b.String()
}

// frame draws the whole-window frame: title and status in the top border, key hints in the
// bottom one, and body inside with one column of padding.
func (t Theme) frame(width, height int, left, right, bottom, body string) string {
	edge := lipgloss.NewStyle().Foreground(t.Border).Render(edgeV)
	inner := width - 4
	lines := strings.Split(body, "\n")
	rows := height - 2
	var b strings.Builder
	b.WriteString(t.borderLine(width, cornerTL, cornerTR, left, right) + "\n")
	for i := range rows {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteString(edge + " " + fit(line, inner) + " " + edge + "\n")
	}
	b.WriteString(t.borderLine(width, cornerBL, cornerBR, bottom, ""))
	return b.String()
}

// panel draws a rounded box of exactly width × height with a title in its top border.
func (t Theme) panel(title string, width, height int, focused bool, body string) string {
	borderColor := t.Border
	if focused {
		borderColor = t.Brand
	}
	edge := lipgloss.NewStyle().Foreground(borderColor)
	inner := width - 4
	titleText := ""
	if title != "" {
		st := t.Dim
		if focused {
			st = t.Title
		}
		titleText = st.Render(title)
	}
	var b strings.Builder
	top := edge.Render(cornerTL+edgeH) + " " + titleText + " "
	if title == "" {
		top = edge.Render(cornerTL + edgeH + edgeH)
	}
	b.WriteString(top + edge.Render(strings.Repeat(edgeH, max(width-ansi.StringWidth(top)-1, 0))+cornerTR) + "\n")
	lines := strings.Split(body, "\n")
	for i := range max(height-2, 0) {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteString(edge.Render(edgeV) + " " + fit(line, inner) + " " + edge.Render(edgeV) + "\n")
	}
	b.WriteString(edge.Render(cornerBL + strings.Repeat(edgeH, max(width-2, 0)) + cornerBR))
	return b.String()
}

// groupColor gives each host group a stable colour from a small palette.
func (t Theme) groupColor(slug string) color.Color {
	h := fnv.New32a()
	_, _ = h.Write([]byte(slug))
	return t.Palette[int(h.Sum32())%len(t.Palette)]
}

func (t Theme) groupBadge(slug string) string {
	return lipgloss.NewStyle().Foreground(t.groupColor(slug)).Render(slug)
}

// dot is a status light: ok, warn or bad.
func (t Theme) dot(state string) string {
	switch state {
	case "ok":
		return t.OK.Render("●")
	case "warn":
		return t.Warn.Render("●")
	default:
		return t.Bad.Render("●")
	}
}

// hints renders key hints spaced out for a border or footer.
func (t Theme) hints(pairs [][2]string) string {
	var out []string
	for _, p := range pairs {
		out = append(out, t.Key.Render(p[0])+" "+t.Hint.Render(p[1]))
	}
	return strings.Join(out, "   ")
}
