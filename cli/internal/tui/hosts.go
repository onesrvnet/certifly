package tui

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
)

type connectTarget struct {
	host      string
	login     string
	hostGroup string
}

type hostAction struct {
	connect *connectTarget
}

// hostsModel is the host picker: a fuzzy filter over the reachable hosts and a login per host.
type hostsModel struct {
	theme     Theme
	filter    textinput.Model
	filtering bool
	all       []api.ReachableHost
	shown     []api.ReachableHost
	cursor    int
	offset    int
	// login is the chosen login per host id; defaults per host group come from the settings.
	login    map[string]string
	defaults map[string]string
	// rows is how many host rows fit; set from the window height.
	rows int
}

func (m *hostsModel) setRows(rows int) {
	m.rows = max(rows, 3)
	m.scroll()
}

// scroll keeps the cursor inside the visible rows.
func (m *hostsModel) scroll() {
	if m.rows == 0 {
		m.rows = 10
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+m.rows {
		m.offset = m.cursor - m.rows + 1
	}
	m.offset = max(min(m.offset, len(m.shown)-m.rows), 0)
}

func newHostsModel(t Theme) hostsModel {
	in := textinput.New()
	in.Prompt = "❯ "
	in.Placeholder = "press / to filter"
	return hostsModel{theme: t, filter: in, login: map[string]string{}}
}

func (m *hostsModel) setHosts(hosts []api.ReachableHost, defaults map[string]string) {
	m.all, m.defaults = hosts, defaults
	m.apply()
}

func (m *hostsModel) apply() {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	type scored struct {
		h     api.ReachableHost
		score int
	}
	var list []scored
	for _, h := range m.all {
		hay := strings.ToLower(h.Name + " " + strings.Join(h.Hostnames, " ") + " " + h.HostGroup.Slug)
		if s, ok := fuzzy(q, hay); ok {
			list = append(list, scored{h, s})
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].score > list[j].score })
	m.shown = m.shown[:0]
	for _, s := range list {
		m.shown = append(m.shown, s.h)
	}
	if m.cursor >= len(m.shown) {
		m.cursor = max(len(m.shown)-1, 0)
	}
	m.scroll()
}

// loginFor is the login the picker uses for a host.
func (m hostsModel) loginFor(h api.ReachableHost) string {
	if l, ok := m.login[h.ID]; ok {
		return l
	}
	if d, ok := m.defaults[h.HostGroup.Slug]; ok {
		for _, l := range h.Logins {
			if l == d {
				return l
			}
		}
	}
	if len(h.Logins) > 0 {
		return h.Logins[0]
	}
	return ""
}

func (m hostsModel) Update(msg tea.Msg) (hostsModel, tea.Cmd, hostAction) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		if m.filtering {
			var cmd tea.Cmd
			m.filter, cmd = m.filter.Update(msg)
			return m, cmd, hostAction{}
		}
		return m, nil, hostAction{}
	}
	switch key.String() {
	case "up", "ctrl+p", "ctrl+k":
		m.move(-1)
		return m, nil, hostAction{}
	case "down", "ctrl+n", "ctrl+j":
		m.move(1)
		return m, nil, hostAction{}
	case "enter":
		if h, ok := m.selected(); ok {
			login := m.loginFor(h)
			host := h.Name
			if len(h.Hostnames) > 0 {
				host = h.Hostnames[0]
			}
			m.filtering = false
			m.filter.Blur()
			return m, nil, hostAction{connect: &connectTarget{host: host, login: login, hostGroup: h.HostGroup.Slug}}
		}
		return m, nil, hostAction{}
	}
	if m.filtering {
		if key.String() == "esc" {
			m.filtering = false
			m.filter.Blur()
			return m, nil, hostAction{}
		}
		var cmd tea.Cmd
		m.filter, cmd = m.filter.Update(msg)
		m.apply()
		return m, cmd, hostAction{}
	}
	switch key.String() {
	case "/":
		m.filtering = true
		return m, m.filter.Focus(), hostAction{}
	case "k":
		m.move(-1)
	case "j":
		m.move(1)
	case "g", "home":
		m.cursor = 0
		m.scroll()
	case "G", "end":
		m.cursor = max(len(m.shown)-1, 0)
		m.scroll()
	case "tab", "l", "right":
		m.cycleLogin(1)
	case "h", "left":
		m.cycleLogin(-1)
	case "esc":
		m.filter.SetValue("")
		m.apply()
	}
	return m, nil, hostAction{}
}

func (m *hostsModel) move(d int) {
	if len(m.shown) == 0 {
		return
	}
	m.cursor = (m.cursor + d + len(m.shown)) % len(m.shown)
	m.scroll()
}

func (m *hostsModel) cycleLogin(d int) {
	h, ok := m.selected()
	if !ok || len(h.Logins) < 2 {
		return
	}
	current := m.loginFor(h)
	for i, l := range h.Logins {
		if l == current {
			m.login[h.ID] = h.Logins[(i+d+len(h.Logins))%len(h.Logins)]
			return
		}
	}
}

func (m hostsModel) selected() (api.ReachableHost, bool) {
	if m.cursor < 0 || m.cursor >= len(m.shown) {
		return api.ReachableHost{}, false
	}
	return m.shown[m.cursor], true
}

// View draws the filter line, the visible host rows and, when there is room, the detail panel.
func (m hostsModel) View(width, height int) string {
	t := m.theme
	detailW := 0
	if width >= 80 {
		detailW = min(max(width*2/5, 32), 44)
	}
	listW := width
	if detailW > 0 {
		listW = width - detailW - 1
	}

	var b strings.Builder
	count := t.Dim.Render(fmt.Sprintf("%d/%d", len(m.shown), len(m.all)))
	search := t.Key.Render("⌕ ") + m.filter.View()
	if !m.filtering && m.filter.Value() == "" {
		search = t.Key.Render("⌕ ") + t.Dim.Render("press / to filter")
	}
	b.WriteString(fit(search, listW-ansiWidth(count)-1) + " " + count + "\n\n")
	switch {
	case len(m.all) == 0:
		b.WriteString(t.Dim.Render("No hosts you can reach yet. They appear here once they join a host group you have access to."))
		return b.String()
	case len(m.shown) == 0:
		b.WriteString(t.Dim.Render("No host matches."))
		return b.String()
	}

	nameW := 12
	for _, h := range m.shown {
		nameW = max(nameW, len(displayName(h)))
	}
	nameW = min(nameW, max(listW-30, 12))
	for i := m.offset; i < min(len(m.shown), m.offset+m.rows); i++ {
		h := m.shown[i]
		current := m.loginFor(h)
		var ls []string
		for _, l := range h.Logins {
			if l == current {
				ls = append(ls, t.Strong.Render(l))
			} else {
				ls = append(ls, t.Dim.Render(l))
			}
		}
		name := fmt.Sprintf("%-*s", nameW, truncate(displayName(h), nameW))
		group := fit(t.groupBadge(h.HostGroup.Slug), 10)
		if i == m.cursor {
			row := fit(t.Strong.Render(name)+"  "+group+"  "+strings.Join(ls, " "), listW-2)
			b.WriteString(t.Key.Render("▌ ") + t.Selected.Render(row) + "\n")
		} else {
			b.WriteString(fit("  "+t.Row.Render(name)+"  "+group+"  "+strings.Join(ls, " "), listW) + "\n")
		}
	}
	list := b.String()
	if detailW == 0 {
		return list
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, lipgloss.NewStyle().Width(listW).Render(list), " ", m.detail(detailW, height))
}

// detail describes the selected host and what Enter will do.
func (m hostsModel) detail(width, height int) string {
	t := m.theme
	h, ok := m.selected()
	if !ok {
		return ""
	}
	edge := lipgloss.NewStyle().Foreground(t.Border).Render("│")
	row := func(label, value string) string { return t.Dim.Render(fmt.Sprintf("%-10s", label)) + value }
	var lines []string
	lines = append(lines, t.Strong.Render(truncate(displayName(h), width-3)), "")
	lines = append(lines, row("Group", t.groupBadge(h.HostGroup.Slug)+t.Dim.Render(" "+h.HostGroup.Name)))
	if len(h.Hostnames) > 1 {
		lines = append(lines, row("Also", truncate(strings.Join(h.Hostnames[1:], ", "), width-13)))
	}
	current := m.loginFor(h)
	var ls []string
	for _, l := range h.Logins {
		if l == current {
			ls = append(ls, t.NavActive.Render(l))
		} else {
			ls = append(ls, t.Dim.Render(l))
		}
	}
	lines = append(lines, row("Log in as", strings.Join(ls, " ")))
	if h.LastSeenAt != nil {
		seen := time.Since(*h.LastSeenAt)
		text := shortDuration(seen) + " ago"
		if seen > time.Hour {
			lines = append(lines, row("Seen", t.Warn.Render(text)))
		} else {
			lines = append(lines, row("Seen", text))
		}
	}
	target := current + "@" + displayName(h)
	lines = append(lines, "", t.Key.Render("↵ ")+t.Dim.Render("ssh"))
	lines = append(lines, t.Strong.Render(truncate(target, width-3)))
	var b strings.Builder
	for i := range max(height, len(lines)) {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteString(edge + " " + fit(line, width-2) + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func displayName(h api.ReachableHost) string {
	if len(h.Hostnames) > 0 {
		return h.Hostnames[0]
	}
	return h.Name
}
