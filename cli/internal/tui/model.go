package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
)

type screen int

const (
	screenLogin screen = iota
	screenMain
)

type tab int

const (
	tabHosts tab = iota
	tabCerts
	tabSettings
)

var tabNames = []string{"Hosts", "Certificates", "Settings"}

// Messages between the commands and the model.
type (
	overviewMsg struct {
		ov  app.Overview
		err error
	}
	mintedMsg   struct{ res certs.Result }
	execDoneMsg struct{ err error }
	tickMsg     time.Time
	flashMsg    struct{}
)

// Model is the root of the person's TUI.
type Model struct {
	app    *app.App
	theme  Theme
	width  int
	height int

	screen screen
	tab    tab

	login    loginModel
	hosts    hostsModel
	certs    certsModel
	settings settingsModel

	overview app.Overview
	loading  bool
	spin     spinner.Model
	err      error
	flash    string
}

// New builds the TUI; it opens on the sign-in screen unless the session is still valid.
func New(a *app.App) Model {
	theme := NewTheme(true)
	m := Model{app: a, theme: theme, spin: newSpinner(theme)}
	if a.SignedIn() {
		m.screen = screenMain
		m.loading = true
	} else {
		m.screen = screenLogin
	}
	m.login = newLoginModel(a, theme)
	m.hosts = newHostsModel(theme)
	m.certs = newCertsModel(theme)
	m.settings = newSettingsModel(a, theme)
	return m
}

func newSpinner(t Theme) spinner.Model {
	s := spinner.New(spinner.WithSpinner(spinner.MiniDot))
	s.Style = lipgloss.NewStyle().Foreground(t.Brand)
	return s
}

// Init asks the terminal for its background (for light or dark styles) and starts loading.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tea.RequestBackgroundColor, m.spin.Tick, tick()}
	if m.screen == screenMain {
		cmds = append(cmds, m.fetch())
	} else {
		cmds = append(cmds, m.login.Init())
	}
	return tea.Batch(cmds...)
}

func tick() tea.Cmd { return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }

func (m Model) fetch() tea.Cmd {
	a := m.app
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		ov, err := a.Fetch(ctx)
		return overviewMsg{ov: ov, err: err}
	}
}

// mintCmds renews certificates; with onlyDue, only those missing or close to expiring.
func (m Model) mintCmds(onlyDue bool) []tea.Cmd {
	var cmds []tea.Cmd
	for _, g := range m.overview.Access.HostGroups {
		if onlyDue && !app.NeedsRenewal(g, m.overview.Loaded) {
			continue
		}
		a := m.app
		cmds = append(cmds, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			return mintedMsg{res: a.MintOne(ctx, g)}
		})
		m.certs.pending[g.Slug] = true
	}
	return cmds
}

func (m *Model) setTheme(isDark bool) {
	switch m.app.Config.Theme {
	case "light":
		isDark = false
	case "dark":
		isDark = true
	}
	m.theme = NewTheme(isDark)
	m.login.theme, m.hosts.theme, m.certs.theme = m.theme, m.theme, m.theme
	m.settings.setTheme(m.theme)
	m.spin.Style = lipgloss.NewStyle().Foreground(m.theme.Brand)
}

func (m *Model) showFlash(text string) tea.Cmd {
	m.flash = text
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg { return flashMsg{} })
}

// Update routes messages: global keys first, then the screen in front.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.setTheme(msg.IsDark())
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// The settings form fills the main panel: window minus frame, sidebar and panel borders.
		m.settings.setSize(msg.Width-4-sidebarWidth-1-4, msg.Height-2-2)
		m.hosts.setRows(msg.Height - 6)
		return m, nil
	case tickMsg:
		return m, tick()
	case flashMsg:
		m.flash = ""
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case loginFinishedMsg:
		m.screen = screenMain
		m.loading = true
		m.settings = newSettingsModel(m.app, m.theme)
		m.settings.setSize(m.width-4-sidebarWidth-1-4, m.height-2-2)
		return m, m.fetch()
	case overviewMsg:
		m.loading = false
		m.err = msg.err
		if msg.err != nil {
			if strings.Contains(msg.err.Error(), "not signed in") || isAuthError(msg.err) {
				m.screen = screenLogin
				m.login = newLoginModel(m.app, m.theme)
				return m, m.login.Init()
			}
			return m, nil
		}
		m.overview = msg.ov
		m.settings.groups = msg.ov.Access.HostGroups
		_ = m.app.WriteSSHConfig(msg.ov.Access.HostGroups)
		m.hosts.setHosts(msg.ov.Hosts, m.app.Config.DefaultLogins)
		m.certs.setOverview(msg.ov)
		if m.app.Config.AutoRenew {
			return m, tea.Batch(m.mintCmds(true)...)
		}
		return m, nil
	case mintedMsg:
		delete(m.certs.pending, msg.res.HostGroup.Slug)
		m.certs.results[msg.res.HostGroup.Slug] = msg.res
		if msg.res.Err != nil {
			return m, m.showFlash(fmt.Sprintf("%s: %v", msg.res.HostGroup.Name, msg.res.Err))
		}
		if len(m.certs.pending) == 0 {
			return m, m.fetch()
		}
		return m, nil
	case execDoneMsg:
		if msg.err != nil {
			return m, m.showFlash(msg.err.Error())
		}
		return m, m.fetch()
	case settingsSavedMsg:
		m.setTheme(m.theme.IsDark)
		return m, tea.Batch(m.showFlash("Settings saved"), m.fetch())
	case signedOutMsg:
		m.screen = screenLogin
		m.overview = app.Overview{}
		m.login = newLoginModel(m.app, m.theme)
		return m, m.login.Init()
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	if m.screen == screenLogin {
		var cmd tea.Cmd
		m.login, cmd = m.login.Update(msg)
		return m, cmd
	}
	return m.updateMain(msg)
}

func (m Model) updateMain(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok && !m.typing() {
		switch key.String() {
		case "q":
			return m, tea.Quit
		case "1":
			m.tab = tabHosts
			return m, nil
		case "2":
			m.tab = tabCerts
			return m, nil
		case "3", "s":
			m.tab = tabSettings
			return m, m.settings.focus()
		case "tab":
			if m.tab != tabHosts {
				m.tab = (m.tab + 1) % 3
				if m.tab == tabSettings {
					return m, m.settings.focus()
				}
				return m, nil
			}
		case "shift+tab":
			m.tab = (m.tab + 2) % 3
			return m, nil
		case "r":
			return m, tea.Batch(m.mintCmds(false)...)
		case "ctrl+r":
			m.loading = true
			return m, m.fetch()
		}
	}
	var cmd tea.Cmd
	switch m.tab {
	case tabHosts:
		var action hostAction
		m.hosts, cmd, action = m.hosts.Update(msg)
		if action.connect != nil {
			return m, m.connect(*action.connect)
		}
	case tabCerts:
		var renew string
		m.certs, cmd, renew = m.certs.Update(msg)
		if renew != "" {
			for _, g := range m.overview.Access.HostGroups {
				if g.Slug == renew {
					a, g := m.app, g
					m.certs.pending[g.Slug] = true
					return m, func() tea.Msg {
						ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
						defer cancel()
						return mintedMsg{res: a.MintOne(ctx, g)}
					}
				}
			}
		}
	case tabSettings:
		m.settings, cmd = m.settings.Update(msg)
	}
	return m, cmd
}

// typing reports whether keys should go to an input instead of the global shortcuts.
func (m Model) typing() bool {
	return (m.tab == tabHosts && m.hosts.filtering) || m.tab == tabSettings && m.settings.editing()
}

// View draws the window frame and the screen in front.
func (m Model) View() tea.View {
	t := m.theme
	w, h := m.width, m.height
	if w == 0 {
		w, h = 100, 30
	}
	right := ""
	if m.app.Session != nil && m.screen == screenMain {
		right = t.Strong.Render(m.app.Session.User.Username) + t.Dim.Render("  "+serverHost(m.app.Config.Server))
	}
	var body, bottom string
	if m.screen == screenLogin {
		l := m.login
		l.width, l.height = w-4, h-2
		body = l.View(m.spin.View())
		bottom = t.hints(l.hints())
	} else {
		body = m.viewMain(w-4, h-2)
		bottom = t.hints(m.helpPairs())
		if m.flash != "" {
			bottom = t.Warn.Render(m.flash)
		}
	}
	v := tea.NewView(t.frame(w, h, t.logo(), right, bottom, body))
	v.AltScreen = true
	v.WindowTitle = "certifly"
	return v
}

func serverHost(server string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(server, "https://"), "http://")
	return strings.TrimSuffix(s, "/")
}

const sidebarWidth = 24

// viewMain is the sidebar next to the panel of the current screen.
func (m Model) viewMain(width, height int) string {
	t := m.theme
	panelW := width - sidebarWidth - 1
	title := tabNames[m.tab]
	var content string
	switch {
	case m.loading && len(m.overview.Hosts) == 0 && m.err == nil:
		content = "\n" + m.spin.View() + t.Dim.Render(" Loading hosts and certificates …")
	case m.err != nil:
		content = "\n" + t.Bad.Render("✗ "+m.err.Error()) + "\n\n" + t.hints([][2]string{{"ctrl+r", "try again"}})
	default:
		inner := panelW - 4
		switch m.tab {
		case tabHosts:
			content = m.hosts.View(inner, height-2)
		case tabCerts:
			content = m.certs.View(inner, m.spin.View())
		case tabSettings:
			content = m.settings.View(inner)
		}
	}
	panel := t.panel(title, panelW, height, true, content)
	return lipgloss.JoinHorizontal(lipgloss.Top, m.sidebar(height), " ", panel)
}

// sidebar lists the screens and, below, each host group's certificate.
func (m Model) sidebar(height int) string {
	t := m.theme
	var b strings.Builder
	b.WriteString("\n")
	for i, name := range tabNames {
		label := fmt.Sprintf("%d  %s", i+1, name)
		if tab(i) == m.tab {
			b.WriteString(t.NavActive.Width(sidebarWidth-1).Render("▸ "+label) + "\n")
		} else {
			b.WriteString(t.Nav.Width(sidebarWidth-1).Render("  "+label) + "\n")
		}
	}
	if groups := m.overview.Access.HostGroups; len(groups) > 0 {
		b.WriteString("\n" + t.Section.Render(" Certificates") + "\n")
		for _, g := range groups {
			name := fmt.Sprintf(" %-11s", truncate(g.Slug, 11))
			switch left, ok := m.certs.remaining(g.Slug); {
			case m.certs.pending[g.Slug]:
				b.WriteString(name + fmt.Sprintf("%7s ", "") + m.spin.View() + "\n")
			case !ok:
				b.WriteString(name + t.Dim.Render(fmt.Sprintf("%7s ", "none")) + t.dot("bad") + "\n")
			case left < 30*time.Minute:
				b.WriteString(name + t.Warn.Render(fmt.Sprintf("%7s ", shortDuration(left))) + t.dot("warn") + "\n")
			default:
				b.WriteString(name + t.Dim.Render(fmt.Sprintf("%7s ", shortDuration(left))) + t.dot("ok") + "\n")
			}
		}
	}
	return lipgloss.NewStyle().Width(sidebarWidth).Height(height).Render(b.String())
}

func (m Model) helpPairs() [][2]string {
	switch m.tab {
	case tabHosts:
		if m.hosts.filtering {
			return [][2]string{{"↵", "connect"}, {"↑↓", "move"}, {"esc", "stop filtering"}}
		}
		return [][2]string{{"↵", "connect"}, {"/", "filter"}, {"tab", "login"}, {"r", "renew"}, {"1-3", "screens"}, {"q", "quit"}}
	case tabCerts:
		return [][2]string{{"↵", "renew selected"}, {"r", "renew all"}, {"1-3", "screens"}, {"q", "quit"}}
	default:
		return m.settings.help()
	}
}

// connect hands the terminal to ssh and comes back to the TUI afterwards.
func (m Model) connect(target connectTarget) tea.Cmd {
	ag, err := m.app.Agent()
	if err != nil {
		return func() tea.Msg { return execDoneMsg{err: err} }
	}
	socket := ag.Socket
	ag.Close()
	cmd, err := sshCommand(target.host, target.login, target.hostGroup, socket)
	if err != nil {
		return func() tea.Msg { return execDoneMsg{err: err} }
	}
	return tea.ExecProcess(cmd, func(err error) tea.Msg { return execDoneMsg{err: nil} })
}
