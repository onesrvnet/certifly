package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/host"
)

type hostStage int

const (
	hostWizard hostStage = iota
	hostWorking
	hostStatus
)

type (
	hostStepMsg   host.Step
	hostDoneMsg   struct{ err error }
	hostStatusMsg host.Status
)

// HostModel is `certifly host` without arguments: the join wizard, then the host's status.
type HostModel struct {
	paths  host.Paths
	theme  Theme
	stage  hostStage
	spin   spinner.Model
	width  int
	height int
	form   *huh.Form
	server string
	token  string
	names  string

	steps    []host.Step
	events   chan tea.Msg
	status   host.Status
	err      error
	confirm  bool
	showConf bool

	// InsecureHTTP allows joining a plain-http server (--insecure-http).
	InsecureHTTP bool
}

// NewHost builds the host TUI; it opens on the status screen when the host already joined.
func NewHost(p host.Paths) HostModel {
	t := NewTheme(true)
	m := HostModel{paths: p, theme: t, spin: newSpinner(t), names: strings.Join(host.DetectHostnames(), ", ")}
	if st, _ := host.LoadState(p); st != nil {
		m.stage = hostStatus
	} else {
		m.stage = hostWizard
		m.buildForm()
	}
	return m
}

func (m *HostModel) buildForm() {
	preview := host.DropIn(m.paths, nil)
	include := "sshd_config reads sshd_config.d: ✓"
	if !host.IncludesDropIns(m.paths) {
		include = "sshd_config does not read sshd_config.d; add `Include /etc/ssh/sshd_config.d/*.conf` at its top first."
	}
	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("certifly server").Placeholder("certifly.example.com").Value(&m.server).Validate(required),
			huh.NewInput().Title("Join token").Description("From certifly: SSH → Host groups → Join tokens. Single use.").EchoMode(huh.EchoModePassword).Value(&m.token).Validate(required),
			huh.NewInput().Title("Host names").Description("Comma-separated; they must match the host group's patterns.").Value(&m.names).Validate(required),
		),
		huh.NewGroup(
			huh.NewNote().Title("This writes /etc/ssh/sshd_config.d/50-certifly.conf").Description(preview+"\n"+include),
			huh.NewConfirm().Title("Join and configure sshd?").Description("sshd is checked with `sshd -t` before it is reloaded; on failure the file is rolled back.").Affirmative("Join").Negative("Cancel").Validate(func(ok bool) error {
				if !ok {
					return fmt.Errorf("cancelled")
				}
				return nil
			}),
		),
	).WithTheme(m.theme.Form()).WithShowHelp(false)
}

func required(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("required")
	}
	return nil
}

func (m HostModel) Init() tea.Cmd {
	cmds := []tea.Cmd{tea.RequestBackgroundColor, m.spin.Tick}
	if m.stage == hostWizard {
		cmds = append(cmds, m.form.Init())
	} else {
		cmds = append(cmds, m.readStatus())
	}
	return tea.Batch(cmds...)
}

func (m HostModel) readStatus() tea.Cmd {
	p := m.paths
	return func() tea.Msg { return hostStatusMsg(host.ReadStatus(p)) }
}

// run starts join or sync in the background and streams its steps.
func (m *HostModel) run(join bool) tea.Cmd {
	m.steps, m.err = nil, nil
	m.stage = hostWorking
	events := make(chan tea.Msg, 16)
	m.events = events
	p, server, token, names, insecure := m.paths, m.server, m.token, splitNames(m.names), m.InsecureHTTP
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		report := func(s host.Step) { events <- hostStepMsg(s) }
		var err error
		if join {
			_, err = host.Join(ctx, p, server, token, names, true, insecure, report)
		} else {
			_, err = host.Sync(ctx, p, insecure, report)
		}
		events <- hostDoneMsg{err: err}
		close(events)
	}()
	return m.next()
}

func (m HostModel) next() tea.Cmd {
	events := m.events
	return func() tea.Msg {
		msg, ok := <-events
		if !ok {
			return nil
		}
		return msg
	}
}

func splitNames(s string) []string {
	var out []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func (m HostModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.theme = NewTheme(msg.IsDark())
		m.spin.Style = lipgloss.NewStyle().Foreground(m.theme.Brand)
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		if m.form != nil {
			m.form = m.form.WithWidth(min(max(msg.Width-8, 56), 100) - 4)
		}
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case hostStepMsg:
		m.steps = append(m.steps, host.Step(msg))
		return m, m.next()
	case hostDoneMsg:
		m.err = msg.err
		if msg.err == nil {
			m.stage = hostStatus
			return m, m.readStatus()
		}
		return m, nil
	case hostStatusMsg:
		m.status = host.Status(msg)
		return m, nil
	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch m.stage {
	case hostWizard:
		model, cmd := m.form.Update(msg)
		if f, ok := model.(*huh.Form); ok {
			m.form = f
		}
		switch m.form.State {
		case huh.StateCompleted:
			m.server = config.NormalizeServer(m.server)
			return m, m.run(true)
		case huh.StateAborted:
			return m, tea.Quit
		}
		return m, cmd
	case hostWorking:
		if key, ok := msg.(tea.KeyPressMsg); ok && m.err != nil {
			switch key.String() {
			case "enter":
				m.stage = hostWizard
				m.buildForm()
				return m, m.form.Init()
			case "q", "esc":
				return m, tea.Quit
			}
		}
	case hostStatus:
		if key, ok := msg.(tea.KeyPressMsg); ok {
			if m.confirm {
				m.confirm = false
				if key.String() == "y" {
					p := m.paths
					return m, func() tea.Msg { return hostDoneMsg{err: host.Uninstall(p)} }
				}
				return m, nil
			}
			switch key.String() {
			case "s":
				return m, m.run(false)
			case "d":
				m.showConf = !m.showConf
			case "u":
				m.confirm = true
			case "q", "esc":
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m HostModel) View() tea.View {
	t := m.theme
	w, h := m.width, m.height
	if w == 0 {
		w, h = 100, 30
	}
	var body string
	switch m.stage {
	case hostWizard:
		body = m.form.View()
	case hostWorking:
		var b strings.Builder
		for _, s := range m.steps {
			if s.Err != nil {
				b.WriteString(t.Warn.Render("! ") + s.Text + t.Dim.Render(" ("+s.Err.Error()+")") + "\n")
			} else {
				b.WriteString(t.OK.Render("✓ ") + s.Text + "\n")
			}
		}
		if m.err != nil {
			b.WriteString(t.Bad.Render("✗ " + m.err.Error()))
		} else {
			b.WriteString(m.spin.View() + t.Dim.Render(" Working …"))
		}
		body = b.String()
	case hostStatus:
		body = m.viewStatus()
	}
	boxW := min(max(w-8, 56), 100)
	title := "Set up this host"
	if m.stage == hostStatus {
		title = "This host"
	}
	panel := t.panel(title, boxW, lipgloss.Height(body)+3, true, "\n"+body)
	content := "\n" + lipgloss.PlaceHorizontal(w-4, lipgloss.Center, panel)
	right := ""
	if m.status.State != nil {
		right = t.Strong.Render(m.status.State.Name)
	}
	v := tea.NewView(t.frame(w, h, gradient("◆ certifly host", true, t.Brand, t.Accent), right, t.hints(m.hints()), content))
	v.AltScreen = true
	v.WindowTitle = "certifly host"
	return v
}

func (m HostModel) hints() [][2]string {
	switch {
	case m.stage == hostWizard:
		return [][2]string{{"↵", "next"}, {"shift+tab", "back"}, {"esc", "quit"}}
	case m.stage == hostWorking && m.err != nil:
		return [][2]string{{"↵", "back"}, {"q", "quit"}}
	case m.stage == hostWorking:
		return nil
	case m.confirm:
		return [][2]string{{"y", "uninstall"}, {"any key", "cancel"}}
	default:
		return [][2]string{{"s", "sync now"}, {"d", "show config"}, {"u", "uninstall"}, {"q", "quit"}}
	}
}

func (m HostModel) viewStatus() string {
	t, st := m.theme, m.status
	row := func(label, value string) string { return t.Dim.Render(fmt.Sprintf("%-13s", label)) + value + "\n" }
	var b strings.Builder
	if st.State == nil {
		b.WriteString(t.Dim.Render("Not joined. Run `certifly host` to set it up."))
		return b.String()
	}
	s := st.State
	b.WriteString(row("Server", s.Server))
	b.WriteString(row("Host group", s.HostGroup.Name+t.Dim.Render(" ("+s.HostGroup.Slug+")")))
	b.WriteString(row("Names", strings.Join(s.Hostnames, ", ")))
	for _, c := range st.Certificates {
		left := time.Until(c.ValidBefore)
		style := t.OK
		if left < 14*24*time.Hour {
			style = t.Warn
		}
		b.WriteString(row("Certificate", strings.TrimPrefix(c.KeyType, "ssh-")+"  "+style.Render("valid "+shortDuration(left))))
	}
	if len(st.Certificates) == 0 {
		b.WriteString(row("Certificate", t.Bad.Render("none yet")))
	}
	sync := shortDuration(time.Since(s.LastSyncAt)) + " ago"
	if s.LastError != "" {
		b.WriteString(row("Last sync", t.Bad.Render("✗ "+s.LastError)))
	} else {
		b.WriteString(row("Last sync", sync+" "+t.OK.Render("✓")))
	}
	b.WriteString(row("KRL", fmt.Sprintf("%d bytes, fetched %s ago", st.KRLBytes, shortDuration(time.Since(s.KRLAt)))))
	switch {
	case !st.Includes:
		b.WriteString(row("sshd config", t.Bad.Render("sshd_config does not include sshd_config.d")))
	case st.SSHDErr != nil:
		b.WriteString(row("sshd config", t.Bad.Render("✗ "+st.SSHDErr.Error())))
	default:
		b.WriteString(row("sshd config", t.OK.Render("✓ sshd -t ok")))
	}
	if m.showConf {
		b.WriteString("\n" + t.Dim.Render(host.DropIn(m.paths, nil)))
	}
	if m.err != nil {
		b.WriteString("\n" + t.Bad.Render("✗ "+m.err.Error()) + "\n")
	}
	if m.confirm {
		b.WriteString("\n" + t.Warn.Render("Remove certifly from sshd and stop the timer?"))
	}
	return strings.TrimRight(b.String(), "\n")
}
