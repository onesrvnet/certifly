package tui

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
)

// The three steps of signing in.
type loginStep int

const (
	stepServer loginStep = iota
	stepApprove
	stepCertificates
	stepSSH
)

type (
	loginStartedMsg struct {
		pending *session.Pending
		opened  bool
		err     error
	}
	loginApprovedMsg struct {
		s   session.Session
		err error
	}
	loginAccessMsg struct {
		access api.Access
		err    error
	}
	loginMintedMsg   struct{ res certs.Result }
	loginFinishedMsg struct{}
)

type loginModel struct {
	app   *app.App
	theme Theme
	step  loginStep

	server  textinput.Model
	pending *session.Pending
	opened  bool
	cancel  context.CancelFunc
	err     error

	groups  []api.HostGroupAccess
	results map[string]certs.Result
	done    bool
	// width and height are the terminal's; the box grows with it up to a readable maximum.
	width, height int
	// sshChoice is the cursor in the SSH step: 0 = only through certifly, 1 = also plain ssh.
	sshChoice int
	applying  bool
}

type sshAppliedMsg struct{ err error }

func newLoginModel(a *app.App, t Theme) loginModel {
	in := textinput.New()
	in.Placeholder = "certifly.example.com"
	in.Prompt = "❯ "
	in.SetValue(strings.TrimPrefix(a.Config.Server, "https://"))
	in.SetWidth(48)
	m := loginModel{app: a, theme: t, server: in, results: map[string]certs.Result{}}
	if a.Config.Server == "" {
		m.step = stepServer
		// Focus here: Init has a value receiver, so focusing there would only focus a copy and
		// the field would ignore every key.
		m.server.Focus()
	} else {
		m.step = stepApprove
	}
	return m
}

// Init starts the server field's cursor on first start, or the sign-in right away.
func (m loginModel) Init() tea.Cmd {
	if m.step == stepServer {
		return textinput.Blink
	}
	return m.start()
}

func (m loginModel) start() tea.Cmd {
	client := m.app.Client()
	client.Token = ""
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		p, err := session.Start(ctx, client)
		if err != nil {
			return loginStartedMsg{err: err}
		}
		return loginStartedMsg{pending: p, opened: session.OpenBrowser(p.BrowserURL)}
	}
}

func (m *loginModel) wait() tea.Cmd {
	ctx, cancel := context.WithDeadline(context.Background(), m.pending.ExpiresAt)
	m.cancel = cancel
	p, client := m.pending, m.app.Client()
	client.Token = ""
	return func() tea.Msg {
		s, err := p.Wait(ctx, client)
		return loginApprovedMsg{s: s, err: err}
	}
}

func (m loginModel) Update(msg tea.Msg) (loginModel, tea.Cmd) {
	switch msg := msg.(type) {
	case loginStartedMsg:
		m.err = msg.err
		if msg.err != nil {
			return m, nil
		}
		m.pending, m.opened = msg.pending, msg.opened
		return m, m.wait()
	case loginApprovedMsg:
		if msg.err != nil {
			if !errors.Is(msg.err, context.Canceled) {
				m.err = msg.err
			}
			return m, nil
		}
		if _, err := m.app.SaveSession(msg.s); err != nil {
			m.err = err
			return m, nil
		}
		m.step = stepCertificates
		a := m.app
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			access, err := a.Client().Access(ctx)
			return loginAccessMsg{access: access, err: err}
		}
	case loginAccessMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		m.groups = msg.access.HostGroups
		if len(m.groups) == 0 {
			m.done = true
			return m, nil
		}
		var cmds []tea.Cmd
		for _, g := range m.groups {
			a, g := m.app, g
			cmds = append(cmds, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				return loginMintedMsg{res: a.MintOne(ctx, g)}
			})
		}
		return m, tea.Batch(cmds...)
	case sshAppliedMsg:
		m.applying = false
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		return m, func() tea.Msg { return loginFinishedMsg{} }
	case loginMintedMsg:
		m.results[msg.res.HostGroup.Slug] = msg.res
		if len(m.results) == len(m.groups) {
			m.done = true
			_ = m.app.WriteSSHConfig(m.groups)
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	if m.step == stepServer {
		var cmd tea.Cmd
		m.server, cmd = m.server.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m loginModel) key(msg tea.KeyPressMsg) (loginModel, tea.Cmd) {
	switch m.step {
	case stepServer:
		switch msg.String() {
		case "enter":
			value := strings.TrimSpace(m.server.Value())
			if value == "" {
				return m, nil
			}
			if _, err := url.Parse(value); err != nil {
				m.err = err
				return m, nil
			}
			if err := m.app.SetServer(value); err != nil {
				m.err = err
				return m, nil
			}
			m.err = nil
			m.step = stepApprove
			m.server.Blur()
			return m, m.start()
		case "esc":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.server, cmd = m.server.Update(msg)
		return m, cmd
	case stepApprove:
		switch msg.String() {
		case "c":
			if m.pending != nil {
				return m, tea.SetClipboard(m.pending.BrowserURL)
			}
		case "o":
			if m.pending != nil {
				session.OpenBrowser(m.pending.BrowserURL)
			}
		case "enter":
			if m.err != nil {
				m.err = nil
				m.pending = nil
				return m, m.start()
			}
		case "e":
			if m.cancel != nil {
				m.cancel()
			}
			m.pending, m.err = nil, nil
			m.step = stepServer
			return m, m.server.Focus()
		case "esc", "q":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
	case stepCertificates:
		if m.done && (msg.String() == "enter" || msg.String() == " ") {
			if !m.app.Config.SSHIntegrationAsked {
				m.step = stepSSH
				return m, nil
			}
			return m, func() tea.Msg { return loginFinishedMsg{} }
		}
		if msg.String() == "esc" || msg.String() == "q" {
			return m, tea.Quit
		}
	case stepSSH:
		if m.applying {
			return m, nil
		}
		switch msg.String() {
		case "up", "k", "down", "j":
			m.sshChoice = 1 - m.sshChoice
		case "enter":
			m.applying = true
			a, groups, on := m.app, m.groups, m.sshChoice == 1
			return m, func() tea.Msg {
				if err := a.SetSSHIntegration(on, groups); err != nil {
					return sshAppliedMsg{err: err}
				}
				if on {
					// The certificates were loaded into certifly's own agent; load them into the person's.
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					defer cancel()
					a.MintAll(ctx, groups)
				}
				return sshAppliedMsg{}
			}
		case "esc", "q":
			return m, tea.Quit
		}
	}
	return m, nil
}

// View draws the step indicator and the current step.
func (m loginModel) View(spin string) string {
	t := m.theme
	var b strings.Builder
	b.WriteString("\n" + m.steps() + "\n\n")
	switch m.step {
	case stepServer:
		b.WriteString(t.Strong.Render("Which certifly server?") + "\n\n")
		b.WriteString(m.server.View() + "\n\n")
		if m.err != nil {
			b.WriteString(t.Bad.Render("✗ " + m.err.Error()))
		}
	case stepApprove:
		b.WriteString(m.viewApprove(spin))
	case stepCertificates:
		b.WriteString(m.viewCertificates(spin))
	case stepSSH:
		b.WriteString(m.viewSSH(spin))
	}
	content := strings.TrimRight(b.String(), "\n")
	box := t.panel("Sign in", m.boxWidth(), lipgloss.Height(content)+3, true, content+"\n")
	if m.width == 0 {
		return box
	}
	// Centred, a little above the middle.
	top := max((m.height-lipgloss.Height(box))/3, 0)
	return strings.Repeat("\n", top) + lipgloss.PlaceHorizontal(m.width, lipgloss.Center, box)
}

// hints are the keys of the current step, shown in the window's bottom border.
func (m loginModel) hints() [][2]string {
	switch m.step {
	case stepServer:
		return [][2]string{{"↵", "continue"}, {"esc", "quit"}}
	case stepApprove:
		if m.err != nil {
			return [][2]string{{"↵", "try again"}, {"e", "change server"}, {"esc", "quit"}}
		}
		return [][2]string{{"c", "copy link"}, {"o", "open again"}, {"e", "change server"}, {"esc", "cancel"}}
	case stepCertificates:
		if m.done {
			return [][2]string{{"↵", "continue"}, {"q", "quit"}}
		}
		return [][2]string{{"q", "quit"}}
	default:
		return [][2]string{{"↑↓", "choose"}, {"↵", "confirm"}}
	}
}

// boxWidth is the width of the sign-in box: the window minus a margin, between 56 and 100 columns.
func (m loginModel) boxWidth() int {
	if m.width == 0 {
		return 64
	}
	return min(max(m.width-4, 56), 96)
}

// inner is the text width inside the box.
func (m loginModel) inner() int { return m.boxWidth() - 4 }

func (m loginModel) steps() string {
	t := m.theme
	names := []string{"Server", "Approve", "Certificates"}
	if !m.app.Config.SSHIntegrationAsked || m.step == stepSSH {
		names = append(names, "SSH")
	}
	var out []string
	for i, name := range names {
		label := fmt.Sprintf("%s %s", []string{"①", "②", "③", "④"}[i], name)
		switch {
		case loginStep(i) == m.step:
			out = append(out, t.Title.Render(label))
		case loginStep(i) < m.step:
			out = append(out, t.OK.Render(label))
		default:
			out = append(out, t.Dim.Render(label))
		}
	}
	return strings.Join(out, t.Dim.Render(" ── "))
}

func (m loginModel) viewApprove(spin string) string {
	t := m.theme
	var b strings.Builder
	if m.err != nil {
		b.WriteString(t.Bad.Render("✗ " + m.err.Error()))
		return b.String()
	}
	if m.pending == nil {
		b.WriteString(spin + t.Dim.Render(" Contacting "+m.app.Config.Server+" …"))
		return b.String()
	}
	if m.opened {
		b.WriteString("Opened your browser. Approve this code there:\n\n")
	} else {
		b.WriteString("Open this link on any device and approve this code:\n\n")
	}
	code := strings.Join(strings.Split(m.pending.UserCode, ""), " ")
	b.WriteString(lipgloss.PlaceHorizontal(m.inner(), lipgloss.Center, t.Code.Render(code)) + "\n\n")
	b.WriteString(t.Dim.Render(m.pending.BrowserURL) + "\n")
	left := time.Until(m.pending.ExpiresAt).Round(time.Second)
	b.WriteString(spin + " Waiting for approval  " + t.Dim.Render(fmt.Sprintf("%d:%02d left", int(left.Minutes()), int(left.Seconds())%60)))
	return b.String()
}

func (m loginModel) viewCertificates(spin string) string {
	t := m.theme
	var b strings.Builder
	if m.app.Session != nil {
		b.WriteString(t.OK.Render("✓") + " Signed in as " + t.Strong.Render(m.app.Session.User.Name) + t.Dim.Render(" ("+m.app.Session.User.Email+")") + "\n\n")
	}
	if m.err != nil {
		b.WriteString(t.Bad.Render("✗ "+m.err.Error()) + "\n")
		return b.String()
	}
	if m.groups == nil {
		b.WriteString(spin + t.Dim.Render(" Looking up your access …"))
		return b.String()
	}
	if len(m.groups) == 0 {
		b.WriteString(t.Warn.Render("You have no SSH access yet.") + t.Dim.Render(" Ask an admin to add you to a group.") + "\n\n")
	}
	// The message column wraps under itself, not under the name.
	msgStyle := lipgloss.NewStyle().Width(max(m.inner()-16, 20))
	line := func(mark, name, msg string) string {
		return lipgloss.JoinHorizontal(lipgloss.Top, mark+" ", fmt.Sprintf("%-13s", name), msgStyle.Render(msg)) + "\n"
	}
	for _, g := range m.groups {
		res, ok := m.results[g.Slug]
		name := g.Slug
		switch {
		case !ok && certs.UsesSK(m.app.Config, g):
			b.WriteString(line(spin, name, t.Dim.Render("YubiKey key …")))
		case !ok:
			b.WriteString(line(spin, name, t.Dim.Render("signing …")))
		case res.Err != nil && errors.Is(res.Err, sshbin.ErrNoFIDO):
			b.WriteString(line(t.Warn.Render("!"), name, t.Warn.Render("needs an OpenSSH with YubiKey support: ")+t.Key.Render(sshbin.InstallHint())))
		case res.Err != nil && (errors.Is(res.Err, certs.ErrKeyNotRegistered) || errors.Is(res.Err, certs.ErrKeyRevoked)):
			b.WriteString(line(t.Warn.Render("!"), name, t.Warn.Render("only accepts registered YubiKeys")+t.Dim.Render(" (Settings → YubiKey → Register)")))
		case res.Err != nil && errors.Is(res.Err, certs.ErrNoSecurityKey):
			b.WriteString(line(t.Warn.Render("!"), name, t.Warn.Render("needs a YubiKey key")+t.Dim.Render(" (Settings → YubiKey)")))
		case res.Err != nil:
			b.WriteString(line(t.Bad.Render("✗"), name, t.Bad.Render(res.Err.Error())))
		default:
			key := ""
			if res.UsesSK {
				key = t.Dim.Render("  YubiKey")
			}
			b.WriteString(line(t.OK.Render("✓"), name, fmt.Sprintf("%-7s", shortDuration(time.Until(res.ValidBefore)))+strings.Join(logins(res.Principals), ", ")+key))
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (m loginModel) viewSSH(spin string) string {
	t := m.theme
	var b strings.Builder
	b.WriteString(t.Strong.Render("Use certifly with plain `ssh` too?") + "\n\n")
	options := []struct{ title, text string }{
		{"No, only through certifly", "Leaves ~/.ssh untouched; certificates live in certifly's\nown agent. Connect with the TUI or `certifly ssh`."},
		{"Yes, set up ssh", "Adds one Include line to ~/.ssh/config and loads\nthe certificates into your ssh-agent, so\n`ssh <host>` just works."},
	}
	for i, o := range options {
		marker, title := "  ", t.Row.Render(o.title)
		if i == m.sshChoice {
			marker, title = t.Key.Render("▸ "), t.Strong.Render(o.title)
		}
		b.WriteString(marker + title + "\n")
		for _, line := range strings.Split(o.text, "\n") {
			b.WriteString("    " + t.Dim.Render(line) + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(t.Dim.Render("You can change this later in Settings."))
	if m.applying {
		b.WriteString("\n\n" + spin + t.Dim.Render(" Setting up …"))
	}
	return b.String()
}

// logins turns principals like "prod:root" into "root".
func logins(principals []string) []string {
	out := make([]string, 0, len(principals))
	for _, p := range principals {
		out = append(out, api.PrincipalLogin(p))
	}
	return out
}

func keys(t Theme, pairs ...string) string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, t.Key.Render(pairs[i])+" "+t.Hint.Render(pairs[i+1]))
	}
	return strings.Join(out, "  ")
}
