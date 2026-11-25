package tui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
)

type (
	settingsSavedMsg struct{}
	signedOutMsg     struct{}
	settingsErrMsg   struct{ err error }
	// The steps of registering a YubiKey.
	regStartedMsg struct {
		reg    *certs.Registration
		keygen *exec.Cmd
		err    error
	}
	regKeyMadeMsg   struct{ err error }
	regSubmittedMsg struct {
		opened bool
		err    error
	}
	regDoneMsg struct {
		key  api.SecurityKey
		path string
		err  error
	}
	// skRegisteredMsg tells the main screen a YubiKey was registered, to renew its certificates.
	skRegisteredMsg struct{ name string }
)

type regStep int

const (
	regStarting regStep = iota
	regUploading
	regWaiting
)

// registering is a YubiKey registration shown in Settings.
type registering struct {
	reg    *certs.Registration
	step   regStep
	opened bool
	cancel context.CancelFunc
	err    error
}

// settingsModel shows the account and settings; `e` edits them in a form.
type settingsModel struct {
	app    *app.App
	theme  Theme
	width  int
	height int
	groups []api.HostGroupAccess

	form    *huh.Form
	draft   settingsDraft
	confirm bool // asking before signing out
	reg     *registering
	err     error
}

// settingsDraft is what the form edits; it is copied into the config on save.
type settingsDraft struct {
	server, keyMode, theme string
	integration, autoRenew bool
	logins                 map[string]*string
}

func newSettingsModel(a *app.App, t Theme) settingsModel {
	return settingsModel{app: a, theme: t, width: 70}
}

func (m *settingsModel) setTheme(t Theme) { m.theme = t }
func (m *settingsModel) setSize(w, h int) {
	m.width, m.height = max(w, 40), max(h, 10)
	if m.form != nil {
		m.form = m.form.WithWidth(m.width).WithHeight(m.height)
	}
}

func (m settingsModel) editing() bool { return m.form != nil || m.confirm || m.reg != nil }

func (m settingsModel) focus() tea.Cmd { return nil }

func (m *settingsModel) startEdit() tea.Cmd {
	c := m.app.Config
	m.draft = settingsDraft{server: c.Server, keyMode: c.KeyMode, theme: c.Theme, integration: c.SSHIntegration, autoRenew: c.AutoRenew, logins: map[string]*string{}}
	fields := []huh.Field{
		huh.NewInput().Title("Server").Description("The certifly URL. Changing it signs you in there.").Value(&m.draft.server),
		huh.NewSelect[string]().Title("Key").Description("Host groups that require a YubiKey always use it.").Options(
			huh.NewOption("Throwaway key per sign-in", config.KeyModeAuto),
			huh.NewOption("Always the YubiKey key", config.KeyModeSK),
		).Value(&m.draft.keyMode),
		huh.NewConfirm().Title("Use with plain ssh").Description("On: an Include in ~/.ssh/config and the certificates in your ssh-agent. Off: ~/.ssh stays untouched; connect through certifly.").Value(&m.draft.integration),
		huh.NewConfirm().Title("Renew on start").Description("Renew certificates that are about to expire when the TUI starts.").Value(&m.draft.autoRenew),
		huh.NewSelect[string]().Title("Theme").Options(huh.NewOption("Match the terminal", "auto"), huh.NewOption("Light", "light"), huh.NewOption("Dark", "dark")).Value(&m.draft.theme),
	}
	for _, g := range m.groups {
		if len(g.Logins) < 2 {
			continue
		}
		value := c.DefaultLogins[g.Slug]
		m.draft.logins[g.Slug] = &value
		opts := []huh.Option[string]{huh.NewOption("First in the list", "")}
		for _, l := range g.Logins {
			opts = append(opts, huh.NewOption(l, l))
		}
		fields = append(fields, huh.NewSelect[string]().Title("Default login on "+g.Name).Options(opts...).Value(m.draft.logins[g.Slug]))
	}
	m.form = huh.NewForm(huh.NewGroup(fields...)).WithTheme(m.theme.Form()).WithWidth(m.width).WithHeight(m.height).WithShowHelp(false)
	return m.form.Init()
}

func (m settingsModel) save() tea.Cmd {
	a, d, groups := m.app, m.draft, m.groups
	return func() tea.Msg {
		serverChanged := config.NormalizeServer(d.server) != a.Config.Server
		a.Config.KeyMode, a.Config.Theme, a.Config.SSHIntegration, a.Config.AutoRenew = d.keyMode, d.theme, d.integration, d.autoRenew
		if a.Config.DefaultLogins == nil {
			a.Config.DefaultLogins = map[string]string{}
		}
		for slug, v := range d.logins {
			if *v == "" {
				delete(a.Config.DefaultLogins, slug)
			} else {
				a.Config.DefaultLogins[slug] = *v
			}
		}
		if d.integration != a.Config.SSHIntegration {
			// Certificates move to the other agent: drop them from the old one and renew.
			if err := a.SetSSHIntegration(d.integration, groups); err != nil {
				return settingsErrMsg{err: err}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a.MintAll(ctx, groups)
		}
		if serverChanged {
			if err := a.SetServer(d.server); err != nil {
				return settingsErrMsg{err: err}
			}
			if !a.SignedIn() {
				return signedOutMsg{}
			}
		} else if err := a.Config.Save(); err != nil {
			return settingsErrMsg{err: err}
		}
		return settingsSavedMsg{}
	}
}

// startRegistration asks the server for a challenge; the key is made once it arrives.
func (m *settingsModel) startRegistration() tea.Cmd {
	m.err = nil
	m.reg = &registering{}
	client := m.app.Client()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		reg, keygen, err := certs.StartRegistration(ctx, client)
		return regStartedMsg{reg: reg, keygen: keygen, err: err}
	}
}

// stopRegistration cancels the waiting and removes the unfinished key.
func (m *settingsModel) stopRegistration() {
	if m.reg == nil {
		return
	}
	if m.reg.cancel != nil {
		m.reg.cancel()
	}
	if m.reg.reg != nil {
		m.reg.reg.Discard()
	}
	m.reg = nil
}

// updateRegistration runs the registration steps: make the key, upload it, wait for approval.
func (m settingsModel) updateRegistration(msg tea.Msg) (settingsModel, tea.Cmd) {
	r := m.reg
	fail := func(err error) (settingsModel, tea.Cmd) {
		if r.reg != nil {
			r.reg.Discard()
		}
		r.err = err
		return m, nil
	}
	switch msg := msg.(type) {
	case regStartedMsg:
		if msg.err != nil {
			return fail(msg.err)
		}
		r.reg = msg.reg
		return m, tea.ExecProcess(msg.keygen, func(err error) tea.Msg {
			if err != nil {
				return regKeyMadeMsg{err: fmt.Errorf("ssh-keygen: %w", err)}
			}
			return regKeyMadeMsg{}
		})
	case regKeyMadeMsg:
		if msg.err != nil {
			return fail(msg.err)
		}
		r.step = regUploading
		reg, client := r.reg, m.app.Client()
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := reg.Submit(ctx, client, ""); err != nil {
				return regSubmittedMsg{err: err}
			}
			return regSubmittedMsg{opened: session.OpenBrowser(reg.BrowserURL)}
		}
	case regSubmittedMsg:
		if msg.err != nil {
			return fail(msg.err)
		}
		r.step, r.opened = regWaiting, msg.opened
		ctx, cancel := context.WithDeadline(context.Background(), r.reg.ExpiresAt)
		r.cancel = cancel
		reg, client := r.reg, m.app.Client()
		return m, func() tea.Msg {
			key, path, err := reg.Wait(ctx, client)
			return regDoneMsg{key: key, path: path, err: err}
		}
	case regDoneMsg:
		if msg.err != nil {
			return fail(msg.err)
		}
		r.cancel()
		m.reg = nil
		m.app.Config.SKKey = msg.path
		if err := m.app.Config.Save(); err != nil {
			m.err = err
			return m, nil
		}
		name := msg.key.Name
		return m, func() tea.Msg { return skRegisteredMsg{name: name} }
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			m.stopRegistration()
		case "enter":
			if r.err != nil {
				m.stopRegistration()
				return m, m.startRegistration()
			}
		case "c":
			if r.step == regWaiting && r.err == nil {
				return m, tea.SetClipboard(r.reg.BrowserURL)
			}
		case "o":
			if r.step == regWaiting && r.err == nil {
				session.OpenBrowser(r.reg.BrowserURL)
			}
		}
	}
	return m, nil
}

func (m settingsModel) Update(msg tea.Msg) (settingsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case settingsErrMsg:
		m.err = msg.err
		return m, nil
	case regStartedMsg, regKeyMadeMsg, regSubmittedMsg, regDoneMsg:
		// A cancelled registration may still answer; nothing waits for it any more.
		if m.reg == nil {
			if started, ok := msg.(regStartedMsg); ok && started.reg != nil {
				started.reg.Discard()
			}
			return m, nil
		}
		return m.updateRegistration(msg)
	}
	if m.reg != nil {
		return m.updateRegistration(msg)
	}
	if m.confirm {
		if key, ok := msg.(tea.KeyPressMsg); ok {
			switch key.String() {
			case "y", "enter":
				m.confirm = false
				a := m.app
				return m, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					_ = a.Logout(ctx)
					return signedOutMsg{}
				}
			default:
				m.confirm = false
			}
		}
		return m, nil
	}
	if m.form != nil {
		if key, ok := msg.(tea.KeyPressMsg); ok && key.String() == "esc" {
			m.form = nil
			return m, nil
		}
		model, cmd := m.form.Update(msg)
		if f, ok := model.(*huh.Form); ok {
			m.form = f
		}
		switch m.form.State {
		case huh.StateCompleted:
			m.form = nil
			return m, m.save()
		case huh.StateAborted:
			m.form = nil
		}
		return m, cmd
	}
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "e", "enter":
			return m, m.startEdit()
		case "c":
			if !sshbin.FIDOCapable() {
				return m, tea.SetClipboard(sshbin.InstallHint())
			}
		case "y":
			if !sshbin.FIDOCapable() {
				m.err = sshbin.ErrNoFIDO
				return m, nil
			}
			return m, m.startRegistration()
		case "o":
			m.confirm = true
		}
	}
	return m, nil
}

func (m settingsModel) help() [][2]string {
	switch {
	case m.reg != nil && m.reg.err != nil:
		return [][2]string{{"↵", "try again"}, {"esc", "back"}}
	case m.reg != nil && m.reg.step == regWaiting:
		return [][2]string{{"c", "copy link"}, {"o", "open again"}, {"esc", "cancel"}}
	case m.reg != nil:
		return [][2]string{{"esc", "cancel"}}
	case m.confirm:
		return [][2]string{{"y", "sign out"}, {"any key", "cancel"}}
	case m.form != nil:
		return [][2]string{{"↵", "next, saves after the last"}, {"shift+tab", "back"}, {"←→", "choose"}, {"esc", "cancel"}}
	default:
		return [][2]string{{"e", "edit"}, {"y", "register YubiKey"}, {"o", "sign out"}, {"1-3", "screens"}, {"q", "quit"}}
	}
}

// View shows the settings as cards: Account, Keys and SSH; `e` turns them into a form.
func (m settingsModel) View(width int, spin string) string {
	if m.form != nil {
		return m.form.View()
	}
	if m.reg != nil {
		return m.viewRegistration(width, spin)
	}
	t, c := m.theme, m.app.Config
	row := func(label, value string) string { return t.Dim.Render(fmt.Sprintf("%-16s", label)) + value }
	card := func(title string, lines ...string) string {
		return t.panel(title, width, len(lines)+2, false, strings.Join(lines, "\n"))
	}
	var account []string
	account = append(account, row("Server", serverHost(c.Server)))
	if s := m.app.Session; s != nil {
		account = append(account,
			row("Signed in as", t.Strong.Render(s.User.Name)+t.Dim.Render("  "+s.User.Email)),
			row("SSH username", s.User.Username),
			row("Session", shortDuration(time.Until(s.ExpiresAt))+t.Dim.Render(" until you need to re-verify")),
		)
	}
	keys := []string{}
	mode := "Throwaway key per sign-in"
	if c.KeyMode == config.KeyModeSK {
		mode = "Always the YubiKey key"
	}
	keys = append(keys, row("Key", mode))
	switch {
	case !sshbin.FIDOCapable():
		keys = append(keys, row("YubiKey", t.Warn.Render("needs ")+t.Key.Render(sshbin.InstallHint())+t.Dim.Render("  ")+t.Key.Render("c")+t.Dim.Render(" copies it")))
	case c.SKKey != "":
		keys = append(keys, row("YubiKey", t.dot("ok")+" set up"+t.Dim.Render("  ")+t.Key.Render("y")+t.Dim.Render(" registers a new one")))
	default:
		keys = append(keys, row("YubiKey", t.Dim.Render("not registered, press ")+t.Key.Render("y")))
	}
	keys = append(keys, row("OpenSSH", t.Dim.Render(sshbin.Find("ssh"))))
	use := "Only through certifly" + t.Dim.Render("  ~/.ssh untouched")
	if c.SSHIntegration {
		use = "Plain ssh too" + t.Dim.Render("  ~/.ssh/config includes certifly")
	}
	sshLines := []string{row("Use with ssh", use), row("Renew on start", onOff(c.AutoRenew)), row("Theme", c.Theme)}
	for slug, login := range c.DefaultLogins {
		sshLines = append(sshLines, row("Login on "+slug, login))
	}
	out := card("Account", account...) + "\n" + card("Keys", keys...) + "\n" + card("SSH", sshLines...)
	if m.confirm {
		out += "\n\n" + t.Warn.Render("Sign out? Certificates already loaded keep working until they expire.")
	}
	if m.err != nil {
		out += "\n\n" + t.Bad.Render("✗ "+m.err.Error())
	}
	return out
}

// viewRegistration is the "Register YubiKey" box: the key made, its model, and the code to approve.
func (m settingsModel) viewRegistration(width int, spin string) string {
	t, r := m.theme, m.reg
	inner := width - 4
	var b strings.Builder
	b.WriteString("\n")
	if r.step >= regUploading {
		b.WriteString(t.OK.Render("✓") + " Key created on the YubiKey\n")
	}
	if r.step == regWaiting {
		if model := r.reg.Model(); model != "" {
			b.WriteString(t.OK.Render("✓") + " Genuine " + model + "\n")
		} else {
			b.WriteString(t.Warn.Render("!") + " Not attested" + t.Dim.Render("  only for host groups that accept any security key") + "\n")
		}
	}
	switch {
	case r.err != nil:
		if r.step >= regUploading {
			b.WriteString("\n")
		}
		msg := r.err.Error()
		if errors.Is(r.err, sshbin.ErrNoFIDO) {
			msg = "needs an OpenSSH with YubiKey support: " + sshbin.InstallHint()
		}
		b.WriteString(t.Bad.Render("✗ "+msg) + "\n")
	case r.step == regStarting:
		b.WriteString(spin + t.Dim.Render(" Asking "+serverHost(m.app.Config.Server)+" for a challenge …") + "\n")
	case r.step == regUploading:
		b.WriteString(spin + t.Dim.Render(" Uploading the key …") + "\n")
	default:
		if r.opened {
			b.WriteString("\nApprove it in your browser:\n\n")
		} else {
			b.WriteString("\nOpen this link on any device and approve this code:\n\n")
		}
		code := strings.Join(strings.Split(r.reg.UserCode, ""), " ")
		b.WriteString(lipgloss.PlaceHorizontal(inner, lipgloss.Center, t.Code.Render(code)) + "\n\n")
		b.WriteString(t.Dim.Render(r.reg.BrowserURL) + "\n")
		left := max(time.Until(r.reg.ExpiresAt).Round(time.Second), 0)
		b.WriteString(spin + " Waiting for approval  " + t.Dim.Render(fmt.Sprintf("%d:%02d left", int(left.Minutes()), int(left.Seconds())%60)) + "\n")
	}
	content := b.String()
	return t.panel("Register YubiKey", width, lipgloss.Height(content)+2, true, content)
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
