package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
)

type (
	settingsSavedMsg struct{}
	signedOutMsg     struct{}
	skCreatedMsg     struct {
		path string
		err  error
	}
)

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

func (m settingsModel) editing() bool { return m.form != nil || m.confirm }

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
				return skCreatedMsg{err: err}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			a.MintAll(ctx, groups)
		}
		if serverChanged {
			if err := a.SetServer(d.server); err != nil {
				return skCreatedMsg{err: err}
			}
			if !a.SignedIn() {
				return signedOutMsg{}
			}
		} else if err := a.Config.Save(); err != nil {
			return skCreatedMsg{err: err}
		}
		return settingsSavedMsg{}
	}
}

func (m settingsModel) Update(msg tea.Msg) (settingsModel, tea.Cmd) {
	if done, ok := msg.(skCreatedMsg); ok {
		m.err = done.err
		if done.err == nil && done.path != "" {
			m.app.Config.SKKey = done.path
			if err := m.app.Config.Save(); err != nil {
				m.err = err
			}
			return m, func() tea.Msg { return settingsSavedMsg{} }
		}
		return m, nil
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
			path, cmd, err := certs.SecurityKeyCommand()
			if err != nil {
				m.err = err
				return m, nil
			}
			return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
				if err == nil {
					if _, statErr := os.Stat(path + ".pub"); statErr != nil {
						err = fmt.Errorf("no key was written: %w", statErr)
					}
				}
				return skCreatedMsg{path: path, err: err}
			})
		case "o":
			m.confirm = true
		}
	}
	return m, nil
}

func (m settingsModel) help() [][2]string {
	switch {
	case m.confirm:
		return [][2]string{{"y", "sign out"}, {"any key", "cancel"}}
	case m.form != nil:
		return [][2]string{{"↵", "next, saves after the last"}, {"shift+tab", "back"}, {"←→", "choose"}, {"esc", "cancel"}}
	default:
		return [][2]string{{"e", "edit"}, {"y", "set up YubiKey"}, {"o", "sign out"}, {"1-3", "screens"}, {"q", "quit"}}
	}
}

// View shows the settings as cards: Account, Keys and SSH; `e` turns them into a form.
func (m settingsModel) View(width int) string {
	if m.form != nil {
		return m.form.View()
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
		keys = append(keys, row("YubiKey", t.dot("ok")+" set up"))
	default:
		keys = append(keys, row("YubiKey", t.Dim.Render("not set up, press ")+t.Key.Render("y")))
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

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}
