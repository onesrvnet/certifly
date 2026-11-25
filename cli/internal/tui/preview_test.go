package tui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/fake"
	"github.com/onesrvnet/certifly/cli/internal/host"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshagent"
)

func frame(m tea.Model) string { return ansi.Strip(m.View().Content) }

func key(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	}
	return tea.KeyPressMsg{Code: rune(s[0]), Text: s}
}

// TestScreens renders the main screens against the fake server; run with -v to see them.
func TestScreens(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("CERTIFLY_CONFIG_DIR", filepath.Join(dir, "cfg"))
	t.Setenv("CERTIFLY_SESSION_FILE", "1")
	srv := fake.New()
	defer srv.Close()
	// Fetching starts certifly's own ssh-agent for this temporary config; stop it afterwards.
	t.Cleanup(func() { _ = exec.Command("pkill", "-f", "ssh-agent -a "+sshagent.PrivateSocket()).Run() })

	a, _ := app.Load()
	_ = a.SetServer(srv.URL)

	// Sign-in, step 2: the code to approve.
	var m tea.Model = New(a)
	m, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 34})
	m, _ = m.Update(tea.BackgroundColorMsg{})
	p, err := session.Start(context.Background(), a.Client())
	if err != nil {
		t.Fatal(err)
	}
	m, _ = m.Update(loginStartedMsg{pending: p, opened: true})
	out := frame(m)
	t.Log("\n" + out)
	if !strings.Contains(out, "W D J B - M J H T") || !strings.Contains(out, "Waiting for approval") {
		t.Fatal("approve step lacks the code")
	}

	// Signed in: the host picker with the status bar.
	s, err := p.Wait(context.Background(), a.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.SaveSession(s)
	a.Config.AutoRenew = false
	m, _ = m.Update(loginFinishedMsg{})
	ov, err := a.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ov.Loaded = nil
	m, _ = m.Update(overviewMsg{ov: ov})
	m, _ = m.Update(key("down"))
	m, _ = m.Update(key("tab"))
	out = frame(m)
	t.Log("\n" + out)
	if !strings.Contains(out, "web-01.prod.corp") || !strings.Contains(out, "7/7") || !strings.Contains(out, "1  Hosts") || !strings.Contains(out, "flexusma@db-01.staging.corp") {
		t.Fatal("host picker incomplete")
	}

	// Filtering narrows the list.
	m, _ = m.Update(key("/"))
	for _, c := range "stag" {
		m, _ = m.Update(key(string(c)))
	}
	out = frame(m)
	t.Log("\n" + out)
	if !strings.Contains(out, "3/7") {
		t.Fatal("filter did not narrow to staging")
	}
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})

	m, _ = m.Update(key("2"))
	t.Log("\n" + frame(m))
	m, _ = m.Update(key("3"))
	out = frame(m)
	t.Log("\n" + out)
	if !strings.Contains(out, "YubiKey") || !strings.Contains(out, "flexusma") {
		t.Fatal("settings incomplete")
	}
	m, _ = m.Update(key("e"))
	t.Log("\n" + frame(m))
	_ = time.Second
}

func TestHostScreens(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc", "ssh"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc", "ssh", "sshd_config"), []byte("Include /etc/ssh/sshd_config.d/*.conf\n"), 0o644)
	var m tea.Model = NewHost(host.Paths{Root: root})
	m, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 34})
	m.Init()
	t.Log("\n" + frame(m))
}

func TestSSHStep(t *testing.T) {
	t.Setenv("CERTIFLY_CONFIG_DIR", t.TempDir())
	a, _ := app.Load()
	a.Config.Server = "https://certifly.example"
	l := newLoginModel(a, NewTheme(true))
	l.step = stepSSH
	l, _ = l.Update(key("down"))
	out := ansi.Strip(l.View(""))
	t.Log("\n" + out)
	if !strings.Contains(out, "④ SSH") || !strings.Contains(out, "▸ Yes, set up ssh") {
		t.Fatal("SSH step incomplete")
	}
}

// On first start the server field takes typing through the whole TUI, without a click or key to focus it.
func TestServerFieldTakesTypingOnFirstStart(t *testing.T) {
	t.Setenv("CERTIFLY_CONFIG_DIR", t.TempDir())
	a, _ := app.Load()
	var m tea.Model = New(a)
	m.Init()
	m, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	for _, r := range "certifly.int.onesrv.net" {
		m, _ = m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	if out := frame(m); !strings.Contains(out, "❯ certifly.int.onesrv.net") {
		t.Fatalf("the typed server name is missing:\n%s", out)
	}
}

// The YubiKey registration in Settings, while it waits for the browser.
func TestRegisterYubiKeyScreen(t *testing.T) {
	t.Setenv("CERTIFLY_CONFIG_DIR", t.TempDir())
	a, _ := app.Load()
	a.Config.Server = "https://pki.example.com"
	m := newSettingsModel(a, NewTheme(true))
	reg := &certs.Registration{
		SecurityKeyEnrollment: api.SecurityKeyEnrollment{EnrollmentID: "e-1", UserCode: "KXTP-MZRL", BrowserURL: "https://pki.example.com/cli/security-key/e-1", ExpiresAt: time.Now().Add(9*time.Minute + 42*time.Second)},
		Upload:                api.SecurityKeyUpload{Attested: true, Model: "YubiKey 5 Series"},
	}
	m.reg = &registering{reg: reg, step: regWaiting, opened: true}
	out := ansi.Strip(m.View(64, "⠋"))
	t.Log("\n" + out)
	for _, want := range []string{"Register YubiKey", "✓ Key created on the YubiKey", "✓ Genuine YubiKey 5 Series", "Approve it in your browser:", "K X T P - M Z R L", "/cli/security-key/e-1", "Waiting for approval"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if !m.editing() {
		t.Fatal("global keys must not fire during a registration")
	}
	if h := m.help(); h[0][0] != "c" || h[len(h)-1][0] != "esc" {
		t.Fatalf("help = %v", h)
	}
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.reg != nil {
		t.Fatal("esc did not cancel the registration")
	}
}

// A host group that needs a registered YubiKey, when the one in use is not.
func TestNotRegisteredCard(t *testing.T) {
	c := newCertsModel(NewTheme(true))
	g := api.HostGroupAccess{ID: "hg-prod", Slug: "hypeserv", Name: "hypeserv", Logins: []string{"root"}, KeyPolicy: api.KeyPolicySK, MaxTTLSeconds: 24 * 3600}
	c.setOverview(app.Overview{Access: api.Access{HostGroups: []api.HostGroupAccess{g}}})
	c.results[g.Slug] = certs.Result{HostGroup: g, UsesSK: true, Err: certs.ErrKeyNotRegistered}
	out := ansi.Strip(c.View(56, ""))
	t.Log("\n" + out)
	for _, want := range []string{"YubiKey, not registered", "! This host group only accepts registered YubiKeys.", "Settings → YubiKey → Register"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}
