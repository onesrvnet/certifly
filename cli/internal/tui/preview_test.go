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

	"github.com/onesrvnet/certifly/cli/internal/app"
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
