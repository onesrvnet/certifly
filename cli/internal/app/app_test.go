package app_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/fake"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshagent"
	"github.com/onesrvnet/certifly/cli/internal/sshconfig"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// isolate points the CLI at temporary directories, the session file and an in-process agent.
func isolate(t *testing.T) (sock string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cfy")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	t.Setenv("CERTIFLY_CONFIG_DIR", filepath.Join(dir, "cfg"))
	t.Setenv("CERTIFLY_SESSION_FILE", "1")
	t.Setenv("SSH_AUTH_SOCK", "")
	sock = filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return sock
}

func TestLoginMintAndSSHConfig(t *testing.T) {
	sock := isolate(t)
	srv := fake.New()
	defer srv.Close()

	a, err := app.Load()
	if err != nil {
		t.Fatal(err)
	}
	a.Config.Agent = sock
	a.Config.SSHIntegration = true
	if err := a.SetServer(srv.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client := a.Client()
	p, err := session.Start(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserCode != "WDJB-MJHT" {
		t.Fatalf("user code %q", p.UserCode)
	}
	s, err := p.Wait(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SaveSession(s); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := app.Load()
	if !reloaded.SignedIn() || reloaded.Session.User.Username != "flexusma" {
		t.Fatalf("session not stored: %+v", reloaded.Session)
	}

	ov, err := a.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.Hosts) != 7 || len(ov.Access.HostGroups) != 2 {
		t.Fatalf("overview: %d hosts, %d groups", len(ov.Hosts), len(ov.Access.HostGroups))
	}
	results := a.MintAll(ctx, ov.Access.HostGroups)
	if err := a.WriteSSHConfig(ov.Access.HostGroups); err != nil {
		t.Fatal(err)
	}
	byGroup := map[string]certs.Result{}
	for _, r := range results {
		byGroup[r.HostGroup.Slug] = r
	}
	if r := byGroup["staging"]; r.Err != nil || r.UsesSK || len(r.Principals) != 2 || r.Principals[0] != "staging:deploy" {
		t.Fatalf("staging: %+v", r)
	}
	if r := byGroup["prod"]; !errors.Is(r.Err, certs.ErrNoSecurityKey) || !r.UsesSK {
		t.Fatalf("prod should need a YubiKey key: %+v", r)
	}

	// The certificate sits in the agent with the CLI's comment, for the certificate's lifetime.
	ov, _ = a.Fetch(ctx)
	if len(ov.Loaded) != 1 || ov.Loaded[0].HostGroup != "staging" || time.Until(ov.Loaded[0].ValidBefore) < 7*time.Hour {
		t.Fatalf("loaded: %+v", ov.Loaded)
	}
	if app.NeedsRenewal(ov.Access.HostGroups[1], ov.Loaded) {
		t.Fatal("a fresh certificate should not need renewal")
	}
	// Renewing replaces the old certificate instead of piling up.
	a.MintAll(ctx, ov.Access.HostGroups[1:])
	ov, _ = a.Fetch(ctx)
	if len(ov.Loaded) != 1 {
		t.Fatalf("after renewal: %d certificates", len(ov.Loaded))
	}

	known, err := os.ReadFile(sshconfig.KnownHostsPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(known), "@cert-authority *.prod.corp,*.staging.corp ssh-ed25519 ") {
		t.Fatalf("known_hosts:\n%s", known)
	}
	if !sshconfig.Included() {
		t.Fatal("with plain-ssh integration on, ~/.ssh/config includes certifly's file")
	}

	if err := a.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	reloaded, _ = app.Load()
	if reloaded.SignedIn() {
		t.Fatal("still signed in after logout")
	}
}

func TestDeniedLogin(t *testing.T) {
	isolate(t)
	srv := fake.New()
	defer srv.Close()
	srv.Deny = true
	a, _ := app.Load()
	_ = a.SetServer(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := session.Start(ctx, a.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wait(ctx, a.Client()); !errors.Is(err, session.ErrDenied) {
		t.Fatalf("want denied, got %v", err)
	}
}

func TestSSHIntegrationInclude(t *testing.T) {
	isolate(t)
	home := os.Getenv("HOME")
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host old\n  User me\n"), 0o600)
	pub, _, _ := ed25519Key()
	groups := fake.New().Groups
	groups[0].CA.PublicKey = pub
	if err := sshconfig.Apply(groups, "/tmp/sock", true, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if !strings.HasPrefix(string(data), "Include ") || !strings.Contains(string(data), "Host old") {
		t.Fatalf("config:\n%s", data)
	}
	// Applying twice keeps one Include; removing restores the file.
	_ = sshconfig.Apply(groups, "/tmp/sock", true, true)
	data, _ = os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if strings.Count(string(data), "Include ") != 1 {
		t.Fatalf("Include twice:\n%s", data)
	}
	if err := sshconfig.RemoveInclude(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if string(data) != "Host old\n  User me\n" {
		t.Fatalf("after removal:\n%q", data)
	}
	cfg, _ := os.ReadFile(sshconfig.ConfigPath())
	if !strings.Contains(string(cfg), "IdentityAgent /tmp/sock") {
		t.Fatalf("ssh_config:\n%s", cfg)
	}
}

func ed25519Key() (string, ssh.Signer, error) {
	srv := fake.New()
	defer srv.Close()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.CA.PublicKey()))), srv.CA, nil
}

// Without plain-ssh integration, certificates go to certifly's own agent and ~/.ssh stays untouched.
func TestCertifiedOnlyUsesPrivateAgent(t *testing.T) {
	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent not installed")
	}
	userSock := isolate(t)
	t.Setenv("SSH_AUTH_SOCK", userSock)
	srv := fake.New()
	defer srv.Close()
	a, _ := app.Load()
	if a.Config.SSHIntegration {
		t.Fatal("plain-ssh integration must be off by default")
	}
	_ = a.SetServer(srv.URL)
	t.Cleanup(func() { _ = exec.Command("pkill", "-f", "ssh-agent -a "+sshagent.PrivateSocket()).Run() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, _ := session.Start(ctx, a.Client())
	s, err := p.Wait(ctx, a.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.SaveSession(s)
	ov, _ := a.Fetch(ctx)
	a.MintAll(ctx, ov.Access.HostGroups)
	_ = a.WriteSSHConfig(ov.Access.HostGroups)

	ag, err := a.Agent()
	if err != nil || ag.Socket != sshagent.PrivateSocket() || !ag.Private {
		t.Fatalf("agent: %+v %v", ag, err)
	}
	if loaded, _ := ag.Certificates(); len(loaded) != 1 {
		t.Fatalf("private agent holds %d certificates", len(loaded))
	}
	ag.Close()
	user, _ := sshagent.Open(userSock)
	if loaded, _ := user.Certificates(); len(loaded) != 0 {
		t.Fatalf("the person's own agent got %d certificates", len(loaded))
	}
	if sshconfig.Included() {
		t.Fatal("~/.ssh/config must stay untouched")
	}
	cfg, _ := os.ReadFile(sshconfig.ConfigPath())
	if !strings.Contains(string(cfg), "IdentityAgent "+sshagent.PrivateSocket()) {
		t.Fatalf("certifly's own ssh_config should point to its agent:\n%s", cfg)
	}

	// Switching on moves the certificates to the person's agent.
	a.Config.Agent = userSock
	if err := a.SetSSHIntegration(true, ov.Access.HostGroups); err != nil {
		t.Fatal(err)
	}
	a.MintAll(ctx, ov.Access.HostGroups)
	if loaded, _ := user.Certificates(); len(loaded) != 1 {
		t.Fatalf("after switching on, own agent has %d", len(loaded))
	}
	private, _ := sshagent.OpenPrivate()
	if loaded, _ := private.Certificates(); len(loaded) != 0 {
		t.Fatalf("after switching on, private agent still has %d", len(loaded))
	}
	if !sshconfig.Included() {
		t.Fatal("switching on adds the Include")
	}
}
