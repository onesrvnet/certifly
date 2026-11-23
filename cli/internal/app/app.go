// Package app ties the CLI's pieces together for both the commands and the TUI.
package app

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshagent"
	"github.com/onesrvnet/certifly/cli/internal/sshconfig"
)

// Version is set at build time with -ldflags.
var Version = "dev"

// ErrNotSignedIn means there is no valid CLI session for the configured server.
var ErrNotSignedIn = errors.New("not signed in: run `certifly login`")

// App is the CLI's state: settings, the session and a client for the server.
type App struct {
	Config  config.Config
	Session *session.Session
	// InsecureHTTP allows a plain-http server (--insecure-http).
	InsecureHTTP bool
}

// Load reads the settings and the session for the configured server.
func Load() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	a := &App{Config: cfg}
	if cfg.Server != "" {
		if s, err := session.Load(cfg.Server); err == nil {
			a.Session = s
		}
	}
	return a, nil
}

// SignedIn reports whether the session is still good.
func (a *App) SignedIn() bool { return a.Config.Server != "" && a.Session.Valid() }

// Client is a client for the server, with the session token when there is one.
func (a *App) Client() *api.Client {
	c := api.New(a.Config.Server, "")
	if a.Session != nil {
		c.Token = a.Session.Token
	}
	c.UserAgent = "certifly-cli/" + Version
	c.AllowHTTP = a.InsecureHTTP
	return c
}

// SetServer switches to another server; the session of the old one stays stored.
func (a *App) SetServer(server string) error {
	a.Config.Server = config.NormalizeServer(server)
	a.Session = nil
	if s, err := session.Load(a.Config.Server); err == nil {
		a.Session = s
	}
	return a.Config.Save()
}

// SaveSession stores a new session and returns where.
func (a *App) SaveSession(s session.Session) (string, error) {
	a.Session = &s
	return session.Save(s)
}

// Logout revokes the session on the server and forgets it here.
func (a *App) Logout(ctx context.Context) error {
	if a.Session != nil {
		_ = a.Client().Logout(ctx)
	}
	a.Session = nil
	return session.Delete(a.Config.Server)
}

// Agent opens the agent certificates go to: the person's own agent when they use certifly with plain
// ssh, otherwise the CLI's private one, so plain ssh never sees them.
func (a *App) Agent() (*sshagent.Agent, error) {
	if !a.Config.SSHIntegration {
		return sshagent.OpenPrivate()
	}
	return sshagent.Open(a.Config.Agent)
}

// SetSSHIntegration switches between plain-ssh integration and certifly-only use. It moves nothing by
// itself: the caller renews the certificates so they land in the right agent; the old agent's copies
// are removed here.
func (a *App) SetSSHIntegration(on bool, groups []api.HostGroupAccess) error {
	old, _ := a.Agent()
	a.Config.SSHIntegration, a.Config.SSHIntegrationAsked = on, true
	if old != nil {
		for _, g := range groups {
			old.RemoveHostGroup(g.Slug)
		}
		old.Close()
	}
	if !on {
		_ = sshconfig.RemoveInclude()
	}
	if err := a.Config.Save(); err != nil {
		return err
	}
	return a.WriteSSHConfig(groups)
}

// Overview is what the TUI and `status` show.
type Overview struct {
	Access api.Access
	Hosts  []api.ReachableHost
	Loaded []sshagent.Loaded
}

// Fetch loads access and reachable hosts from the server, and the CLI's certificates in the agent.
func (a *App) Fetch(ctx context.Context) (Overview, error) {
	if !a.SignedIn() {
		return Overview{}, ErrNotSignedIn
	}
	c := a.Client()
	access, err := c.Access(ctx)
	if err != nil {
		return Overview{}, err
	}
	hosts, err := c.ReachableHosts(ctx)
	if err != nil {
		return Overview{}, err
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	ov := Overview{Access: access, Hosts: hosts}
	if ag, err := a.Agent(); err == nil {
		ov.Loaded, _ = ag.Certificates()
		ag.Close()
	}
	return ov, nil
}

// MintOne gets and loads the certificate for one host group.
func (a *App) MintOne(ctx context.Context, g api.HostGroupAccess) certs.Result {
	ag, err := a.Agent()
	if err != nil {
		return certs.Result{HostGroup: g, Err: err}
	}
	defer ag.Close()
	return certs.Mint(ctx, a.Client(), ag, a.Config, g)
}

// MintAll gets certificates for the given host groups at once. Callers refresh the SSH files with
// WriteSSHConfig and the full list of host groups.
func (a *App) MintAll(ctx context.Context, groups []api.HostGroupAccess) []certs.Result {
	results := make([]certs.Result, len(groups))
	var wg sync.WaitGroup
	for i, g := range groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = a.MintOne(ctx, g)
		}()
	}
	wg.Wait()
	return results
}

// WriteSSHConfig refreshes the known_hosts and ssh_config files (and the Include if enabled).
func (a *App) WriteSSHConfig(groups []api.HostGroupAccess) error {
	ag, err := a.Agent()
	if err != nil {
		return err
	}
	defer ag.Close()
	return sshconfig.Apply(groups, ag.Socket, ag.Private, a.Config.SSHIntegration)
}

// NeedsRenewal reports whether the host group's certificate is missing or ends within a quarter of
// its usual lifetime.
func NeedsRenewal(g api.HostGroupAccess, loaded []sshagent.Loaded) bool {
	for _, l := range loaded {
		if l.HostGroup != g.Slug {
			continue
		}
		left := time.Until(l.ValidBefore)
		return left < time.Duration(g.DefaultTTLSeconds)*time.Second/4
	}
	return true
}
