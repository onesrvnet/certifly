// Package cmd holds the certifly commands. Without arguments, certifly opens the TUI.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshconfig"
	"github.com/onesrvnet/certifly/cli/internal/tui"
)

// Execute runs the command line.
func Execute() int {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "certifly:", err)
		return 1
	}
	return 0
}

func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

func ctx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func root() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "certifly",
		Short:         "SSH access with short-lived certificates from certifly",
		Long:          "certifly signs you in with your browser (passkey, YubiKey or OIDC), loads short-lived SSH certificates into ssh-agent, and lets you pick a host to connect to.\n\nRun it without arguments for the interactive TUI.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       app.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !interactive() {
				return cmd.Help()
			}
			return runTUI()
		},
	}
	cmd.PersistentFlags().BoolVar(&insecureHTTP, "insecure-http", false, "allow a plain-http server (the session token, CA keys and KRL travel unprotected)")
	cmd.AddCommand(loginCmd(), logoutCmd(), renewCmd(), statusCmd(), lsCmd(), sshCmd(), configCmd(), yubikeyCmd(), hostCmd(), updateCmd())
	return cmd
}

// insecureHTTP is the --insecure-http flag: plain http to the server is refused without it.
var insecureHTTP bool

func loadApp() (*app.App, error) {
	a, err := app.Load()
	if err != nil {
		return nil, err
	}
	a.InsecureHTTP = insecureHTTP
	return a, nil
}

func runTUI() error {
	a, err := loadApp()
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(tui.New(a)).Run()
	return err
}

func loginCmd() *cobra.Command {
	var server string
	var plain bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in with your browser and load certificates for every host group you can reach",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp()
			if err != nil {
				return err
			}
			if server != "" {
				if err := a.SetServer(server); err != nil {
					return err
				}
			}
			if a.Config.Server == "" && !interactive() {
				return errors.New("no server set: use --server certifly.example.com")
			}
			if interactive() && !plain {
				a.Session = nil
				_, err := tea.NewProgram(tui.New(a)).Run()
				return err
			}
			return plainLogin(a)
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "certifly server, e.g. certifly.example.com")
	cmd.Flags().BoolVar(&plain, "plain", false, "no TUI: print the code and link, for scripts and headless machines")
	return cmd
}

func plainLogin(a *app.App) error {
	c, cancel := ctx()
	defer cancel()
	client := a.Client()
	client.Token = ""
	p, err := session.Start(c, client)
	if err != nil {
		return err
	}
	opened := session.OpenBrowser(p.BrowserURL)
	if opened {
		fmt.Println("Opened your browser. Approve this code there:")
	} else {
		fmt.Println("Open this link on any device and approve this code:")
	}
	fmt.Printf("\n    %s\n\n    %s\n\nWaiting for approval …\n", p.UserCode, p.BrowserURL)
	waitCtx, waitCancel := context.WithDeadline(c, p.ExpiresAt)
	defer waitCancel()
	s, err := p.Wait(waitCtx, client)
	if err != nil {
		return err
	}
	where, err := a.SaveSession(s)
	if err != nil {
		return err
	}
	fmt.Printf("✓ Signed in as %s (%s); session kept in the %s for 12 h\n", s.User.Name, s.User.Email, where)
	return mintAndReport(c, a)
}

func mintAndReport(c context.Context, a *app.App) error {
	access, err := a.Client().Access(c)
	if err != nil {
		return err
	}
	if len(access.HostGroups) == 0 {
		fmt.Println("You have no SSH access yet. Ask an admin to add you to a group.")
		return nil
	}
	failed := 0
	results := a.MintAll(c, access.HostGroups)
	if err := a.WriteSSHConfig(access.HostGroups); err != nil {
		fmt.Println("! could not write the SSH files:", err)
	}
	for _, r := range results {
		if r.Err != nil {
			failed++
			fmt.Printf("✗ %-12s %v\n", r.HostGroup.Slug, r.Err)
			continue
		}
		key := ""
		if r.UsesSK {
			key = "  (YubiKey)"
		}
		fmt.Printf("✓ %-12s %-8s %s%s\n", r.HostGroup.Slug, time.Until(r.ValidBefore).Round(time.Minute), strings.Join(trimGroup(r.Principals), ", "), key)
	}
	if failed > 0 {
		return fmt.Errorf("%d host group(s) without a certificate", failed)
	}
	return nil
}

func trimGroup(principals []string) []string {
	out := make([]string, len(principals))
	for i, p := range principals {
		out[i] = api.PrincipalLogin(p)
	}
	return out
}

func renewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "renew",
		Short: "Get fresh certificates for every host group, without signing in again",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp()
			if err != nil {
				return err
			}
			if !a.SignedIn() {
				return app.ErrNotSignedIn
			}
			c, cancel := ctx()
			defer cancel()
			return mintAndReport(c, a)
		},
	}
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Sign out; certificates already in ssh-agent keep working until they expire",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp()
			if err != nil {
				return err
			}
			c, cancel := ctx()
			defer cancel()
			if err := a.Logout(c); err != nil {
				return err
			}
			fmt.Println("Signed out.")
			return nil
		},
	}
}

func statusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the session and the certificate per host group",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp()
			if err != nil {
				return err
			}
			if !a.SignedIn() {
				return app.ErrNotSignedIn
			}
			c, cancel := ctx()
			defer cancel()
			ov, err := a.Fetch(c)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"server": a.Config.Server, "user": a.Session.User, "session_expires_at": a.Session.ExpiresAt, "host_groups": ov.Access.HostGroups, "loaded": ov.Loaded})
			}
			fmt.Printf("%s as %s, session ends in %s\n\n", a.Config.Server, a.Session.User.Email, time.Until(a.Session.ExpiresAt).Round(time.Minute))
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "HOST GROUP\tLEFT\tKEY\tLOGINS")
			for _, g := range ov.Access.HostGroups {
				left := "none"
				for _, l := range ov.Loaded {
					if l.HostGroup == g.Slug {
						left = time.Until(l.ValidBefore).Round(time.Minute).String()
					}
				}
				key := "throwaway"
				if certs.UsesSK(a.Config, g) {
					key = "YubiKey"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", g.Slug, left, key, strings.Join(g.Logins, ", "))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func lsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ls [filter]",
		Short: "List the hosts you can reach",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp()
			if err != nil {
				return err
			}
			if !a.SignedIn() {
				return app.ErrNotSignedIn
			}
			c, cancel := ctx()
			defer cancel()
			hosts, err := a.Client().ReachableHosts(c)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				q := strings.ToLower(args[0])
				var kept []api.ReachableHost
				for _, h := range hosts {
					if strings.Contains(strings.ToLower(h.Name+" "+strings.Join(h.Hostnames, " ")+" "+h.HostGroup.Slug), q) {
						kept = append(kept, h)
					}
				}
				hosts = kept
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(hosts)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "HOST\tGROUP\tLOGINS")
			for _, h := range hosts {
				name := h.Name
				if len(h.Hostnames) > 0 {
					name = h.Hostnames[0]
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", name, h.HostGroup.Slug, strings.Join(h.Logins, ", "))
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func sshCmd() *cobra.Command {
	var login string
	cmd := &cobra.Command{
		Use:   "ssh <host> [-- command]",
		Short: "Connect to a host, renewing its host group's certificate first if needed",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := loadApp()
			if err != nil {
				return err
			}
			if !a.SignedIn() {
				return app.ErrNotSignedIn
			}
			c, cancel := ctx()
			defer cancel()
			ov, err := a.Fetch(c)
			if err != nil {
				return err
			}
			target := args[0]
			var host *api.ReachableHost
			for i, h := range ov.Hosts {
				if h.Name == target || contains(h.Hostnames, target) {
					host = &ov.Hosts[i]
				}
			}
			if host == nil {
				return fmt.Errorf("%s is not among the hosts you can reach (see `certifly ls`)", target)
			}
			if login == "" {
				login = a.Config.DefaultLogins[host.HostGroup.Slug]
				if login == "" && len(host.Logins) > 0 {
					login = host.Logins[0]
				}
			}
			if !contains(host.Logins, login) {
				return fmt.Errorf("you cannot log in to %s as %s; allowed: %s", target, login, strings.Join(host.Logins, ", "))
			}
			for _, g := range ov.Access.HostGroups {
				if g.ID == host.HostGroup.ID && app.NeedsRenewal(g, ov.Loaded) {
					if r := a.MintOne(c, g); r.Err != nil {
						return r.Err
					}
					_ = a.WriteSSHConfig(ov.Access.HostGroups)
				}
			}
			ag, err := a.Agent()
			if err != nil {
				return err
			}
			socket := ag.Socket
			ag.Close()
			ssh, err := sshconfig.Command(target, login, host.HostGroup.Slug, socket, args[1:]...)
			if err != nil {
				return err
			}
			ssh.Stdin, ssh.Stdout, ssh.Stderr = os.Stdin, os.Stdout, os.Stderr
			return ssh.Run()
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "local user to log in as")
	return cmd
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Read or change settings (also in the TUI under Settings)"}
	keysHelp := "server, key_mode (auto|sk), ssh_integration (true|false), auto_renew (true|false), theme (auto|light|dark), agent, default_login.<host group>"
	cmd.AddCommand(&cobra.Command{
		Use:   "get [key]",
		Short: "Print one setting or all of them",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := config.Load()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return json.NewEncoder(os.Stdout).Encode(c)
			}
			v, err := getSetting(c, args[0])
			if err != nil {
				return err
			}
			fmt.Println(v)
			return nil
		},
	}, &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Change a setting: " + keysHelp,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := config.Load()
			if err != nil {
				return err
			}
			if err := setSetting(&c, args[0], args[1]); err != nil {
				return err
			}
			if args[0] == "ssh_integration" && !c.SSHIntegration {
				_ = sshconfig.RemoveInclude()
			}
			return c.Save()
		},
	})
	return cmd
}

func getSetting(c config.Config, key string) (string, error) {
	switch {
	case key == "server":
		return c.Server, nil
	case key == "key_mode":
		return c.KeyMode, nil
	case key == "ssh_integration":
		return fmt.Sprint(c.SSHIntegration), nil
	case key == "auto_renew":
		return fmt.Sprint(c.AutoRenew), nil
	case key == "theme":
		return c.Theme, nil
	case key == "agent":
		return c.Agent, nil
	case strings.HasPrefix(key, "default_login."):
		return c.DefaultLogins[strings.TrimPrefix(key, "default_login.")], nil
	}
	return "", fmt.Errorf("unknown setting %q", key)
}

func setSetting(c *config.Config, key, value string) error {
	boolean := func() (bool, error) {
		switch value {
		case "true", "on", "yes":
			return true, nil
		case "false", "off", "no":
			return false, nil
		}
		return false, fmt.Errorf("%s takes true or false", key)
	}
	var err error
	switch {
	case key == "server":
		c.Server = config.NormalizeServer(value)
	case key == "key_mode":
		if value != config.KeyModeAuto && value != config.KeyModeSK {
			return errors.New("key_mode takes auto or sk")
		}
		c.KeyMode = value
	case key == "ssh_integration":
		c.SSHIntegration, err = boolean()
	case key == "auto_renew":
		c.AutoRenew, err = boolean()
	case key == "theme":
		if value != "auto" && value != "light" && value != "dark" {
			return errors.New("theme takes auto, light or dark")
		}
		c.Theme = value
	case key == "agent":
		c.Agent = value
	case strings.HasPrefix(key, "default_login."):
		if c.DefaultLogins == nil {
			c.DefaultLogins = map[string]string{}
		}
		c.DefaultLogins[strings.TrimPrefix(key, "default_login.")] = value
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
	return err
}

func yubikeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "yubikey",
		Short: "Create an ed25519-sk key on your YubiKey for host groups that require one",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, keygen, err := certs.SecurityKeyCommand()
			if err != nil {
				return err
			}
			fmt.Println("Touch your YubiKey when it blinks (ssh-keygen may ask for its PIN).")
			keygen.Stdin, keygen.Stdout, keygen.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := keygen.Run(); err != nil {
				return fmt.Errorf("ssh-keygen: %w", err)
			}
			c, err := config.Load()
			if err != nil {
				return err
			}
			c.SKKey = path
			if err := c.Save(); err != nil {
				return err
			}
			fmt.Println("✓ YubiKey key ready:", path+".pub")
			return nil
		},
	}
}
