package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/onesrvnet/certifly/cli/internal/host"
	"github.com/onesrvnet/certifly/cli/internal/tui"
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Server side: join a host group and keep sshd set up (run as root)",
		Long:  "Without a subcommand, opens the setup wizard, or the host's status once it joined.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !interactive() {
				return cmd.Help()
			}
			m := tui.NewHost(host.DefaultPaths())
			m.InsecureHTTP = insecureHTTP
			_, err := tea.NewProgram(m).Run()
			return err
		},
	}
	cmd.AddCommand(hostJoinCmd(), hostSyncCmd(), hostPrincipalsCmd(), hostStatusCmd(), hostUninstallCmd())
	return cmd
}

func printStep(step host.Step) {
	if step.Err != nil {
		fmt.Printf("! %s (%v)\n", step.Text, step.Err)
		return
	}
	fmt.Println("✓", step.Text)
}

func hostJoinCmd() *cobra.Command {
	var server string
	var names []string
	var noInstall bool
	cmd := &cobra.Command{
		Use:   "join <token>",
		Short: "Join a host group with a one-time token and configure sshd",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if server == "" {
				return errors.New("--server is required, e.g. --server certifly.example.com")
			}
			if len(names) == 0 {
				names = host.DetectHostnames()
			}
			c, cancel := ctx()
			defer cancel()
			_, err := host.Join(c, host.DefaultPaths(), server, args[0], names, !noInstall, insecureHTTP, printStep)
			if err == nil {
				fmt.Println("✓ sshd -t ok, sshd configured")
			}
			return err
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "certifly server")
	cmd.Flags().StringSliceVar(&names, "name", nil, "host name to register (repeatable; default: detected FQDN and short name)")
	cmd.Flags().BoolVar(&noInstall, "no-timer", false, "do not install the systemd timer")
	return cmd
}

func hostSyncCmd() *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Renew the host certificate and fetch the CA key, KRL and principals (the timer runs this)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, cancel := ctx()
			defer cancel()
			report := printStep
			if quiet {
				report = func(host.Step) {}
			}
			_, err := host.Sync(c, host.DefaultPaths(), insecureHTTP, report)
			if err == nil && !quiet {
				fmt.Println("✓ in sync")
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&quiet, "quiet", false, "print only errors")
	return cmd
}

func hostPrincipalsCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "principals <local user>",
		Short:  "For sshd's AuthorizedPrincipalsCommand: the principals that may log in as this user",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			principals, err := host.Principals(host.DefaultPaths(), args[0])
			if err != nil {
				return err
			}
			if len(principals) > 0 {
				fmt.Println(strings.Join(principals, "\n"))
			}
			return nil
		},
	}
}

func hostStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show this host's certificate, last sync and sshd check",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := host.ReadStatus(host.DefaultPaths())
			if st.State == nil {
				return errors.New("this host has not joined certifly")
			}
			s := st.State
			fmt.Printf("Server       %s\nHost group   %s\nNames        %s\n", s.Server, s.HostGroup.Name, strings.Join(s.Hostnames, ", "))
			for _, c := range st.Certificates {
				fmt.Printf("Certificate  %s valid %s\n", c.KeyType, time.Until(c.ValidBefore).Round(time.Hour))
			}
			fmt.Printf("Last sync    %s ago %s\n", time.Since(s.LastSyncAt).Round(time.Second), s.LastError)
			fmt.Printf("KRL          %d bytes\n", st.KRLBytes)
			if st.SSHDErr != nil {
				fmt.Println("sshd -t      ✗", st.SSHDErr)
				os.Exit(1)
			}
			fmt.Println("sshd -t      ✓")
			return nil
		},
	}
}

func hostUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove certifly from sshd and stop the timer (the host stays listed in certifly)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := host.Uninstall(host.DefaultPaths()); err != nil {
				return err
			}
			fmt.Println("✓ certifly removed from sshd")
			return nil
		},
	}
}
