package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/update"
)

func updateCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update certifly to the latest release",
		Long:  "Downloads the latest certifly release from GitHub for this platform, checks it against the release's SHA-256 checksums and replaces this binary with it.\n\nA binary installed with Homebrew is updated with `brew upgrade certifly` instead.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, cancel := ctx()
			defer cancel()
			rel, err := update.Latest(c)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if !update.Newer(app.Version, rel.Version) {
				if app.Version == rel.Version {
					fmt.Fprintf(out, "certifly %s is the latest release.\n", app.Version)
				} else {
					fmt.Fprintf(out, "This is certifly %s; the latest release is %s. Nothing to update.\n", app.Version, rel.Version)
				}
				return nil
			}
			if check {
				fmt.Fprintf(out, "certifly %s is available (this is %s). Run `certifly update` to install it.\n", rel.Version, app.Version)
				return nil
			}
			target, err := update.Executable()
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Updating certifly %s to %s …\n", app.Version, rel.Version)
			if err := update.Install(c, rel, target); err != nil {
				return err
			}
			fmt.Fprintf(out, "Installed certifly %s at %s.\n", rel.Version, target)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only report whether a newer release exists")
	return cmd
}
