// Command certifly is the certifly CLI: SSH certificates for people, and host setup for servers.
package main

import (
	"os"

	"github.com/onesrvnet/certifly/cli/internal/cmd"
)

func main() { os.Exit(cmd.Execute()) }
