// Command fakeserver runs the in-memory certifly server, to try the TUI without a real one:
//
//	go run ./internal/fake/cmd/fakeserver
//	CERTIFLY_CONFIG_DIR=/tmp/certifly-try go run . login --server <printed URL>
package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/onesrvnet/certifly/cli/internal/fake"
)

func main() {
	srv := fake.New()
	defer srv.Close()
	fmt.Println("fake certifly at", srv.URL)
	fmt.Println("logins are approved after the first poll; the prod host group requires a YubiKey key")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
