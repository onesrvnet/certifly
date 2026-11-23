package host_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/host"
)

func TestOwnUsernameHasItsOwnNamespace(t *testing.T) {
	p := host.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(p.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	file := host.PrincipalsFile{HostGroupSlug: "prod", HostPrincipals: api.HostPrincipals{Fixed: map[string][]string{"deploy": {"prod:deploy"}}, OwnUsername: true}}
	data, _ := json.Marshal(file)
	if err := os.WriteFile(filepath.Join(p.Principals()), data, 0o644); err != nil {
		t.Fatal(err)
	}
	defer host.SetRegularAccount(func(string) bool { return true })()

	got, err := host.Principals(p, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	// The fixed login and a person whose username is "deploy" stay apart.
	if !slices.Equal(got, []string{"prod:deploy", "prod:~deploy"}) {
		t.Fatalf("deploy: %v", got)
	}
	got, _ = host.Principals(p, "alice")
	if !slices.Equal(got, []string{"prod:~alice"}) {
		t.Fatalf("alice: %v", got)
	}

	defer host.SetRegularAccount(func(string) bool { return false })()
	got, _ = host.Principals(p, "alice")
	if len(got) != 0 {
		t.Fatalf("system account got %v", got)
	}
}

func TestPrincipalLogin(t *testing.T) {
	for in, want := range map[string]string{"prod:root": "root", "prod:~alice": "alice", "plain": "plain"} {
		if got := api.PrincipalLogin(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
