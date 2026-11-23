package sshconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"golang.org/x/crypto/ssh"
)

func TestCheckSlug(t *testing.T) {
	for _, ok := range []string{"prod", "web-2", "0a"} {
		if err := CheckSlug(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "Prod", "-x", "a b", "a\nb", "a.b"} {
		if err := CheckSlug(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, _, err := IdentityFiles("../../etc"); err == nil {
		t.Error("IdentityFiles accepted a path")
	}
}

func caKey(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func TestApplyKeepsServerTextOutOfTheConfig(t *testing.T) {
	t.Setenv("CERTIFLY_CONFIG_DIR", t.TempDir())
	good := caKey(t)
	groups := []api.HostGroupAccess{
		{Slug: "prod", Name: "x\nHost *\n  ProxyCommand touch /tmp/pwned", HostPatterns: []string{"*.prod.corp", "evil\n  ProxyCommand x", "a b", "*.ok.corp"}, CA: api.CA{ID: "ca-1", PublicKey: good}},
		{Slug: "../escape", Name: "Escape", HostPatterns: []string{"*.esc.corp"}, CA: api.CA{ID: "ca-2", PublicKey: caKey(t)}},
		{Slug: "badkey", Name: "Bad key", HostPatterns: []string{"*.bad.corp"}, CA: api.CA{ID: "ca-3", PublicKey: good + "\n@cert-authority * " + good}},
	}
	if err := Apply(groups, "/tmp/agent.sock", true, false); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(ConfigPath())
	known, _ := os.ReadFile(KnownHostsPath())
	for _, line := range strings.Split(string(cfg), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ProxyCommand") {
			t.Fatalf("config gained a ProxyCommand:\n%s", cfg)
		}
	}
	if !strings.Contains(string(cfg), "Host *.prod.corp *.ok.corp\n") {
		t.Fatalf("expected only the valid patterns:\n%s", cfg)
	}
	if strings.Contains(string(cfg), "esc.corp") || strings.Contains(string(cfg), "bad.corp") {
		t.Fatalf("host groups with a bad slug or CA key must be left out:\n%s", cfg)
	}
	if got := strings.Count(string(known), "@cert-authority"); got != 1 {
		t.Fatalf("want one @cert-authority line, got %d:\n%s", got, known)
	}
	if !strings.Contains(string(known), "@cert-authority *.prod.corp,*.ok.corp "+good+"\n") {
		t.Fatalf("known_hosts:\n%s", known)
	}
}
