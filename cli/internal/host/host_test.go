package host_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/fake"
	"github.com/onesrvnet/certifly/cli/internal/host"
	"golang.org/x/crypto/ssh"
)

// fakeRoot builds /etc/ssh with an Ed25519 host key under a temporary root.
func fakeRoot(t *testing.T) host.Paths {
	t.Helper()
	root := t.TempDir()
	sshDir := filepath.Join(root, "etc", "ssh")
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sshDir, "ssh_host_ed25519_key"), pem.EncodeToMemory(block), 0o600)
	signer, _ := ssh.NewSignerFromKey(priv)
	_ = os.WriteFile(filepath.Join(sshDir, "ssh_host_ed25519_key.pub"), ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644)
	_ = os.WriteFile(filepath.Join(sshDir, "sshd_config"), []byte("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"), 0o644)
	return host.Paths{Root: root}
}

func TestJoinSyncAndPrincipals(t *testing.T) {
	p := fakeRoot(t)
	srv := fake.New()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var steps []string
	report := func(s host.Step) { steps = append(steps, s.Text) }

	if _, err := host.Join(ctx, p, srv.URL, "wrong", []string{"web-01.prod.corp"}, true, false, report); err == nil {
		t.Fatal("a wrong join token must fail")
	}
	state, err := host.Join(ctx, p, srv.URL, "cfj_test", []string{"web-01.prod.corp", "web-01"}, true, false, report)
	if err != nil {
		t.Fatal(err)
	}
	if state.HostID != "host-1" || state.HostGroup.Slug != "prod" {
		t.Fatalf("state: %+v", state)
	}

	cert, err := os.ReadFile(filepath.Join(p.SSHDir(), "ssh_host_ed25519_key-cert.pub"))
	if err != nil || !strings.HasPrefix(string(cert), "ssh-ed25519-cert-v01@openssh.com ") {
		t.Fatalf("host certificate: %v %s", err, cert)
	}
	dropIn, _ := os.ReadFile(p.DropIn())
	for _, want := range []string{"TrustedUserCAKeys " + p.CA(), "RevokedKeys " + p.KRL(), "HostCertificate " + filepath.Join(p.SSHDir(), "ssh_host_ed25519_key-cert.pub"), "host principals %u", "AuthorizedPrincipalsCommandUser nobody"} {
		if !strings.Contains(string(dropIn), want) {
			t.Fatalf("drop-in lacks %q:\n%s", want, dropIn)
		}
	}
	for _, f := range []string{p.CA(), p.KRL(), p.Principals(), p.Timer(), p.Service()} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("missing %s", f)
		}
	}
	if fi, _ := os.Stat(p.Principals()); fi.Mode().Perm() != 0o644 {
		t.Fatalf("principals must be readable by nobody: %v", fi.Mode())
	}

	// Fixed logins work for any account; root never gets an own-username principal.
	got, err := host.Principals(p, "root")
	if err != nil || strings.Join(got, ",") != "prod:root" {
		t.Fatalf("root: %v %v", got, err)
	}
	if got, _ := host.Principals(p, "nobody"); len(got) != 0 {
		t.Fatalf("nobody: %v", got)
	}
	if got, _ := host.Principals(p, "no-such-user-xyz"); len(got) != 0 {
		t.Fatalf("unknown user: %v", got)
	}

	// Sync proves the host key with a signature over the server's nonce.
	if _, err := host.Sync(ctx, p, false, report); err != nil {
		t.Fatal(err)
	}
	st := host.ReadStatus(p)
	if st.State == nil || len(st.Certificates) != 1 || time.Until(st.Certificates[0].ValidBefore) < 80*24*time.Hour || !st.Includes {
		t.Fatalf("status: %+v", st)
	}

	if err := host.Uninstall(p); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.DropIn(), p.Timer(), p.Principals(), filepath.Join(p.SSHDir(), "ssh_host_ed25519_key-cert.pub")} {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("%s still there after uninstall", f)
		}
	}
}

// The signature must be what `ssh-keygen -Y` produces and accepts.
func TestSSHSIGVerifiesWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	message := []byte("nonce-abc_DEF-123")
	sig, err := host.SignSSHSIG(signer, host.Namespace, message)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sigFile := filepath.Join(dir, "msg.sig")
	_ = os.WriteFile(sigFile, []byte(sig), 0o644)
	allowed := filepath.Join(dir, "allowed")
	_ = os.WriteFile(allowed, []byte("host@test "+string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), 0o644)
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "host@test", "-n", host.Namespace, "-s", sigFile)
	cmd.Stdin = strings.NewReader(string(message))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, out)
	}
	// A wrong namespace must not verify.
	cmd = exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "host@test", "-n", "other@x", "-s", sigFile)
	cmd.Stdin = strings.NewReader(string(message))
	if err := cmd.Run(); err == nil {
		t.Fatal("verified under another namespace")
	}
}

func TestDefaultPathsAreAbsolute(t *testing.T) {
	t.Setenv("CERTIFLY_HOST_ROOT", "")
	p := host.DefaultPaths()
	for _, path := range []string{p.CA(), p.KRL(), p.DropIn(), p.State(), p.Principals()} {
		if !filepath.IsAbs(path) {
			t.Fatalf("%s is not absolute", path)
		}
	}
	if p.CA() != "/etc/ssh/certifly/ca.pub" {
		t.Fatalf("CA path %s", p.CA())
	}
}
