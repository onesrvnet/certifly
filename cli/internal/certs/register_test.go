package certs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/fake"
)

// skLine is an sk-ssh-ed25519 public key line, as ssh-keygen writes it for a YubiKey.
func skLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	for _, part := range [][]byte{[]byte("sk-ssh-ed25519@openssh.com"), pub, []byte("ssh:certifly")} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(part)))
		blob = append(blob, part...)
	}
	return "sk-ssh-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(blob) + " certifly:sk"
}

func registrationSetup(t *testing.T) (*fake.Server, *api.Client) {
	t.Helper()
	t.Setenv("CERTIFLY_CONFIG_DIR", t.TempDir())
	old := fidoCapable
	fidoCapable = func() bool { return true }
	t.Cleanup(func() { fidoCapable = old })
	srv := fake.New()
	t.Cleanup(srv.Close)
	return srv, api.New(srv.URL, "cfc_test")
}

// makeKey stands in for ssh-keygen: it writes the key handle, the public key and an attestation.
func makeKey(t *testing.T, reg *Registration) string {
	t.Helper()
	line := skLine(t)
	for name, data := range map[string]string{reg.Path: "handle", reg.Path + ".pub": line + "\n", reg.Path + ".attestation": "attestation"} {
		if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return line
}

func TestRegistrationUsesTheServerChallengeAndInstallsTheKeyOnApproval(t *testing.T) {
	srv, client := registrationSetup(t)
	ctx := context.Background()
	// A key from before stays usable until the new one is approved.
	current := filepath.Join(config.Dir(), keyFileName)
	_ = os.MkdirAll(config.Dir(), 0o700)
	_ = os.WriteFile(current, []byte("old handle"), 0o600)
	_ = os.WriteFile(current+".challenge", []byte("old challenge"), 0o600)

	reg, keygen, err := StartRegistration(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := os.ReadFile(reg.Path + ".challenge")
	if err != nil || len(challenge) != 32 || base64.StdEncoding.EncodeToString(challenge) != reg.Challenge {
		t.Fatalf("challenge file = %x, %v", challenge, err)
	}
	if !slices.Contains(keygen.Args, "challenge="+reg.Path+".challenge") || !slices.Contains(keygen.Args, "write-attestation="+reg.Path+".attestation") || keygen.Args[len(keygen.Args)-1] != reg.Path {
		t.Fatalf("ssh-keygen %v", keygen.Args)
	}
	if got, _ := os.ReadFile(current); string(got) != "old handle" {
		t.Fatal("starting a registration touched the current key")
	}

	line := makeKey(t, reg)
	if err := reg.Submit(ctx, client, ""); err != nil {
		t.Fatal(err)
	}
	if reg.Model() != "YubiKey 5 Series" || reg.Upload.UserCode != "KXTP-MZRL" {
		t.Fatalf("upload = %+v", reg.Upload)
	}
	key, path, err := reg.Wait(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if path != current || key.ID != "k-1" {
		t.Fatalf("installed %q, key %+v", path, key)
	}
	if got, _ := os.ReadFile(path + ".pub"); strings.TrimSpace(string(got)) != line {
		t.Fatalf("public key = %q", got)
	}
	for _, f := range []string{reg.Path, reg.Path + ".pub", reg.Path + ".challenge", reg.Path + ".attestation", current + ".challenge"} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s was left behind", f)
		}
	}

	// The prod host group now signs the registered key, and refuses another YubiKey.
	if _, err := signSK(ctx, client, "hg-prod", line); err != nil {
		t.Fatal(err)
	}
	if _, err := signSK(ctx, client, "hg-prod", skLine(t)); !errors.Is(err, ErrKeyNotRegistered) {
		t.Fatalf("unregistered key: %v", err)
	}
	if len(srv.Registered) != 1 {
		t.Fatalf("registered %v", srv.Registered)
	}
}

func TestDeniedRegistrationLeavesTheCurrentKey(t *testing.T) {
	srv, client := registrationSetup(t)
	srv.DenyKey = true
	ctx := context.Background()
	current := filepath.Join(config.Dir(), keyFileName)
	_ = os.MkdirAll(config.Dir(), 0o700)
	_ = os.WriteFile(current, []byte("old handle"), 0o600)

	reg, _, err := StartRegistration(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	makeKey(t, reg)
	if err := reg.Submit(ctx, client, "backup"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.Wait(ctx, client); !errors.Is(err, ErrRegistrationDenied) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := os.ReadFile(current); string(got) != "old handle" {
		t.Fatal("a denied registration replaced the key")
	}
	if _, err := os.Stat(reg.Path + ".pub"); err == nil {
		t.Fatal("the denied key was left behind")
	}
}

func TestExpiredRegistrationIsDiscarded(t *testing.T) {
	_, client := registrationSetup(t)
	reg, _, err := StartRegistration(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	makeKey(t, reg)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(50*time.Millisecond))
	defer cancel()
	if _, _, err := reg.Wait(ctx, client); !errors.Is(err, ErrRegistrationExpired) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(reg.Path); err == nil {
		t.Fatal("the expired key was left behind")
	}
}

func TestRegistrationRefusesAPlainKey(t *testing.T) {
	_, client := registrationSetup(t)
	reg, _, err := StartRegistration(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(reg.Path+".pub", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"), 0o600)
	if err := reg.Submit(context.Background(), client, ""); !api.IsCode(err, "ssh_key_type") {
		t.Fatalf("err = %v", err)
	}
}
