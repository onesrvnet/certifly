// Package certs gets SSH user certificates signed and loads them into the agent: one per host group.
package certs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/sshagent"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
	"github.com/onesrvnet/certifly/cli/internal/sshconfig"
	"golang.org/x/crypto/ssh"
)

// ErrNoSecurityKey means a host group needs a security key and none is set up yet.
var ErrNoSecurityKey = errors.New("this host group needs a YubiKey key; register one with `certifly yubikey` or in Settings → YubiKey")

// ErrKeyNotRegistered means the host group only signs registered YubiKeys and this one is not.
var ErrKeyNotRegistered = errors.New("this host group only accepts registered YubiKeys; register yours with `certifly yubikey` or in Settings → YubiKey")

// ErrKeyRevoked means the YubiKey key was revoked; it is never signed again.
var ErrKeyRevoked = errors.New("this YubiKey key was revoked; register a new one with `certifly yubikey` or in Settings → YubiKey")

// Result is the outcome for one host group.
type Result struct {
	HostGroup   api.HostGroupAccess
	Principals  []string
	ValidBefore time.Time
	// UsesSK is true when the certificate is for the security key.
	UsesSK bool
	Err    error
}

// UsesSK reports whether a host group's certificate goes on the security key.
func UsesSK(cfg config.Config, g api.HostGroupAccess) bool {
	return g.NeedsSK() || (cfg.KeyMode == config.KeyModeSK && cfg.SKKey != "")
}

// Mint gets one certificate for a host group and loads it into the agent.
func Mint(ctx context.Context, client *api.Client, ag *sshagent.Agent, cfg config.Config, g api.HostGroupAccess) Result {
	res := Result{HostGroup: g, UsesSK: UsesSK(cfg, g)}
	// The slug names the key and certificate files.
	if res.Err = sshconfig.CheckSlug(g.Slug); res.Err != nil {
		return res
	}
	if res.UsesSK {
		res.Principals, res.ValidBefore, res.Err = mintSK(ctx, client, ag, cfg, g)
	} else {
		res.Principals, res.ValidBefore, res.Err = mintThrowaway(ctx, client, ag, g)
	}
	return res
}

func mintThrowaway(ctx context.Context, client *api.Client, ag *sshagent.Agent, g api.HostGroupAccess) ([]string, time.Time, error) {
	priv, pub, err := sshagent.NewThrowawayKey()
	if err != nil {
		return nil, time.Time{}, err
	}
	signed, err := client.SignUser(ctx, api.SignRequest{HostGroupID: g.ID, PublicKey: string(ssh.MarshalAuthorizedKey(pub))})
	if err != nil {
		return nil, time.Time{}, err
	}
	cert, err := parseCertificate(signed.Certificate)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := ag.AddCertificate(g.Slug, priv, cert); err != nil {
		return nil, time.Time{}, err
	}
	if err := sshconfig.WriteIdentity(g.Slug, string(ssh.MarshalAuthorizedKey(pub)), signed.Certificate); err != nil {
		return nil, time.Time{}, err
	}
	return cert.ValidPrincipals, time.Unix(int64(cert.ValidBefore), 0), nil
}

func mintSK(ctx context.Context, client *api.Client, ag *sshagent.Agent, cfg config.Config, g api.HostGroupAccess) ([]string, time.Time, error) {
	if !sshbin.FIDOCapable() {
		return nil, time.Time{}, sshbin.ErrNoFIDO
	}
	if cfg.SKKey == "" {
		return nil, time.Time{}, ErrNoSecurityKey
	}
	pubLine, err := os.ReadFile(cfg.SKKey + ".pub")
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("cannot read the YubiKey public key: %w", err)
	}
	signed, err := signSK(ctx, client, g.ID, string(pubLine))
	if err != nil {
		return nil, time.Time{}, err
	}
	cert, err := parseCertificate(signed.Certificate)
	if err != nil {
		return nil, time.Time{}, err
	}
	// ssh-add reads <key> and <key>-cert.pub; one copy of the key handle per host group keeps their
	// certificates apart, and its comment marks it as certifly's.
	dir := filepath.Join(config.Dir(), "sk")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, time.Time{}, err
	}
	keyFile := filepath.Join(dir, g.Slug)
	handle, err := os.ReadFile(cfg.SKKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := config.WriteFileAtomic(keyFile, handle, 0o600); err != nil {
		return nil, time.Time{}, err
	}
	if err := config.WriteFileAtomic(keyFile+".pub", pubLine, 0o644); err != nil {
		return nil, time.Time{}, err
	}
	if err := config.WriteFileAtomic(keyFile+"-cert.pub", []byte(strings.TrimSpace(signed.Certificate)+"\n"), 0o644); err != nil {
		return nil, time.Time{}, err
	}
	if out, err := sshbin.Command("ssh-keygen", "-c", "-C", sshagent.CommentPrefix+g.Slug, "-f", keyFile).CombinedOutput(); err != nil {
		return nil, time.Time{}, fmt.Errorf("ssh-keygen -c: %s", strings.TrimSpace(string(out)))
	}
	ag.RemoveHostGroup(g.Slug)
	life := time.Until(time.Unix(int64(cert.ValidBefore), 0))
	if err := ag.AddKeyFile(keyFile, life); err != nil {
		return nil, time.Time{}, err
	}
	if err := sshconfig.WriteIdentity(g.Slug, string(pubLine), signed.Certificate); err != nil {
		return nil, time.Time{}, err
	}
	return cert.ValidPrincipals, time.Unix(int64(cert.ValidBefore), 0), nil
}

// signSK asks the server to sign the YubiKey's public key, with the refusals about the key itself
// turned into errors the TUI can explain.
func signSK(ctx context.Context, client *api.Client, hostGroupID, pubLine string) (api.SignedCertificate, error) {
	signed, err := client.SignUser(ctx, api.SignRequest{HostGroupID: hostGroupID, PublicKey: strings.TrimSpace(pubLine)})
	switch {
	case api.IsCode(err, "ssh_key_not_registered"):
		return signed, ErrKeyNotRegistered
	case api.IsCode(err, "ssh_key_revoked"):
		return signed, ErrKeyRevoked
	}
	return signed, err
}

func parseCertificate(line string) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("the server sent an unreadable certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("the server sent a key instead of a certificate")
	}
	return cert, nil
}
