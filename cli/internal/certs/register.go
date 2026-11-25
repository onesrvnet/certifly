package certs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/session"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
)

// Errors that end a security key registration.
var (
	ErrRegistrationDenied  = errors.New("the YubiKey registration was denied in the browser")
	ErrRegistrationExpired = errors.New("the YubiKey registration expired; start again")
)

// fidoCapable is sshbin.FIDOCapable; tests replace it.
var fidoCapable = sshbin.FIDOCapable

// keyFileName is the YubiKey key handle in the config folder.
const keyFileName = "id_ed25519_sk"

// Registration is a security key registration in progress. The new key is made next to the
// current one and only replaces it once the person approved it, so a denied or expired
// registration leaves the current key as it was.
type Registration struct {
	api.SecurityKeyEnrollment
	// Path is where ssh-keygen writes the new key handle.
	Path   string
	Upload api.SecurityKeyUpload
}

// StartRegistration asks the server for a challenge and returns the ssh-keygen command that makes
// the new key with it. Run the command with the terminal attached: the person touches the
// YubiKey and may be asked for its PIN.
func StartRegistration(ctx context.Context, client *api.Client) (*Registration, *exec.Cmd, error) {
	if !fidoCapable() {
		return nil, nil, sshbin.ErrNoFIDO
	}
	start, err := client.StartSecurityKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := session.CheckBrowserURL(start.BrowserURL, client.BaseURL, client.AllowHTTP); err != nil {
		return nil, nil, err
	}
	challenge, err := base64.StdEncoding.DecodeString(start.Challenge)
	if err != nil || len(challenge) != 32 {
		return nil, nil, errors.New("the server sent an unusable challenge")
	}
	if start.IntervalSeconds < 1 {
		start.IntervalSeconds = 2
	}
	dir := config.Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	r := &Registration{SecurityKeyEnrollment: start, Path: filepath.Join(dir, keyFileName+".new")}
	r.Discard()
	if err := config.WriteFileAtomic(r.Path+".challenge", challenge, 0o600); err != nil {
		return nil, nil, err
	}
	cmd := sshbin.Command("ssh-keygen", "-t", "ed25519-sk", "-O", "application=ssh:certifly", "-O", "challenge="+r.Path+".challenge",
		"-O", "write-attestation="+r.Path+".attestation", "-N", "", "-C", "certifly:sk", "-f", r.Path)
	return r, cmd, nil
}

// Submit uploads the new key and its attestation. An empty name lets the server use the
// machine's host name.
func (r *Registration) Submit(ctx context.Context, client *api.Client, name string) error {
	pub, err := os.ReadFile(r.Path + ".pub")
	if err != nil {
		return fmt.Errorf("no key was written: %w", err)
	}
	attestation := ""
	if data, err := os.ReadFile(r.Path + ".attestation"); err == nil && len(data) > 0 {
		attestation = base64.StdEncoding.EncodeToString(data)
	}
	upload, err := client.SubmitSecurityKey(ctx, r.EnrollmentID, strings.TrimSpace(string(pub)), attestation, name)
	if err != nil {
		return err
	}
	r.Upload = upload
	return nil
}

// Wait polls until the person approved the key, then puts it in place of the current one and
// returns the registered key and its path. Denied, expired and cancelled registrations are discarded.
func (r *Registration) Wait(ctx context.Context, client *api.Client) (api.SecurityKey, string, error) {
	interval := time.Duration(r.IntervalSeconds) * time.Second
	for {
		select {
		case <-ctx.Done():
			r.Discard()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return api.SecurityKey{}, "", ErrRegistrationExpired
			}
			return api.SecurityKey{}, "", ctx.Err()
		case <-time.After(interval):
		}
		res, err := client.PollSecurityKey(ctx, r.EnrollmentID)
		switch {
		case api.IsStatus(err, http.StatusTooManyRequests):
			interval += time.Second
			continue
		case api.IsCode(err, "ssh_key_enrollment_denied") || api.IsStatus(err, http.StatusForbidden):
			r.Discard()
			return api.SecurityKey{}, "", ErrRegistrationDenied
		case api.IsCode(err, "ssh_key_enrollment_expired") || api.IsStatus(err, http.StatusGone) || api.IsStatus(err, http.StatusNotFound):
			r.Discard()
			return api.SecurityKey{}, "", ErrRegistrationExpired
		case err != nil:
			if ctx.Err() != nil {
				continue
			}
			r.Discard()
			return api.SecurityKey{}, "", err
		}
		if res.Status == "approved" {
			path, err := r.install()
			return res.Key, path, err
		}
	}
}

// install moves the approved key into place. The challenge and attestation are not needed any more.
func (r *Registration) install() (string, error) {
	final := filepath.Join(filepath.Dir(r.Path), keyFileName)
	for _, f := range []string{final + ".challenge", final + ".attestation"} {
		_ = os.Remove(f)
	}
	if err := os.Rename(r.Path, final); err != nil {
		return "", err
	}
	if err := os.Rename(r.Path+".pub", final+".pub"); err != nil {
		return "", err
	}
	r.Discard()
	return final, nil
}

// Discard removes the files of an unfinished registration.
func (r *Registration) Discard() {
	for _, f := range []string{r.Path, r.Path + ".pub", r.Path + ".challenge", r.Path + ".attestation"} {
		_ = os.Remove(f)
	}
}

// Model describes the uploaded key for the person: the YubiKey model, or that it is not attested.
func (r *Registration) Model() string {
	if r.Upload.Attested {
		if r.Upload.Model != "" {
			return r.Upload.Model
		}
		return "YubiKey"
	}
	return ""
}
