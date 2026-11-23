// Package session keeps the CLI session token: in the OS keychain, or in a 0600 file where there is none.
package session

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/zalando/go-keyring"
)

const keyringService = "certifly"

// Session is a signed-in CLI: the token and who it belongs to.
type Session struct {
	Server    string    `json:"server"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      api.User  `json:"user"`
}

// Valid reports whether the session can still be used for a while.
func (s *Session) Valid() bool {
	return s != nil && s.Token != "" && time.Until(s.ExpiresAt) > time.Minute
}

func filePath() string { return filepath.Join(config.Dir(), "session.json") }

// useFile is set when the keychain is not available (headless Linux) or by CERTIFLY_SESSION_FILE=1.
func useFile() bool { return os.Getenv("CERTIFLY_SESSION_FILE") == "1" }

// Load returns the session for server, or nil when there is none.
func Load(server string) (*Session, error) {
	var data []byte
	if !useFile() {
		secret, err := keyring.Get(keyringService, server)
		switch {
		case err == nil:
			data = []byte(secret)
		case errors.Is(err, keyring.ErrNotFound):
			// Maybe stored in the file before a keychain was available.
		default:
			// No usable keychain here: fall back to the file.
		}
	}
	if data == nil {
		raw, err := os.ReadFile(filePath())
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		data = raw
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil || s.Server != server {
		return nil, nil
	}
	return &s, nil
}

// Save stores the session, in the keychain when it works, otherwise in the file.
func Save(s Session) (where string, err error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if !useFile() {
		if err := keyring.Set(keyringService, s.Server, string(data)); err == nil {
			_ = os.Remove(filePath())
			return "keychain", nil
		}
	}
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		return "", err
	}
	return filePath(), config.WriteFileAtomic(filePath(), data, 0o600)
}

// Delete forgets the session for server everywhere it may be stored.
func Delete(server string) error {
	_ = keyring.Delete(keyringService, server)
	err := os.Remove(filePath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
