// Package config holds the CLI's settings and its file paths.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Key modes for user certificates.
const (
	// KeyModeAuto uses a throwaway key unless a host group requires a security key.
	KeyModeAuto = "auto"
	// KeyModeSK always uses the security key, also where a throwaway key would do.
	KeyModeSK = "sk"
)

// Config is ~/.config/certifly/config.json.
type Config struct {
	Server string `json:"server"`
	// KeyMode is KeyModeAuto or KeyModeSK.
	KeyMode string `json:"key_mode"`
	// SKKey is the private key handle file of the security key (an ed25519-sk key), if one was made.
	SKKey string `json:"sk_key,omitempty"`
	// SSHIntegration makes plain `ssh` use certifly: an Include in ~/.ssh/config, and the
	// certificates in the person's own ssh-agent. Off, certifly keeps to its own folder and agent.
	SSHIntegration bool `json:"ssh_integration"`
	// SSHIntegrationAsked is set once the person answered the question at the first sign-in.
	SSHIntegrationAsked bool `json:"ssh_integration_asked"`
	// Agent is the ssh-agent socket to use; empty means $SSH_AUTH_SOCK, or the CLI's own agent.
	Agent string `json:"agent,omitempty"`
	// DefaultLogins maps a host group slug to the login picked first.
	DefaultLogins map[string]string `json:"default_logins,omitempty"`
	// Theme is "auto", "light" or "dark".
	Theme string `json:"theme"`
	// AutoRenew renews certificates when the TUI starts and they are close to expiring.
	AutoRenew bool `json:"auto_renew"`
}

// Default is the configuration before anything was set.
func Default() Config {
	return Config{KeyMode: KeyModeAuto, Theme: "auto", AutoRenew: true}
}

// Dir is the CLI's own directory: $XDG_CONFIG_HOME/certifly or ~/.config/certifly.
func Dir() string {
	if dir := os.Getenv("CERTIFLY_CONFIG_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "certifly")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".certifly"
	}
	return filepath.Join(home, ".config", "certifly")
}

// Path is the config file.
func Path() string { return filepath.Join(Dir(), "config.json") }

// Load reads the config, or the defaults when there is none yet.
func Load() (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(Path())
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.KeyMode == "" {
		cfg.KeyMode = KeyModeAuto
	}
	if cfg.Theme == "" {
		cfg.Theme = "auto"
	}
	return cfg, nil
}

// Save writes the config, readable only by its owner.
func (c Config) Save() error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(Path(), append(data, '\n'), 0o600)
}

// NormalizeServer turns "certifly.example" into "https://certifly.example".
func NormalizeServer(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

// WriteFileAtomic writes through a temporary file and a rename, so readers never see half a file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
