package update

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/config"
)

// CheckInterval is how often the TUI looks for a new release.
const CheckInterval = 24 * time.Hour

// CachePath is where the last look for a new release is remembered.
func CachePath() string { return filepath.Join(config.Dir(), "update-check.json") }

type checkCache struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest,omitempty"`
}

// Available returns the newest version when it is newer than current. It asks GitHub at most
// once per CheckInterval and remembers the answer in cachePath; a failed lookup is remembered
// too, so an offline machine does not wait for GitHub on every start. CERTIFLY_NO_UPDATE_CHECK
// turns it off, and development builds never check.
func Available(ctx context.Context, current, cachePath string, now time.Time) (string, bool) {
	if os.Getenv("CERTIFLY_NO_UPDATE_CHECK") != "" || parse(current) == nil {
		return "", false
	}
	var c checkCache
	if data, err := os.ReadFile(cachePath); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	if c.CheckedAt.IsZero() || now.Sub(c.CheckedAt) >= CheckInterval || now.Before(c.CheckedAt) {
		c = checkCache{CheckedAt: now}
		if rel, err := Latest(ctx); err == nil {
			c.Latest = rel.Version
		}
		if data, err := json.Marshal(c); err == nil {
			_ = os.MkdirAll(filepath.Dir(cachePath), 0o700)
			_ = os.WriteFile(cachePath, data, 0o600)
		}
	}
	if c.Latest != "" && Newer(current, c.Latest) {
		return c.Latest, true
	}
	return "", false
}

// Command is what the person runs to update the binary at path.
func Command(path string) string {
	if Managed(path) {
		return "brew upgrade certifly"
	}
	if dir := filepath.Dir(path); !writable(dir) {
		return "sudo certifly update"
	}
	return "certifly update"
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".certifly-update-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}
