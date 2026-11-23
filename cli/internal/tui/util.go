package tui

import (
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/sshconfig"
)

// fuzzy matches q as a subsequence of s; consecutive and word-start matches score higher.
func fuzzy(q, s string) (int, bool) {
	if q == "" {
		return 0, true
	}
	score, si, run := 0, 0, 0
	for _, qc := range q {
		found := false
		for si < len(s) {
			c := rune(s[si])
			si++
			if c == qc {
				found = true
				run++
				score += 1 + run
				if si == 1 || strings.ContainsRune(" .-_:", rune(s[si-2])) {
					score += 3
				}
				break
			}
			run = 0
		}
		if !found {
			return 0, false
		}
	}
	return score, true
}

// shortDuration prints 3h12m, 45m, 7d.
func shortDuration(d time.Duration) string {
	switch {
	case d <= 0:
		return "expired"
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dm", max(int(d.Minutes()), 1))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func isAuthError(err error) bool {
	var apiErr *api.Error
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized
}

func sshCommand(host, login, hostGroup, socket string) (*exec.Cmd, error) {
	return sshconfig.Command(host, login, hostGroup, socket)
}

func ansiWidth(s string) int { return ansi.StringWidth(s) }
