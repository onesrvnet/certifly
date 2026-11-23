package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
)

// Errors that end a login.
var (
	ErrDenied  = errors.New("the sign-in was denied in the browser")
	ErrExpired = errors.New("the sign-in link expired; start again")
)

// Pending is a started login: what to show the person while the CLI waits.
type Pending struct {
	api.LoginStart
	verifier string
}

// Start asks the server for a login and returns the code and the browser link.
func Start(ctx context.Context, client *api.Client) (*Pending, error) {
	verifier := randomURLSafe(32)
	sum := sha256.Sum256([]byte(verifier))
	start, err := client.StartLogin(ctx, base64.RawURLEncoding.EncodeToString(sum[:]), ThisMachine())
	if err != nil {
		return nil, err
	}
	if err := CheckBrowserURL(start.BrowserURL, client.BaseURL, client.AllowHTTP); err != nil {
		return nil, err
	}
	if start.IntervalSeconds < 1 {
		start.IntervalSeconds = 2
	}
	return &Pending{LoginStart: start, verifier: verifier}, nil
}

// Wait polls until the login is approved, denied or expired, and returns the session.
func (p *Pending) Wait(ctx context.Context, client *api.Client) (Session, error) {
	interval := time.Duration(p.IntervalSeconds) * time.Second
	for {
		select {
		case <-ctx.Done():
			return Session{}, ctx.Err()
		case <-time.After(interval):
		}
		res, err := client.PollLogin(ctx, p.DeviceCode, p.verifier)
		switch {
		case api.IsCode(err, "slow_down") || api.IsStatus(err, http.StatusTooManyRequests):
			interval += time.Second
			continue
		case api.IsStatus(err, http.StatusForbidden):
			return Session{}, ErrDenied
		case api.IsStatus(err, http.StatusGone):
			return Session{}, ErrExpired
		case err != nil:
			return Session{}, err
		}
		if res.Status == "approved" && res.Token != "" {
			return Session{Server: client.BaseURL, Token: res.Token, ExpiresAt: res.ExpiresAt, User: res.User}, nil
		}
	}
}

// ThisMachine names the computer for the confirm screen in the browser.
func ThisMachine() api.Machine {
	host, _ := os.Hostname()
	return api.Machine{Hostname: host, OS: runtime.GOOS}
}

// CheckBrowserURL accepts the sign-in link only on the server the CLI talks to, over https (or
// http where the server itself is allowed it). The link is opened and shown to the person, so it
// must not lead anywhere else.
func CheckBrowserURL(link, server string, allowHTTP bool) error {
	refused := fmt.Errorf("the server sent a sign-in link for another site: %q", link)
	u, err := url.Parse(link)
	if err != nil || u.User != nil {
		return refused
	}
	s, err := url.Parse(server)
	if err != nil || !strings.EqualFold(u.Host, s.Host) {
		return refused
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && api.CheckScheme(link, allowHTTP) == nil) {
		return refused
	}
	return nil
}

// OpenBrowser opens url in the default browser; false when there is none (a server, an SSH session).
func OpenBrowser(url string) bool {
	if os.Getenv("SSH_CONNECTION") != "" && os.Getenv("DISPLAY") == "" && runtime.GOOS == "linux" {
		return false
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start() == nil
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
