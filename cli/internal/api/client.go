// Package api talks to a certifly server: every call is POST /api/v2/<resource>/<action> with JSON.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/safetext"
)

// Client calls one certifly server, optionally with a CLI session token.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	// UserAgent identifies the CLI and its version.
	UserAgent string
	// AllowHTTP permits plain http to hosts other than this machine (--insecure-http).
	AllowHTTP bool
}

// New returns a client for the server at baseURL. Redirects are never followed for API calls:
// Go would resend the body, which can hold a join token or a device code, to the new address.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		UserAgent: "certifly-cli",
	}
}

// ErrInsecureHTTP refuses plain http: anyone on the path could read the session token, or hand
// a host a CA key of their own.
var ErrInsecureHTTP = errors.New("plain http is refused: use https, or pass --insecure-http to allow it")

// CheckScheme accepts https, and http only for this machine or when allowHTTP is set.
func CheckScheme(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("not a valid URL: %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP || isLoopback(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s: %w", u.Host, ErrInsecureHTTP)
	}
	return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Error is an error answer from the server: `{error: {code, message}}` with its HTTP status.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("the server answered %d", e.Status)
}

// IsCode reports whether err is a server error with the given code.
func IsCode(err error, code string) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// IsStatus reports whether err is a server error with the given HTTP status.
func IsStatus(err error, status int) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.Status == status
}

// Call runs the RPC `method` ("resource.action") with input `in` and decodes the answer into `out`.
func (c *Client) Call(ctx context.Context, method string, in, out any) error {
	resource, action, ok := strings.Cut(method, ".")
	if !ok {
		return fmt.Errorf("bad method %q", method)
	}
	if in == nil {
		in = struct{}{}
	}
	if err := CheckScheme(c.BaseURL, c.AllowHTTP); err != nil {
		return err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v2/%s/%s", c.BaseURL, resource, action), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", c.BaseURL, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return fmt.Errorf("%s answered with a redirect (%d); check the server URL", c.BaseURL, res.StatusCode)
	}
	if res.StatusCode >= 400 {
		var wrapped struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &wrapped)
		return &Error{Status: res.StatusCode, Code: safetext.Clean(wrapped.Error.Code), Message: safetext.Clean(wrapped.Error.Message)}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unexpected answer from %s: %w", c.BaseURL, err)
	}
	// Names and messages from the server end up in the terminal and in config files.
	safetext.CleanAll(out)
	return nil
}

// Get fetches a public file such as the CA key or the KRL, by path or by full URL (the PKI base
// URL can differ from the server URL).
func (c *Client) Get(ctx context.Context, pathOrURL string) ([]byte, error) {
	target := pathOrURL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = c.BaseURL + target
	}
	if err := CheckScheme(target, c.AllowHTTP); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	// A file server may redirect a GET; follow it only on the same host and never to plain http.
	httpClient := *c.HTTP
	httpClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if !strings.EqualFold(next.URL.Hostname(), via[0].URL.Hostname()) {
			return fmt.Errorf("refusing a redirect from %s to %s", via[0].URL.Host, next.URL.Host)
		}
		return CheckScheme(next.URL.String(), c.AllowHTTP)
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach %s: %w", c.BaseURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, &Error{Status: res.StatusCode}
	}
	return io.ReadAll(io.LimitReader(res.Body, 32<<20))
}
