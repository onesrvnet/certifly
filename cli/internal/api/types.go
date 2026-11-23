package api

import (
	"context"
	"strings"
	"time"
)

// The shapes of docs/ssh-cli-api.md.

type Machine struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type LoginStart struct {
	LoginID         string    `json:"login_id"`
	DeviceCode      string    `json:"device_code"`
	UserCode        string    `json:"user_code"`
	BrowserURL      string    `json:"browser_url"`
	IntervalSeconds int       `json:"interval_seconds"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type LoginPoll struct {
	Status    string    `json:"status"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

type CA struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// Key policies a host group can set for user certificates.
const (
	KeyPolicyAny        = "any"
	KeyPolicySK         = "sk"
	KeyPolicySKAttested = "sk_attested"
)

type HostGroupAccess struct {
	ID                string   `json:"id"`
	Slug              string   `json:"slug"`
	Name              string   `json:"name"`
	Logins            []string `json:"logins"`
	Principals        []string `json:"principals"`
	KeyPolicy         string   `json:"key_policy"`
	DefaultTTLSeconds int      `json:"default_ttl_seconds"`
	MaxTTLSeconds     int      `json:"max_ttl_seconds"`
	Extensions        []string `json:"extensions"`
	HostPatterns      []string `json:"host_patterns"`
	CA                CA       `json:"ca"`
}

// PrincipalLogin is the local user a principal stands for. Principals are `<slug>:<login>` for
// a login an access rule names, and `<slug>:~<username>` for a person's own username.
func PrincipalLogin(principal string) string {
	_, login, ok := strings.Cut(principal, ":")
	if !ok {
		return principal
	}
	return strings.TrimPrefix(login, "~")
}

// NeedsSK reports whether this host group only signs keys held on a security key.
func (g HostGroupAccess) NeedsSK() bool {
	return g.KeyPolicy == KeyPolicySK || g.KeyPolicy == KeyPolicySKAttested
}

type Access struct {
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
	HostGroups []HostGroupAccess `json:"host_groups"`
}

type HostGroupRef struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type ReachableHost struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Hostnames  []string     `json:"hostnames"`
	HostGroup  HostGroupRef `json:"host_group"`
	Logins     []string     `json:"logins"`
	LastSeenAt *time.Time   `json:"last_seen_at"`
}

type SignRequest struct {
	HostGroupID          string `json:"host_group_id"`
	PublicKey            string `json:"public_key"`
	TTLSeconds           int    `json:"ttl_seconds,omitempty"`
	Attestation          string `json:"attestation,omitempty"`
	AttestationChallenge string `json:"attestation_challenge,omitempty"`
}

type SignedCertificate struct {
	ID          string    `json:"id"`
	Certificate string    `json:"certificate"`
	Serial      string    `json:"serial"`
	KeyID       string    `json:"key_id"`
	Principals  []string  `json:"principals"`
	ValidAfter  time.Time `json:"valid_after"`
	ValidBefore time.Time `json:"valid_before"`
}

type HostPrincipals struct {
	Fixed       map[string][]string `json:"fixed"`
	OwnUsername bool                `json:"own_username"`
}

type HostInfo struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	HostGroup HostGroupRef `json:"host_group"`
}

type HostSync struct {
	Host                HostInfo       `json:"host"`
	Certificates        []string       `json:"certificates"`
	CAPublicKey         string         `json:"ca_public_key"`
	KRLURL              string         `json:"krl_url"`
	Principals          HostPrincipals `json:"principals"`
	SyncIntervalSeconds int            `json:"sync_interval_seconds"`
}

// --- calls ---

func (c *Client) StartLogin(ctx context.Context, codeChallenge string, machine Machine) (LoginStart, error) {
	var out LoginStart
	err := c.Call(ctx, "cli_logins.start", map[string]any{"code_challenge": codeChallenge, "machine": machine}, &out)
	return out, err
}

func (c *Client) PollLogin(ctx context.Context, deviceCode, codeVerifier string) (LoginPoll, error) {
	var out LoginPoll
	err := c.Call(ctx, "cli_logins.poll", map[string]any{"device_code": deviceCode, "code_verifier": codeVerifier}, &out)
	return out, err
}

func (c *Client) Logout(ctx context.Context) error {
	return c.Call(ctx, "cli_sessions.delete", nil, nil)
}

func (c *Client) Access(ctx context.Context) (Access, error) {
	var out Access
	err := c.Call(ctx, "ssh_access.get", nil, &out)
	return out, err
}

// ReachableHosts follows the cursor to the end.
func (c *Client) ReachableHosts(ctx context.Context) ([]ReachableHost, error) {
	var all []ReachableHost
	cursor := ""
	for {
		in := map[string]any{"limit": 500}
		if cursor != "" {
			in["cursor"] = cursor
		}
		var page struct {
			Data       []ReachableHost `json:"data"`
			NextCursor *string         `json:"next_cursor"`
		}
		if err := c.Call(ctx, "ssh_hosts.reachable", in, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = *page.NextCursor
	}
}

func (c *Client) SignUser(ctx context.Context, req SignRequest) (SignedCertificate, error) {
	var out struct {
		Data SignedCertificate `json:"data"`
	}
	err := c.Call(ctx, "ssh_user_certificates.sign", req, &out)
	return out.Data, err
}

func (c *Client) JoinHost(ctx context.Context, token string, hostnames, publicKeys []string) (HostSync, error) {
	var out struct {
		Data HostSync `json:"data"`
	}
	err := c.Call(ctx, "ssh_hosts.join", map[string]any{"token": token, "hostnames": hostnames, "public_keys": publicKeys}, &out)
	return out.Data, err
}

func (c *Client) HostChallenge(ctx context.Context, hostID string) (string, error) {
	var out struct {
		Nonce string `json:"nonce"`
	}
	err := c.Call(ctx, "ssh_hosts.challenge", map[string]any{"host_id": hostID}, &out)
	return out.Nonce, err
}

func (c *Client) SyncHost(ctx context.Context, hostID, nonce, signature string, publicKeys []string) (HostSync, error) {
	var out struct {
		Data HostSync `json:"data"`
	}
	err := c.Call(ctx, "ssh_hosts.sync", map[string]any{"host_id": hostID, "nonce": nonce, "signature": signature, "public_keys": publicKeys}, &out)
	return out.Data, err
}
