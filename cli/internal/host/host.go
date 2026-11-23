// Package host is the server side of the CLI: join a host group, keep the host certificate, CA key,
// KRL and principals current, and wire them into sshd.
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"golang.org/x/crypto/ssh"
)

// Paths on the host. Root can override them for tests with CERTIFLY_HOST_ROOT.
type Paths struct {
	Root string
}

// join builds an absolute path under Root, or under / on a real host: sshd needs absolute paths.
func (p Paths) join(parts ...string) string {
	root := p.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func (p Paths) SSHDir() string     { return p.join("etc", "ssh") }
func (p Paths) Dir() string        { return p.join("etc", "ssh", "certifly") }
func (p Paths) State() string      { return p.join("etc", "certifly", "host.json") }
func (p Paths) CA() string         { return filepath.Join(p.Dir(), "ca.pub") }
func (p Paths) KRL() string        { return filepath.Join(p.Dir(), "revoked.krl") }
func (p Paths) Principals() string { return filepath.Join(p.Dir(), "principals.json") }
func (p Paths) DropIn() string     { return p.join("etc", "ssh", "sshd_config.d", "50-certifly.conf") }
func (p Paths) SSHDConfig() string { return p.join("etc", "ssh", "sshd_config") }
func (p Paths) SystemdDir() string { return p.join("etc", "systemd", "system") }
func (p Paths) Service() string    { return filepath.Join(p.SystemdDir(), "certifly-host.service") }
func (p Paths) Timer() string      { return filepath.Join(p.SystemdDir(), "certifly-host.timer") }
func (p Paths) CertFor(keyFile string) string {
	return strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"
}

// DefaultPaths are the real system paths.
func DefaultPaths() Paths { return Paths{Root: os.Getenv("CERTIFLY_HOST_ROOT")} }

// State is /etc/certifly/host.json: which server and host this machine is.
type State struct {
	Server     string           `json:"server"`
	HostID     string           `json:"host_id"`
	Name       string           `json:"name"`
	HostGroup  api.HostGroupRef `json:"host_group"`
	Hostnames  []string         `json:"hostnames"`
	LastSyncAt time.Time        `json:"last_sync_at"`
	LastError  string           `json:"last_error,omitempty"`
	KRLURL     string           `json:"krl_url"`
	KRLAt      time.Time        `json:"krl_at"`
	Interval   int              `json:"sync_interval_seconds"`
	// InsecureHTTP records that the host joined with --insecure-http, so the timer's syncs keep
	// working against the same plain-http server.
	InsecureHTTP bool `json:"insecure_http,omitempty"`
}

// PrincipalsFile is what `certifly host principals` reads; sshd runs it as nobody, so it is
// world-readable and holds nothing secret.
type PrincipalsFile struct {
	HostGroupSlug string `json:"host_group_slug"`
	api.HostPrincipals
}

// HostKey is one of the host's SSH keys.
type HostKey struct {
	PublicFile  string
	PrivateFile string
	Public      ssh.PublicKey
}

// HostKeys finds the host's keys in /etc/ssh (DSA is ignored; certifly refuses it).
func HostKeys(p Paths) ([]HostKey, error) {
	matches, err := filepath.Glob(filepath.Join(p.SSHDir(), "ssh_host_*_key.pub"))
	if err != nil {
		return nil, err
	}
	var keys []HostKey
	for _, pubFile := range matches {
		if strings.Contains(pubFile, "_dsa_") {
			continue
		}
		data, err := os.ReadFile(pubFile)
		if err != nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			continue
		}
		keys = append(keys, HostKey{PublicFile: pubFile, PrivateFile: strings.TrimSuffix(pubFile, ".pub"), Public: pub})
	}
	// Ed25519 first: it signs the challenges.
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].Public.Type() == ssh.KeyAlgoED25519 && keys[j].Public.Type() != ssh.KeyAlgoED25519
	})
	if len(keys) == 0 {
		return nil, fmt.Errorf("no SSH host keys found in %s; is OpenSSH server installed?", p.SSHDir())
	}
	return keys, nil
}

// DetectHostnames suggests the names to register: the FQDN and the short host name.
func DetectHostnames() []string {
	short, _ := os.Hostname()
	names := []string{}
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		if fqdn := strings.TrimSpace(string(out)); fqdn != "" && fqdn != "localhost" {
			names = append(names, fqdn)
		}
	}
	if short != "" && (len(names) == 0 || names[0] != short) {
		names = append(names, short)
	}
	return names
}

func publicLines(keys []HostKey) []string {
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.Public)))
	}
	return lines
}

// LoadState reads the host state; nil when the host has not joined.
func LoadState(p Paths) (*State, error) {
	data, err := os.ReadFile(p.State())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	return &s, json.Unmarshal(data, &s)
}

func saveState(p Paths, s State) error {
	if err := os.MkdirAll(filepath.Dir(p.State()), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	return config.WriteFileAtomic(p.State(), append(data, '\n'), 0o600)
}

// Step is progress reported to the person while joining or syncing.
type Step struct {
	Text string
	Err  error
}

// Join spends a join token and sets the host up: certificates, CA, KRL, principals, sshd config and
// the timer. report receives each step as it finishes. Plain http is refused unless insecureHTTP:
// whoever sits on the path could otherwise install a CA key of their own.
func Join(ctx context.Context, p Paths, server, token string, hostnames []string, install, insecureHTTP bool, report func(Step)) (*State, error) {
	if runtime.GOOS != "linux" && p.Root == "" {
		return nil, errors.New("host mode runs on Linux servers")
	}
	keys, err := HostKeys(p)
	if err != nil {
		return nil, err
	}
	client := api.New(config.NormalizeServer(server), "")
	client.AllowHTTP = insecureHTTP
	sync, err := client.JoinHost(ctx, token, hostnames, publicLines(keys))
	if err != nil {
		return nil, err
	}
	report(Step{Text: fmt.Sprintf("Joined host group %s as %s", sync.Host.HostGroup.Name, sync.Host.Name)})
	state := State{Server: client.BaseURL, HostID: sync.Host.ID, Name: sync.Host.Name, HostGroup: sync.Host.HostGroup, Hostnames: hostnames, InsecureHTTP: insecureHTTP}
	if _, err := apply(ctx, p, client, &state, sync, keys, report); err != nil {
		return &state, err
	}
	if install {
		if err := Install(p, report); err != nil {
			return &state, err
		}
	}
	return &state, saveState(p, state)
}

// Sync proves the host's identity with its host key, then refreshes everything. sshd is reloaded
// only when a host certificate or the config changed. Plain http needs insecureHTTP, or a join
// that allowed it.
func Sync(ctx context.Context, p Paths, insecureHTTP bool, report func(Step)) (*State, error) {
	state, err := LoadState(p)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("this host has not joined certifly yet: run `certifly host join <token>`")
	}
	keys, err := HostKeys(p)
	if err != nil {
		return state, err
	}
	client := api.New(state.Server, "")
	client.AllowHTTP = insecureHTTP || state.InsecureHTTP
	fail := func(err error) (*State, error) {
		state.LastError = err.Error()
		_ = saveState(p, *state)
		return state, err
	}
	nonce, err := client.HostChallenge(ctx, state.HostID)
	if err != nil {
		return fail(err)
	}
	signer, err := loadSigner(keys[0].PrivateFile)
	if err != nil {
		return fail(err)
	}
	signature, err := SignSSHSIG(signer, Namespace, []byte(nonce))
	if err != nil {
		return fail(err)
	}
	sync, err := client.SyncHost(ctx, state.HostID, nonce, signature, publicLines(keys))
	if err != nil {
		return fail(err)
	}
	changed, err := apply(ctx, p, client, state, sync, keys, report)
	if err != nil {
		return fail(err)
	}
	if changed {
		if err := ReloadSSHD(p); err != nil {
			return fail(err)
		}
		report(Step{Text: "sshd reloaded"})
	}
	state.LastError = ""
	return state, saveState(p, *state)
}

func loadSigner(privateFile string) (ssh.Signer, error) {
	data, err := os.ReadFile(privateFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read the host key (run as root): %w", err)
	}
	return ssh.ParsePrivateKey(data)
}

// apply writes what the server sent; it reports whether sshd needs a reload.
func apply(ctx context.Context, p Paths, client *api.Client, state *State, sync api.HostSync, keys []HostKey, report func(Step)) (bool, error) {
	if err := os.MkdirAll(p.Dir(), 0o755); err != nil {
		return false, err
	}
	changed := false
	for _, line := range sync.Certificates {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return false, fmt.Errorf("the server sent an unreadable host certificate: %w", err)
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			continue
		}
		for _, k := range keys {
			if bytes.Equal(cert.Key.Marshal(), k.Public.Marshal()) {
				dest := p.CertFor(k.PublicFile)
				old, _ := os.ReadFile(dest)
				data := []byte(strings.TrimSpace(line) + "\n")
				if !bytes.Equal(old, data) {
					if err := config.WriteFileAtomic(dest, data, 0o644); err != nil {
						return false, err
					}
					changed = true
					report(Step{Text: fmt.Sprintf("Host certificate for %s valid %s", k.Public.Type(), time.Until(time.Unix(int64(cert.ValidBefore), 0)).Round(time.Hour))})
				}
			}
		}
	}
	// sshd trusts every key in this file for user logins, so it must be exactly one plain key.
	caKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(sync.CAPublicKey)))
	if err != nil || len(rest) > 0 {
		return false, errors.New("the server sent an unreadable CA key")
	}
	if _, isCert := caKey.(*ssh.Certificate); isCert {
		return false, errors.New("the server sent a certificate instead of a CA key")
	}
	if err := writeIfChanged(p.CA(), ssh.MarshalAuthorizedKey(caKey), 0o644); err != nil {
		return false, err
	}
	principals, _ := json.MarshalIndent(PrincipalsFile{HostGroupSlug: sync.Host.HostGroup.Slug, HostPrincipals: sync.Principals}, "", "  ")
	if err := writeIfChanged(p.Principals(), append(principals, '\n'), 0o644); err != nil {
		return false, err
	}
	if krl, err := client.Get(ctx, sync.KRLURL); err == nil {
		if err := writeIfChanged(p.KRL(), krl, 0o644); err != nil {
			return false, err
		}
		state.KRLAt = time.Now()
	} else if _, statErr := os.Stat(p.KRL()); statErr != nil {
		// sshd refuses every certificate when RevokedKeys points to a missing file.
		return false, fmt.Errorf("cannot fetch the KRL: %w", err)
	} else {
		report(Step{Text: "KRL fetch failed; keeping the previous one", Err: err})
	}
	state.HostGroup, state.Name, state.KRLURL, state.Interval = sync.Host.HostGroup, sync.Host.Name, sync.KRLURL, sync.SyncIntervalSeconds
	state.LastSyncAt = time.Now()
	dropChanged, err := writeDropIn(p, keys)
	if err != nil {
		return false, err
	}
	return changed || dropChanged, nil
}

func writeIfChanged(path string, data []byte, perm os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return config.WriteFileAtomic(path, data, perm)
}

// DropIn is the sshd configuration certifly needs.
func DropIn(p Paths, keys []HostKey) string {
	exe, err := os.Executable()
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
	}
	var b strings.Builder
	b.WriteString("# Written by certifly. Remove with `certifly host uninstall`.\n")
	fmt.Fprintf(&b, "TrustedUserCAKeys %s\n", p.CA())
	fmt.Fprintf(&b, "RevokedKeys %s\n", p.KRL())
	for _, k := range keys {
		if _, err := os.Stat(p.CertFor(k.PublicFile)); err == nil {
			fmt.Fprintf(&b, "HostCertificate %s\n", p.CertFor(k.PublicFile))
		}
	}
	fmt.Fprintf(&b, "AuthorizedPrincipalsCommand %s host principals %%u\n", exe)
	b.WriteString("AuthorizedPrincipalsCommandUser nobody\n")
	return b.String()
}

// writeDropIn writes the config; if `sshd -t` refuses it, the previous file comes back.
func writeDropIn(p Paths, keys []HostKey) (bool, error) {
	data := []byte(DropIn(p, keys))
	old, readErr := os.ReadFile(p.DropIn())
	if readErr == nil && bytes.Equal(old, data) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p.DropIn()), 0o755); err != nil {
		return false, err
	}
	if err := config.WriteFileAtomic(p.DropIn(), data, 0o644); err != nil {
		return false, err
	}
	if err := CheckSSHD(p); err != nil {
		if readErr == nil {
			_ = config.WriteFileAtomic(p.DropIn(), old, 0o644)
		} else {
			_ = os.Remove(p.DropIn())
		}
		return false, err
	}
	return true, nil
}

// IncludesDropIns reports whether sshd_config reads sshd_config.d (Debian, Ubuntu, RHEL 9 and
// most current distributions do).
func IncludesDropIns(p Paths) bool {
	data, err := os.ReadFile(p.SSHDConfig())
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], "Include") && strings.Contains(f[1], "sshd_config.d") {
			return true
		}
	}
	return false
}

// CheckSSHD runs `sshd -t`; skipped under a test root.
func CheckSSHD(p Paths) error {
	if p.Root != "" {
		return nil
	}
	for _, bin := range []string{"/usr/sbin/sshd", "sshd"} {
		if out, err := exec.Command(bin, "-t").CombinedOutput(); err == nil {
			return nil
		} else if !errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("sshd -t refused the configuration: %s", strings.TrimSpace(string(out)))
		}
	}
	return errors.New("sshd not found")
}

// ReloadSSHD reloads sshd (ssh.service on Debian/Ubuntu, sshd.service elsewhere).
func ReloadSSHD(p Paths) error {
	if p.Root != "" {
		return nil
	}
	for _, unit := range []string{"ssh", "sshd"} {
		if exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil {
			if out, err := exec.Command("systemctl", "reload", unit).CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl reload %s: %s", unit, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	if out, err := exec.Command("pkill", "-HUP", "-x", "sshd").CombinedOutput(); err != nil {
		return fmt.Errorf("could not reload sshd: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Install adds the systemd timer that runs `certifly host sync` every 15 minutes.
func Install(p Paths, report func(Step)) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	service := fmt.Sprintf(`[Unit]
Description=certifly: renew the SSH host certificate, fetch the CA key, KRL and principals
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s host sync --quiet
`, exe)
	timer := `[Unit]
Description=Run certifly host sync every 15 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=15min
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
`
	if err := os.MkdirAll(p.SystemdDir(), 0o755); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(p.Service(), []byte(service), 0o644); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(p.Timer(), []byte(timer), 0o644); err != nil {
		return err
	}
	if p.Root == "" {
		for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "certifly-host.timer"}} {
			if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
			}
		}
	}
	report(Step{Text: "Installed certifly-host.timer (every 15 min)"})
	return nil
}

// Uninstall removes certifly from sshd and stops the timer. The host stays registered in certifly.
func Uninstall(p Paths) error {
	if p.Root == "" {
		_ = exec.Command("systemctl", "disable", "--now", "certifly-host.timer").Run()
	}
	keys, _ := HostKeys(p)
	for _, f := range []string{p.Service(), p.Timer(), p.DropIn()} {
		_ = os.Remove(f)
	}
	for _, k := range keys {
		_ = os.Remove(p.CertFor(k.PublicFile))
	}
	_ = os.RemoveAll(p.Dir())
	if err := CheckSSHD(p); err != nil {
		return err
	}
	return ReloadSSHD(p)
}

// Principals answers sshd's AuthorizedPrincipalsCommand for a local user, from the last sync only.
// A person's own username is honoured only for regular accounts (UID 1000–59999, the Linux default range); system accounts such
// as root are reachable only through logins an access rule names explicitly.
func Principals(p Paths, localUser string) ([]string, error) {
	data, err := os.ReadFile(p.Principals())
	if err != nil {
		return nil, err
	}
	var f PrincipalsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	out := append([]string{}, f.Fixed[localUser]...)
	// Own usernames have their own namespace, so a person whose username equals a login an
	// access rule names (deploy, say) does not get that login's access.
	own := f.HostGroupSlug + ":~" + localUser
	if f.OwnUsername && f.HostGroupSlug != "" && regularAccount(localUser) && !slices.Contains(out, own) {
		out = append(out, own)
	}
	return out, nil
}

// regularAccount is a variable so tests can stand in for the system's user database.
var regularAccount = func(name string) bool {
	u, err := user.Lookup(name)
	if err != nil {
		return false
	}
	uid, err := strconv.Atoi(u.Uid)
	return err == nil && uid >= 1000 && uid < 60000
}

// Status is what `certifly host status` and the host TUI show.
type Status struct {
	State        *State
	Certificates []CertStatus
	KRLBytes     int
	DropInOK     bool
	Includes     bool
	SSHDErr      error
}

type CertStatus struct {
	KeyType     string
	ValidBefore time.Time
	Principals  []string
}

// ReadStatus collects the host's state without contacting the server.
func ReadStatus(p Paths) Status {
	st := Status{}
	st.State, _ = LoadState(p)
	keys, _ := HostKeys(p)
	for _, k := range keys {
		data, err := os.ReadFile(p.CertFor(k.PublicFile))
		if err != nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			continue
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			st.Certificates = append(st.Certificates, CertStatus{KeyType: k.Public.Type(), ValidBefore: time.Unix(int64(cert.ValidBefore), 0), Principals: cert.ValidPrincipals})
		}
	}
	if fi, err := os.Stat(p.KRL()); err == nil {
		st.KRLBytes = int(fi.Size())
	}
	_, err := os.Stat(p.DropIn())
	st.DropInOK = err == nil
	st.Includes = IncludesDropIns(p)
	st.SSHDErr = CheckSSHD(p)
	return st
}

// LocalIP is a hint for the join wizard.
func LocalIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
