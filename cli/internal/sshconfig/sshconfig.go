// Package sshconfig wires certifly into the person's OpenSSH: known_hosts trust for host
// certificates, and an Include in ~/.ssh/config pointing at a file the CLI owns.
package sshconfig

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/safetext"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
	"golang.org/x/crypto/ssh"
)

// Files the CLI writes; it never edits ~/.ssh/config beyond one Include line at the top.
func KnownHostsPath() string { return filepath.Join(config.Dir(), "known_hosts") }
func ConfigPath() string     { return filepath.Join(config.Dir(), "ssh_config") }

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// CheckSlug accepts only the slugs the server makes. Slugs name files, so anything else (a "/"
// or "..") could point outside the CLI's folder.
func CheckSlug(slug string) error {
	if len(slug) > 100 || !slugPattern.MatchString(slug) {
		return fmt.Errorf("the server sent an invalid host group slug %q", safetext.Clean(slug))
	}
	return nil
}

// hostPattern is what ssh_config and known_hosts take as a host pattern; anything else (spaces,
// commas, line breaks) could add options or hosts of its own.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9.*?:\[\]_-]+$`)

func safePatterns(patterns []string) []string {
	var out []string
	for _, p := range unique(patterns) {
		if hostPattern.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}

// caKeyLine returns the CA key as a single `<type> <base64>` line, or false when it is not a
// plain public key.
func caKeyLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return "", false
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(rest) > 0 {
		return "", false
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return "", false
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), true
}

// IdentityFiles are the public key and certificate of a host group's key, written next to the
// config. They are public; the private key stays in the agent (or on the YubiKey). Naming them
// lets ssh offer the certificate even when ~/.ssh/config has `IdentitiesOnly yes`.
func IdentityFiles(hostGroup string) (publicKey, certificate string, err error) {
	if err := CheckSlug(hostGroup); err != nil {
		return "", "", err
	}
	dir := filepath.Join(config.Dir(), "certs")
	return filepath.Join(dir, hostGroup+".pub"), filepath.Join(dir, hostGroup+"-cert.pub"), nil
}

// WriteIdentity stores a host group's public key and certificate lines for IdentityFiles.
func WriteIdentity(hostGroup, publicKey, certificate string) error {
	pub, cert, err := IdentityFiles(hostGroup)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(pub), 0o700); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(pub, []byte(strings.TrimSpace(publicKey)+"\n"), 0o644); err != nil {
		return err
	}
	return config.WriteFileAtomic(cert, []byte(strings.TrimSpace(certificate)+"\n"), 0o644)
}

func userSSHConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

// Apply writes the known_hosts and ssh_config files for the host groups the person can reach.
// With integrate, it also adds `Include <ssh_config>` to ~/.ssh/config if it is not there yet.
func Apply(groups []api.HostGroupAccess, agentSocket string, privateAgent, integrate bool) error {
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		return err
	}
	// One @cert-authority line per CA, for all host name patterns of its host groups. Host groups
	// whose slug or CA key is not well-formed are left out.
	patterns := map[string][]string{}
	keys := map[string]string{}
	var usable []api.HostGroupAccess
	for _, g := range groups {
		key, ok := caKeyLine(g.CA.PublicKey)
		if !ok || CheckSlug(g.Slug) != nil {
			continue
		}
		usable = append(usable, g)
		patterns[g.CA.ID] = append(patterns[g.CA.ID], safePatterns(g.HostPatterns)...)
		keys[g.CA.ID] = key
	}
	var known bytes.Buffer
	known.WriteString("# Written by certifly. Host certificates signed by these CAs are trusted for these names.\n")
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if len(patterns[id]) == 0 {
			continue
		}
		fmt.Fprintf(&known, "@cert-authority %s %s\n", strings.Join(unique(patterns[id]), ","), keys[id])
	}
	if err := config.WriteFileAtomic(KnownHostsPath(), known.Bytes(), 0o644); err != nil {
		return err
	}

	var cfg bytes.Buffer
	cfg.WriteString("# Written by certifly; changes are overwritten. Remove the Include in ~/.ssh/config to stop using it.\n")
	for _, g := range usable {
		hostPatterns := safePatterns(g.HostPatterns)
		if len(hostPatterns) == 0 {
			continue
		}
		pub, cert, err := IdentityFiles(g.Slug)
		if err != nil {
			continue
		}
		fmt.Fprintf(&cfg, "\n# %s\nHost %s\n", safetext.Clean(g.Name), strings.Join(hostPatterns, " "))
		fmt.Fprintf(&cfg, "  UserKnownHostsFile ~/.ssh/known_hosts %s\n", quote(KnownHostsPath()))
		fmt.Fprintf(&cfg, "  IdentityFile %s\n  CertificateFile %s\n", quote(pub), quote(cert))
		if privateAgent {
			fmt.Fprintf(&cfg, "  IdentityAgent %s\n", quote(agentSocket))
		}
	}
	if err := config.WriteFileAtomic(ConfigPath(), cfg.Bytes(), 0o644); err != nil {
		return err
	}
	if integrate {
		return ensureInclude()
	}
	return nil
}

// Included reports whether ~/.ssh/config already includes the CLI's file.
func Included() bool {
	data, err := os.ReadFile(userSSHConfig())
	return err == nil && bytes.Contains(data, []byte(ConfigPath()))
}

// Include must come before any Host block to apply to every host, so it goes first in the file.
func ensureInclude() error {
	if Included() {
		return nil
	}
	path := userSSHConfig()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	line := fmt.Sprintf("Include %s\n\n", quote(ConfigPath()))
	return config.WriteFileAtomic(path, append([]byte(line), old...), 0o600)
}

// RemoveInclude takes the CLI's Include line out of ~/.ssh/config again.
func RemoveInclude() error {
	path := userSSHConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), ConfigPath()) && strings.HasPrefix(strings.TrimSpace(scanner.Text()), "Include") {
			continue
		}
		out.WriteString(scanner.Text() + "\n")
	}
	return config.WriteFileAtomic(path, bytes.TrimLeft(out.Bytes(), "\n"), 0o600)
}

// Command builds the ssh command for a host, login and host group. It names the agent, the
// certificate and certifly's known_hosts explicitly, so it works whatever ~/.ssh/config says
// (IdentityAgent, IdentitiesOnly) and without the Include.
func Command(host, login, hostGroup, agentSocket string, args ...string) (*exec.Cmd, error) {
	pub, cert, err := IdentityFiles(hostGroup)
	if err != nil {
		return nil, err
	}
	argv := []string{
		"-o", "IdentityAgent=" + agentSocket,
		"-o", "IdentityFile=" + pub,
		"-o", "CertificateFile=" + cert,
		"-o", "UserKnownHostsFile=~/.ssh/known_hosts " + KnownHostsPath(),
		"-l", login, host,
	}
	argv = append(argv, args...)
	cmd := sshbin.Command("ssh", argv...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	return cmd, nil
}

func unique(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range items {
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func quote(path string) string {
	if strings.ContainsAny(path, " \t") {
		return `"` + path + `"`
	}
	return path
}
