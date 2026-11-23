// Package sshagent loads certifly certificates into ssh-agent: the person's own agent, or a private
// one the CLI starts when there is none.
package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/config"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// CommentPrefix marks keys the CLI added, so it can replace and list them.
const CommentPrefix = "certifly:"

// Agent is a connection to an ssh-agent.
type Agent struct {
	Socket string
	// Private is true when the socket belongs to the agent the CLI started.
	Private bool
	client  agent.ExtendedAgent
	conn    net.Conn
}

var privateMu sync.Mutex

// PrivateSocket is where the CLI's own agent listens.
func PrivateSocket() string { return filepath.Join(config.Dir(), "agent.sock") }

// Open connects to the configured agent, $SSH_AUTH_SOCK, or the CLI's private agent (started if needed).
// Use it only when the person chose to share certificates with plain ssh; otherwise OpenPrivate.
func Open(configured string) (*Agent, error) {
	for _, sock := range []string{configured, os.Getenv("SSH_AUTH_SOCK")} {
		if sock == "" {
			continue
		}
		if a, err := dial(sock); err == nil {
			a.Private = sock == PrivateSocket()
			return a, nil
		}
	}
	return OpenPrivate()
}

func dial(sock string) (*Agent, error) {
	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return &Agent{Socket: sock, client: agent.NewClient(conn), conn: conn}, nil
}

// OpenPrivate connects to the CLI's own agent, starting it if needed.
func OpenPrivate() (*Agent, error) {
	// Certificates for several host groups are fetched at once; only one of them may start the agent.
	privateMu.Lock()
	defer privateMu.Unlock()
	sock := PrivateSocket()
	if a, err := dial(sock); err == nil {
		a.Private = true
		return a, nil
	}
	if err := os.MkdirAll(config.Dir(), 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(sock)
	// ssh-agent -a <socket> forks into the background and keeps running after the CLI exits.
	cmd := sshbin.Command("ssh-agent", "-a", sock)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("could not start ssh-agent: %s", strings.TrimSpace(string(out)))
	}
	for range 20 {
		if a, err := dial(sock); err == nil {
			a.Private = true
			return a, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("started ssh-agent, but cannot connect to it")
}

// Close drops the connection; the agent keeps running.
func (a *Agent) Close() error { return a.conn.Close() }

// NewThrowawayKey makes an Ed25519 key that lives only in memory and in the agent.
func NewThrowawayKey() (ed25519.PrivateKey, ssh.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	return priv, sshPub, err
}

// AddCertificate loads key and cert into the agent for the certificate's remaining lifetime,
// replacing what the CLI loaded earlier for the same host group.
func (a *Agent) AddCertificate(hostGroup string, key any, cert *ssh.Certificate) error {
	comment := CommentPrefix + hostGroup
	a.RemoveHostGroup(hostGroup)
	life := time.Until(time.Unix(int64(cert.ValidBefore), 0))
	if life < time.Minute {
		return errors.New("the certificate is already about to expire")
	}
	// The plain key too, like ssh-add does: ssh matches an IdentityFile to an agent key by its
	// plain public key, and only then signs with the certificate.
	if err := a.client.Add(agent.AddedKey{PrivateKey: key, Comment: comment, LifetimeSecs: uint32(life.Seconds())}); err != nil {
		return err
	}
	return a.client.Add(agent.AddedKey{PrivateKey: key, Certificate: cert, Comment: comment, LifetimeSecs: uint32(life.Seconds())})
}

// RemoveHostGroup drops the CLI's keys for a host group from the agent.
func (a *Agent) RemoveHostGroup(hostGroup string) {
	keys, err := a.client.List()
	if err != nil {
		return
	}
	for _, k := range keys {
		if k.Comment == CommentPrefix+hostGroup {
			pub, err := ssh.ParsePublicKey(k.Blob)
			if err == nil {
				_ = a.client.Remove(pub)
			}
		}
	}
}

// Loaded is a certificate the CLI put into the agent.
type Loaded struct {
	HostGroup   string
	Principals  []string
	ValidBefore time.Time
	KeyType     string
}

// Certificates lists the CLI's certificates in the agent, newest first per host group.
func (a *Agent) Certificates() ([]Loaded, error) {
	keys, err := a.client.List()
	if err != nil {
		return nil, err
	}
	var out []Loaded
	for _, k := range keys {
		if !strings.HasPrefix(k.Comment, CommentPrefix) {
			continue
		}
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			continue
		}
		out = append(out, Loaded{
			HostGroup:   strings.TrimPrefix(k.Comment, CommentPrefix),
			Principals:  cert.ValidPrincipals,
			ValidBefore: time.Unix(int64(cert.ValidBefore), 0),
			KeyType:     cert.Key.Type(),
		})
	}
	return out, nil
}

// AddKeyFile loads a key file (for a security-key handle) and its -cert.pub with ssh-add, which
// knows how to talk to the security key; the agent forgets it when the certificate expires.
func (a *Agent) AddKeyFile(path string, life time.Duration) error {
	cmd := sshbin.Command("ssh-add", "-t", fmt.Sprint(int(life.Seconds())), path)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+a.Socket)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-add: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
