// Package fake is an in-memory certifly server speaking docs/ssh-cli-api.md, for tests and for
// trying the TUI without a real server (`go run ./internal/fake/cmd`).
package fake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/onesrvnet/certifly/cli/internal/api"
	"golang.org/x/crypto/ssh"
)

// Server is the fake. Logins and YubiKey registrations are approved automatically unless Deny
// or DenyKey is set.
type Server struct {
	*httptest.Server
	mu         sync.Mutex
	CA         ssh.Signer
	Groups     []api.HostGroupAccess
	Hosts      []api.ReachableHost
	User       api.User
	Deny       bool
	Signed     []string // public keys signed for people
	JoinToken  string
	HostKeys   []string
	nonce      string
	serial     uint64
	pollsUntil int
	DenyKey    bool
	// Registered holds the fingerprints of approved YubiKeys; the prod host group signs only these.
	Registered map[string]bool
	keyUpload  string
	keyPolls   int
}

// New starts a fake with a prod (YubiKey required) and a staging host group and a few hosts.
func New() *Server {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	ca := api.CA{ID: "ca-1", Slug: "ops", Name: "Ops SSH", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}
	s := &Server{
		CA:        signer,
		User:      api.User{ID: "u-1", Name: "Flex Usma", Email: "flexusma@corp.example", Username: "flexusma"},
		JoinToken: "cfj_test",
		Groups: []api.HostGroupAccess{
			{ID: "hg-prod", Slug: "prod", Name: "Production", Logins: []string{"ops", "root"}, KeyPolicy: api.KeyPolicySK, DefaultTTLSeconds: 4 * 3600, MaxTTLSeconds: 4 * 3600, Extensions: []string{"permit-pty"}, HostPatterns: []string{"*.prod.corp"}, CA: ca},
			{ID: "hg-staging", Slug: "staging", Name: "Staging", Logins: []string{"deploy", "flexusma"}, KeyPolicy: api.KeyPolicyAny, DefaultTTLSeconds: 8 * 3600, MaxTTLSeconds: 24 * 3600, Extensions: []string{"permit-pty", "permit-port-forwarding"}, HostPatterns: []string{"*.staging.corp"}, CA: ca},
		},
		pollsUntil: 1,
		Registered: map[string]bool{},
	}
	for i, g := range s.Groups {
		s.Groups[i].Principals = nil
		for _, l := range g.Logins {
			// The person's own username has its own namespace on the server.
			if l == s.User.Username {
				s.Groups[i].Principals = append(s.Groups[i].Principals, g.Slug+":~"+l)
				continue
			}
			s.Groups[i].Principals = append(s.Groups[i].Principals, g.Slug+":"+l)
		}
	}
	add := func(name, group string, logins ...string) {
		gid := "hg-" + group
		s.Hosts = append(s.Hosts, api.ReachableHost{ID: "h-" + name, Name: name, Hostnames: []string{name}, HostGroup: api.HostGroupRef{ID: gid, Slug: group, Name: group}, Logins: logins})
	}
	for _, n := range []string{"web-01", "web-02", "db-01", "queue-01"} {
		add(n+".prod.corp", "prod", "ops", "root")
	}
	for _, n := range []string{"web-01", "webhook", "db-01"} {
		add(n+".staging.corp", "staging", "deploy", "flexusma")
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) group(id string) *api.HostGroupAccess {
	for i := range s.Groups {
		if s.Groups[i].ID == id {
			return &s.Groups[i]
		}
	}
	return nil
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}

func ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, ".krl") {
		_, _ = w.Write([]byte("SSHKRL\n\x00"))
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	method := strings.Replace(strings.TrimPrefix(r.URL.Path, "/api/v2/"), "/", ".", 1)
	authed := r.Header.Get("Authorization") == "Bearer cfc_test"
	switch method {
	case "cli_logins.start":
		ok(w, api.LoginStart{LoginID: "l-1", DeviceCode: "dev-1", UserCode: "WDJB-MJHT", BrowserURL: s.URL + "/cli/login/l-1", IntervalSeconds: 1, ExpiresAt: time.Now().Add(10 * time.Minute)})
	case "cli_logins.poll":
		if s.Deny {
			fail(w, 403, "cli_login_denied")
			return
		}
		if s.pollsUntil > 0 {
			s.pollsUntil--
			ok(w, map[string]string{"status": "pending"})
			return
		}
		ok(w, api.LoginPoll{Status: "approved", Token: "cfc_test", ExpiresAt: time.Now().Add(12 * time.Hour), User: s.User})
	case "cli_sessions.delete":
		ok(w, map[string]any{})
	case "ssh_access.get":
		if !authed {
			fail(w, 401, "unauthorized")
			return
		}
		out := map[string]any{"user": map[string]string{"id": s.User.ID, "username": s.User.Username}, "host_groups": s.Groups}
		ok(w, out)
	case "ssh_hosts.reachable":
		if !authed {
			fail(w, 401, "unauthorized")
			return
		}
		ok(w, map[string]any{"data": s.Hosts, "next_cursor": nil})
	case "ssh_user_certificates.sign":
		if !authed {
			fail(w, 401, "unauthorized")
			return
		}
		g := s.group(fmt.Sprint(in["host_group_id"]))
		if g == nil {
			fail(w, 403, "ssh_no_access")
			return
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fmt.Sprint(in["public_key"])))
		if err != nil {
			fail(w, 400, "ssh_key_type")
			return
		}
		if g.NeedsSK() && !strings.HasPrefix(pub.Type(), "sk-") {
			fail(w, 400, "ssh_key_policy")
			return
		}
		if g.NeedsSK() && !s.Registered[ssh.FingerprintSHA256(pub)] {
			fail(w, 403, "ssh_key_not_registered")
			return
		}
		cert := s.sign(pub, ssh.UserCert, g.Principals, time.Duration(g.DefaultTTLSeconds)*time.Second, "certifly:"+s.User.Email+":"+g.Slug)
		s.Signed = append(s.Signed, fmt.Sprint(in["public_key"]))
		ok(w, map[string]any{"data": api.SignedCertificate{ID: "c", Certificate: cert, Serial: fmt.Sprint(s.serial), Principals: g.Principals, ValidBefore: time.Now().Add(time.Duration(g.DefaultTTLSeconds) * time.Second)}})
	case "ssh_security_key_enrollments.start":
		if !authed {
			fail(w, 401, "unauthorized")
			return
		}
		s.keyUpload, s.keyPolls = "", 1
		challenge := make([]byte, 32)
		_, _ = rand.Read(challenge)
		ok(w, api.SecurityKeyEnrollment{EnrollmentID: "e-1", Challenge: base64.StdEncoding.EncodeToString(challenge), UserCode: "KXTP-MZRL", BrowserURL: s.URL + "/cli/security-key/e-1", IntervalSeconds: 1, ExpiresAt: time.Now().Add(10 * time.Minute)})
	case "ssh_security_key_enrollments.submit":
		if !authed {
			fail(w, 401, "unauthorized")
			return
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fmt.Sprint(in["public_key"])))
		if err != nil || !strings.HasPrefix(pub.Type(), "sk-") {
			fail(w, 400, "ssh_key_type")
			return
		}
		s.keyUpload = ssh.FingerprintSHA256(pub)
		_, attested := in["attestation"]
		model := ""
		if attested {
			model = "YubiKey 5 Series"
		}
		ok(w, map[string]any{"data": api.SecurityKeyUpload{ID: "e-1", Status: "pending", UserCode: "KXTP-MZRL", Machine: api.Machine{Hostname: "laptop", OS: "darwin"}, Name: "laptop", PublicKey: fmt.Sprint(in["public_key"]), Fingerprint: s.keyUpload, Model: model, Attested: attested, ExpiresAt: time.Now().Add(10 * time.Minute)}})
	case "ssh_security_key_enrollments.poll":
		switch {
		case !authed:
			fail(w, 401, "unauthorized")
		case s.DenyKey:
			fail(w, 403, "ssh_key_enrollment_denied")
		case s.keyUpload == "":
			fail(w, 410, "ssh_key_enrollment_expired")
		case s.keyPolls > 0:
			s.keyPolls--
			ok(w, map[string]string{"status": "pending"})
		default:
			s.Registered[s.keyUpload] = true
			ok(w, map[string]any{"status": "approved", "key": api.SecurityKey{ID: "k-1", Name: "laptop", Fingerprint: s.keyUpload, Model: "YubiKey 5 Series", Attested: true}})
		}
	case "ssh_hosts.join":
		if in["token"] != s.JoinToken {
			fail(w, 401, "invalid_token")
			return
		}
		s.JoinToken = ""
		ok(w, map[string]any{"data": s.hostSync(in)})
	case "ssh_hosts.challenge":
		s.nonce = fmt.Sprintf("nonce-%d", time.Now().UnixNano())
		ok(w, map[string]any{"nonce": s.nonce, "expires_at": time.Now().Add(5 * time.Minute)})
	case "ssh_hosts.sync":
		if in["nonce"] != s.nonce || !strings.Contains(fmt.Sprint(in["signature"]), "BEGIN SSH SIGNATURE") {
			fail(w, 403, "host_not_verified")
			return
		}
		s.nonce = ""
		ok(w, map[string]any{"data": s.hostSync(in)})
	default:
		fail(w, 404, "not_found")
	}
}

func (s *Server) hostSync(in map[string]any) api.HostSync {
	var certs []string
	names := []string{"web-01.prod.corp"}
	if raw, ok := in["hostnames"].([]any); ok && len(raw) > 0 {
		names = names[:0]
		for _, n := range raw {
			names = append(names, fmt.Sprint(n))
		}
	}
	raw, _ := in["public_keys"].([]any)
	s.HostKeys = nil
	for _, line := range raw {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fmt.Sprint(line)))
		if err != nil {
			continue
		}
		s.HostKeys = append(s.HostKeys, fmt.Sprint(line))
		certs = append(certs, s.sign(pub, ssh.HostCert, names, 90*24*time.Hour, "certifly:host:"+names[0]))
	}
	return api.HostSync{
		Host:                api.HostInfo{ID: "host-1", Name: names[0], HostGroup: api.HostGroupRef{ID: "hg-prod", Slug: "prod", Name: "Production"}},
		Certificates:        certs,
		CAPublicKey:         s.Groups[0].CA.PublicKey,
		KRLURL:              s.URL + "/api/pki/ssh/ops.krl",
		Principals:          api.HostPrincipals{Fixed: map[string][]string{"root": {"prod:root"}, "ops": {"prod:ops"}}, OwnUsername: true},
		SyncIntervalSeconds: 900,
	}
}

func (s *Server) sign(pub ssh.PublicKey, kind uint32, principals []string, life time.Duration, keyID string) string {
	s.serial++
	cert := &ssh.Certificate{
		Key: pub, Serial: s.serial, CertType: kind, KeyId: keyID, ValidPrincipals: principals,
		ValidAfter: uint64(time.Now().Add(-2 * time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(life).Unix()),
	}
	if kind == ssh.UserCert {
		cert.Permissions.Extensions = map[string]string{"permit-pty": ""}
	}
	if err := cert.SignCert(rand.Reader, s.CA); err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}
