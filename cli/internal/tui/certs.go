package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/onesrvnet/certifly/cli/internal/app"
	"github.com/onesrvnet/certifly/cli/internal/certs"
	"github.com/onesrvnet/certifly/cli/internal/sshbin"
)

// certsModel lists the host groups the person can reach and their certificate in the agent.
type certsModel struct {
	theme    Theme
	overview app.Overview
	cursor   int
	pending  map[string]bool
	results  map[string]certs.Result
}

func newCertsModel(t Theme) certsModel {
	return certsModel{theme: t, pending: map[string]bool{}, results: map[string]certs.Result{}}
}

func (m *certsModel) setOverview(ov app.Overview) {
	m.overview = ov
	if m.cursor >= len(ov.Access.HostGroups) {
		m.cursor = 0
	}
}

// remaining is how long the host group's certificate in the agent still lasts.
func (m certsModel) remaining(slug string) (time.Duration, bool) {
	var best time.Time
	for _, l := range m.overview.Loaded {
		if l.HostGroup == slug && l.ValidBefore.After(best) {
			best = l.ValidBefore
		}
	}
	if r, ok := m.results[slug]; ok && r.Err == nil && r.ValidBefore.After(best) {
		best = r.ValidBefore
	}
	if best.IsZero() || time.Until(best) <= 0 {
		return 0, false
	}
	return time.Until(best), true
}

// Update moves the cursor; it returns the slug of a host group to renew.
func (m certsModel) Update(msg tea.Msg) (certsModel, tea.Cmd, string) {
	key, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil, ""
	}
	n := len(m.overview.Access.HostGroups)
	switch key.String() {
	case "up", "k":
		if n > 0 {
			m.cursor = (m.cursor - 1 + n) % n
		}
	case "down", "j":
		if n > 0 {
			m.cursor = (m.cursor + 1) % n
		}
	case "enter":
		if m.cursor < n {
			return m, nil, m.overview.Access.HostGroups[m.cursor].Slug
		}
	}
	return m, nil, ""
}

// View shows one card per host group: its certificate, key and logins.
func (m certsModel) View(width int, spin string) string {
	t := m.theme
	groups := m.overview.Access.HostGroups
	if len(groups) == 0 {
		return "\n" + t.Dim.Render("You have no SSH access yet. Ask an admin to add you to a group.")
	}
	row := func(label, value string) string { return t.Dim.Render(fmt.Sprintf("%-13s", label)) + value }
	var cards []string
	for i, g := range groups {
		state := "bad"
		left := "no certificate"
		if d, ok := m.remaining(g.Slug); ok {
			state, left = "ok", "valid "+shortDuration(d)
			if d < 30*time.Minute {
				state = "warn"
			}
		}
		status := t.dot(state) + " " + left
		if m.pending[g.Slug] {
			status = spin + " renewing …"
		}
		key := "Throwaway key"
		switch g.KeyPolicy {
		case "sk":
			key = "YubiKey"
		case "sk_attested":
			key = "YubiKey, attested"
		}
		var ls []string
		for _, l := range g.Logins {
			ls = append(ls, t.Strong.Render(l))
		}
		res, failed := m.results[g.Slug]
		failed = failed && res.Err != nil
		notRegistered := failed && (errors.Is(res.Err, certs.ErrKeyNotRegistered) || errors.Is(res.Err, certs.ErrKeyRevoked))
		if notRegistered {
			key = t.Warn.Render("YubiKey, not registered")
			if errors.Is(res.Err, certs.ErrKeyRevoked) {
				key = t.Warn.Render("YubiKey, revoked")
			}
		}
		lines := []string{
			row("Certificate", status),
			row("Key", key),
			row("Log in as", strings.Join(ls, " ")),
			row("Lifetime", t.Dim.Render("up to "+shortDuration(time.Duration(g.MaxTTLSeconds)*time.Second))),
		}
		switch {
		case notRegistered:
			lines = append(lines, t.Warn.Render("! This host group only accepts registered YubiKeys."), "  "+t.Dim.Render("Settings → YubiKey → Register"))
		case failed:
			msg := res.Err.Error()
			switch {
			case errors.Is(res.Err, sshbin.ErrNoFIDO):
				msg = "needs an OpenSSH with YubiKey support: " + sshbin.InstallHint()
			case errors.Is(res.Err, certs.ErrNoSecurityKey):
				msg = "needs a YubiKey key: Settings, then y"
			}
			lines = append(lines, t.Bad.Render("✗ "+msg))
		}
		title := g.Name + "  " + t.groupBadge(g.Slug)
		cards = append(cards, t.panel(title, width, len(lines)+2, i == m.cursor, strings.Join(lines, "\n")))
	}
	return strings.Join(cards, "\n")
}
