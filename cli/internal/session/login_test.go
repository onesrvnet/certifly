package session

import "testing"

func TestCheckBrowserURL(t *testing.T) {
	cases := []struct {
		link, server string
		allow        bool
		ok           bool
	}{
		{"https://certifly.example/cli/login/1", "https://certifly.example", false, true},
		{"https://evil.example/cli/login/1", "https://certifly.example", false, false},
		{"https://user@certifly.example/x", "https://certifly.example", false, false},
		{"http://certifly.example/x", "https://certifly.example", false, false},
		{"http://certifly.example/x", "http://certifly.example", true, true},
		{"http://127.0.0.1:3000/x", "http://127.0.0.1:3000", false, true},
		{"file:///etc/passwd", "https://certifly.example", false, false},
		{"javascript:alert(1)", "https://certifly.example", false, false},
	}
	for _, c := range cases {
		if err := CheckBrowserURL(c.link, c.server, c.allow); (err == nil) != c.ok {
			t.Errorf("CheckBrowserURL(%q, %q, %v) = %v", c.link, c.server, c.allow, err)
		}
	}
}
