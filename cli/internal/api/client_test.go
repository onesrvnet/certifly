package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckScheme(t *testing.T) {
	cases := []struct {
		url   string
		allow bool
		ok    bool
	}{
		{"https://certifly.example", false, true},
		{"http://certifly.example", false, false},
		{"http://certifly.example", true, true},
		{"http://localhost:3000", false, true},
		{"http://127.0.0.1:3000", false, true},
		{"http://[::1]:3000", false, true},
		{"ftp://certifly.example", true, false},
		{"certifly.example", false, false},
	}
	for _, c := range cases {
		err := CheckScheme(c.url, c.allow)
		if (err == nil) != c.ok {
			t.Errorf("CheckScheme(%q, %v) = %v", c.url, c.allow, err)
		}
	}
	if err := CheckScheme("http://certifly.example", false); !errors.Is(err, ErrInsecureHTTP) {
		t.Errorf("want ErrInsecureHTTP, got %v", err)
	}
}

func TestCallRefusesPlainHTTP(t *testing.T) {
	c := New("http://certifly.example", "")
	if err := c.Call(context.Background(), "x.get", nil, nil); !errors.Is(err, ErrInsecureHTTP) {
		t.Fatalf("want ErrInsecureHTTP, got %v", err)
	}
	if _, err := c.Get(context.Background(), "https://certifly.example/a.krl"); err != nil && errors.Is(err, ErrInsecureHTTP) {
		t.Fatal("https must not be refused")
	}
	if _, err := c.Get(context.Background(), "http://pki.example/a.krl"); !errors.Is(err, ErrInsecureHTTP) {
		t.Fatalf("want ErrInsecureHTTP for an http KRL, got %v", err)
	}
}

func TestCallDoesNotFollowRedirects(t *testing.T) {
	var resent []byte
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resent, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := New(srv.URL, "")
	err := c.Call(context.Background(), "ssh_hosts.join", map[string]string{"token": "cfj_secret"}, nil)
	if err == nil {
		t.Fatal("a redirect must fail the call")
	}
	if resent != nil {
		t.Fatalf("body was resent: %s", resent)
	}
}

func TestGetFollowsOnlySameHostRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("other")) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/old.krl":
			http.Redirect(w, r, "/new.krl", http.StatusFound)
		case "/new.krl":
			_, _ = w.Write([]byte("krl"))
		default:
			// 127.0.0.1 and localhost are different hosts to the check.
			_, port, _ := net.SplitHostPort(other.Listener.Addr().String())
			http.Redirect(w, r, "http://localhost:"+port+"/x", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "")
	data, err := c.Get(context.Background(), "/old.krl")
	if err != nil || string(data) != "krl" {
		t.Fatalf("same-host redirect: %q %v", data, err)
	}
	if _, err := c.Get(context.Background(), "/elsewhere"); err == nil {
		t.Fatal("a redirect to another host must fail")
	}
}

func TestErrorMessagesAreCleaned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"bad","message":"no\u001b[2J\nway"}}`))
	}))
	defer srv.Close()
	var out struct{ Name string }
	err := New(srv.URL, "").Call(context.Background(), "x.get", nil, &out)
	if err == nil || err.Error() != "no [2J way" {
		t.Fatalf("got %v", err)
	}
}
