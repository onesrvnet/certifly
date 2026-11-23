package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
	}{
		{"0.2.0", "0.3.0", true},
		{"0.2.0", "0.2.1", true},
		{"0.9.9", "1.0.0", true},
		{"0.2.0", "0.2.0", false},
		{"0.3.0", "0.2.9", false},
		{"0.10.0", "0.9.0", false},
		{"0.2.0-rc.1", "0.2.0", true},
		{"0.2.0", "0.2.0-rc.1", false},
		{"dev", "0.2.0", false},
		{"0.2.0", "garbage", false},
	}
	for _, c := range cases {
		if got := Newer(c.current, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestManagedAndAssetName(t *testing.T) {
	if !Managed("/opt/homebrew/Cellar/certifly/0.2.0/bin/certifly") || !Managed("/home/linuxbrew/.linuxbrew/bin/certifly") {
		t.Error("Homebrew paths are not recognised")
	}
	if Managed("/usr/local/bin/certifly") {
		t.Error("/usr/local/bin is not Homebrew's")
	}
	if got := AssetName("0.2.0", "linux", "arm64"); got != "certifly_0.2.0_linux_arm64.tar.gz" {
		t.Errorf("AssetName = %q", got)
	}
	if got := AssetName("0.2.0", "windows", "amd64"); got != "certifly_0.2.0_windows_amd64.zip" {
		t.Errorf("AssetName = %q", got)
	}
}

// archiveFor builds a release archive for this platform holding the given binary, the way
// GoReleaser lays it out (binary at the root, next to LICENSE and README.md).
func archiveFor(t *testing.T, binary []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	files := []struct {
		name string
		data []byte
	}{{"LICENSE", []byte("license")}, {"README.md", []byte("readme")}}
	if runtime.GOOS == "windows" {
		zw := zip.NewWriter(&buf)
		files = append(files, struct {
			name string
			data []byte
		}{"certifly.exe", binary})
		for _, f := range files {
			w, _ := zw.Create(f.name)
			w.Write(f.data)
		}
		zw.Close()
		return buf.Bytes()
	}
	files = append(files, struct {
		name string
		data []byte
	}{"certifly", binary})
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		tw.Write(f.data)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// fakeGitHub serves /releases/latest and the release's files.
type fakeGitHub struct {
	*httptest.Server
	tag     string
	files   map[string][]byte
	latests atomic.Int32
}

func newFakeGitHub(t *testing.T, tag string) *fakeGitHub {
	f := &fakeGitHub{tag: tag, files: map[string][]byte{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/releases/latest":
			f.latests.Add(1)
			http.Redirect(w, r, "/releases/tag/"+f.tag, http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/releases/download/"+f.tag+"/"):
			data, ok := f.files[strings.TrimPrefix(r.URL.Path, "/releases/download/"+f.tag+"/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	old := BaseURL
	BaseURL = f.URL
	t.Cleanup(func() { BaseURL = old })
	return f
}

// publish adds the archive for this platform and a checksums.txt that lists it with sum.
func (f *fakeGitHub) publish(version string, archive []byte, sum string) {
	name := AssetName(version, runtime.GOOS, runtime.GOARCH)
	f.files[name] = archive
	f.files["checksums.txt"] = []byte(fmt.Sprintf("%s  certifly_%s_other_os.tar.gz\n%s  %s\n", strings.Repeat("0", 64), version, sum, name))
}

func sha(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func installed(t *testing.T) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "certifly")
	if err := os.WriteFile(target, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestLatestReadsTheRedirect(t *testing.T) {
	newFakeGitHub(t, "v0.3.0")
	rel, err := Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "0.3.0" || rel.Tag != "v0.3.0" {
		t.Fatalf("Latest = %+v", rel)
	}
}

func TestLatestRefusesATagThatIsNoVersion(t *testing.T) {
	newFakeGitHub(t, "nightly")
	if _, err := Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "not a version tag") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallReplacesTheBinary(t *testing.T) {
	f := newFakeGitHub(t, "v0.3.0")
	archive := archiveFor(t, []byte("new binary"))
	f.publish("0.3.0", archive, sha(archive))
	target := installed(t)

	if err := Install(context.Background(), Release{Version: "0.3.0", Tag: "v0.3.0"}, target); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new binary" {
		t.Fatalf("binary = %q", got)
	}
	if info, _ := os.Stat(target); runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v", info.Mode())
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(target), ".certifly-update-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
}

func TestInstallRefusesAChecksumMismatch(t *testing.T) {
	f := newFakeGitHub(t, "v0.3.0")
	archive := archiveFor(t, []byte("tampered binary"))
	f.publish("0.3.0", archive, sha([]byte("something else")))
	target := installed(t)

	err := Install(context.Background(), Release{Version: "0.3.0", Tag: "v0.3.0"}, target)
	if err == nil || !strings.Contains(err.Error(), "does not match its checksum") {
		t.Fatalf("err = %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "old binary" {
		t.Fatalf("the old binary was touched: %q", got)
	}
}

func TestInstallRefusesAPlatformWithoutChecksum(t *testing.T) {
	f := newFakeGitHub(t, "v0.3.0")
	f.files["checksums.txt"] = []byte(strings.Repeat("0", 64) + "  certifly_0.3.0_plan9_mips.tar.gz\n")
	err := Install(context.Background(), Release{Version: "0.3.0", Tag: "v0.3.0"}, installed(t))
	if err == nil || !strings.Contains(err.Error(), "lists no") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallLeavesHomebrewAlone(t *testing.T) {
	newFakeGitHub(t, "v0.3.0")
	err := Install(context.Background(), Release{Version: "0.3.0", Tag: "v0.3.0"}, "/opt/homebrew/Cellar/certifly/0.2.0/bin/certifly")
	if err != ErrManaged {
		t.Fatalf("err = %v", err)
	}
}

func TestAvailableChecksOncePerInterval(t *testing.T) {
	t.Setenv("CERTIFLY_NO_UPDATE_CHECK", "")
	f := newFakeGitHub(t, "v0.3.0")
	cache := filepath.Join(t.TempDir(), "update-check.json")
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

	if v, ok := Available(context.Background(), "0.2.0", cache, now); !ok || v != "0.3.0" {
		t.Fatalf("Available = %q, %v", v, ok)
	}
	// Within the interval the remembered answer is used, without asking GitHub.
	if v, ok := Available(context.Background(), "0.2.0", cache, now.Add(time.Hour)); !ok || v != "0.3.0" {
		t.Fatalf("Available = %q, %v", v, ok)
	}
	if n := f.latests.Load(); n != 1 {
		t.Fatalf("GitHub was asked %d times", n)
	}
	// Once the version is current, nothing is offered.
	if _, ok := Available(context.Background(), "0.3.0", cache, now.Add(2*time.Hour)); ok {
		t.Fatal("offered the version already running")
	}
	// After the interval GitHub is asked again.
	f.tag = "v0.4.0"
	if v, _ := Available(context.Background(), "0.3.0", cache, now.Add(CheckInterval+time.Minute)); v != "0.4.0" {
		t.Fatalf("Available after the interval = %q", v)
	}
	if n := f.latests.Load(); n != 2 {
		t.Fatalf("GitHub was asked %d times", n)
	}
}

func TestAvailableIsOffForDevBuildsAndOnRequest(t *testing.T) {
	f := newFakeGitHub(t, "v0.3.0")
	cache := filepath.Join(t.TempDir(), "update-check.json")
	if _, ok := Available(context.Background(), "dev", cache, time.Now()); ok {
		t.Fatal("a dev build was offered an update")
	}
	t.Setenv("CERTIFLY_NO_UPDATE_CHECK", "1")
	if _, ok := Available(context.Background(), "0.2.0", cache, time.Now()); ok {
		t.Fatal("offered an update with CERTIFLY_NO_UPDATE_CHECK set")
	}
	if n := f.latests.Load(); n != 0 {
		t.Fatalf("GitHub was asked %d times", n)
	}
}
