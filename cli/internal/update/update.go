// Package update finds the newest certifly CLI release on GitHub and replaces the running binary
// with it. A download is checked against the release's checksums.txt (SHA-256) before it is
// installed.
package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// BaseURL is where releases live; tests point it at a local server.
var BaseURL = "https://github.com/onesrvnet/certifly"

// maxDownload caps an archive download; a release archive is a few megabytes.
const maxDownload = 200 << 20

// ErrManaged means a package manager installed this binary and should update it.
var ErrManaged = errors.New("certifly was installed with Homebrew: run `brew upgrade certifly`")

// Release is a published CLI release.
type Release struct {
	// Version without the leading v, e.g. 0.2.0.
	Version string
	Tag     string
}

func client() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && !isLocal(req.URL) {
				return fmt.Errorf("refusing a redirect to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}

func isLocal(u *url.URL) bool {
	h := u.Hostname()
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// Latest asks GitHub which release is the newest. It reads the redirect of
// /releases/latest, so it needs no API call and no token. Pre-releases are never "latest".
func Latest(ctx context.Context) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, BaseURL+"/releases/latest", nil)
	if err != nil {
		return Release{}, err
	}
	c := client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("looking for the latest release: %w", err)
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	if res.StatusCode < 300 || res.StatusCode > 399 || loc == "" {
		return Release{}, fmt.Errorf("looking for the latest release: GitHub answered %s", res.Status)
	}
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return Release{}, fmt.Errorf("looking for the latest release: unexpected redirect to %q", loc)
	}
	tag, err := url.PathUnescape(loc[i+len("/tag/"):])
	if err != nil || !strings.HasPrefix(tag, "v") || parse(strings.TrimPrefix(tag, "v")) == nil {
		return Release{}, fmt.Errorf("looking for the latest release: %q is not a version tag", loc[i+len("/tag/"):])
	}
	return Release{Version: strings.TrimPrefix(tag, "v"), Tag: tag}, nil
}

// parse reads major.minor.patch, with an optional -prerelease suffix it ignores for ordering
// beyond "a pre-release comes before its release". It returns nil for anything else.
func parse(v string) []int {
	core, pre, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	// A release sorts after its pre-releases.
	if pre == "" {
		out[3] = 1
	}
	return out
}

// Newer reports whether latest is a newer version than current. A development build ("dev") or
// an unreadable version is never offered an update.
func Newer(current, latest string) bool {
	c, l := parse(current), parse(latest)
	if c == nil || l == nil {
		return false
	}
	for i := range c {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// AssetName is the archive for this platform, as GoReleaser names it.
func AssetName(version, goos, goarch string) string {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("certifly_%s_%s_%s.%s", version, goos, goarch, ext)
}

// Executable is the path of the running binary, symlinks resolved.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// Managed reports whether a package manager owns the binary at path.
func Managed(path string) bool {
	p := filepath.ToSlash(path)
	return strings.Contains(p, "/Cellar/") || strings.Contains(p, "/homebrew/") || strings.Contains(p, "/linuxbrew/")
}

// Install downloads rel for this platform, checks it against checksums.txt and replaces the
// binary at target with it.
func Install(ctx context.Context, rel Release, target string) error {
	if Managed(target) {
		return ErrManaged
	}
	dir := filepath.Dir(target)
	// Fail before downloading when the binary cannot be replaced.
	probe, err := os.CreateTemp(dir, ".certifly-update-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("no permission to write to %s: run it again with sudo", dir)
		}
		return err
	}
	probe.Close()
	os.Remove(probe.Name())

	asset := AssetName(rel.Version, runtime.GOOS, runtime.GOARCH)
	sums, err := download(ctx, rel.Tag, "checksums.txt", 1<<20)
	if err != nil {
		return err
	}
	want, err := checksumFor(sums, asset)
	if err != nil {
		return err
	}
	archive, err := download(ctx, rel.Tag, asset, maxDownload)
	if err != nil {
		return err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("%s does not match its checksum in checksums.txt; nothing was installed", asset)
	}
	binary, err := extract(archive, runtime.GOOS)
	if err != nil {
		return err
	}
	return replace(target, binary)
}

func download(ctx context.Context, tag, name string, limit int64) ([]byte, error) {
	u := fmt.Sprintf("%s/releases/download/%s/%s", BaseURL, url.PathEscape(tag), url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: GitHub answered %s", name, res.Status)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("downloading %s: larger than %d bytes", name, limit)
	}
	return data, nil
}

// checksumFor finds the SHA-256 of name in a checksums.txt ("<hex>  <name>" per line).
func checksumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			sum := strings.ToLower(fields[0])
			if b, err := hex.DecodeString(sum); err != nil || len(b) != sha256.Size {
				return "", fmt.Errorf("checksums.txt has no valid SHA-256 for %s", name)
			}
			return sum, nil
		}
	}
	return "", fmt.Errorf("checksums.txt lists no %s: this platform may have no release", name)
}

// extract takes the certifly binary out of a release archive.
func extract(archive []byte, goos string) ([]byte, error) {
	if goos == "windows" {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		for _, f := range zr.File {
			if f.Name == "certifly.exe" {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, maxDownload))
			}
		}
		return nil, errors.New("the archive has no certifly.exe")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("reading the archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the archive has no certifly binary")
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		if h.Typeflag == tar.TypeReg && h.Name == "certifly" {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}

// replace swaps the binary at target for data, keeping its file mode. The new file is written
// next to it and renamed over it, so the old binary stays intact until the swap.
func replace(target string, data []byte) error {
	mode := os.FileMode(0o755)
	if info, err := os.Stat(target); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".certifly-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// A running .exe cannot be overwritten, but it can be renamed out of the way.
		old := target + ".old"
		_ = os.Remove(old)
		if err := os.Rename(target, old); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), target)
}
