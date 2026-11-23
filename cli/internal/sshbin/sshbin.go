// Package sshbin finds the OpenSSH tools to run. Apple's /usr/bin/ssh has no FIDO support, so on
// macOS the Homebrew build is preferred when it is installed.
package sshbin

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// InstallHint is how to get an OpenSSH that can use a YubiKey on this system.
func InstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "brew install openssh"
	case "windows":
		return "install the Win32-OpenSSH release with FIDO support (8.9 or newer)"
	default:
		return "install OpenSSH 8.2 or newer built with libfido2 (e.g. apt install openssh-client libfido2-1)"
	}
}

// ErrNoFIDO means the OpenSSH found here cannot use security keys.
var ErrNoFIDO = errors.New("this OpenSSH cannot use a YubiKey; " + InstallHint())

// Preferred locations before $PATH: Homebrew on Apple silicon and Intel.
var preferred = []string{"/opt/homebrew/bin", "/usr/local/bin"}

// Find returns the path of tool ("ssh", "ssh-keygen", "ssh-add"), the FIDO-capable build first.
func Find(tool string) string {
	if dir := os.Getenv("CERTIFLY_OPENSSH_DIR"); dir != "" {
		return filepath.Join(dir, tool)
	}
	if runtime.GOOS == "darwin" {
		for _, dir := range preferred {
			p := filepath.Join(dir, tool)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath(tool); err == nil {
		return p
	}
	return tool
}

// FIDOCapable reports whether the tools Find picks can use security keys. Apple's build in /usr/bin
// cannot; other systems' OpenSSH is assumed to have libfido2 (ssh-keygen says so when it does not).
func FIDOCapable() bool {
	if os.Getenv("CERTIFLY_OPENSSH_DIR") != "" {
		return true
	}
	return !(runtime.GOOS == "darwin" && strings.HasPrefix(Find("ssh-keygen"), "/usr/bin/"))
}

// Command is exec.Command for an OpenSSH tool from Find.
func Command(tool string, args ...string) *exec.Cmd { return exec.Command(Find(tool), args...) }
