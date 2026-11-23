#!/bin/sh
# Installs the certifly CLI from its GitHub releases, on Linux and macOS:
#
#   curl -fsSL https://raw.githubusercontent.com/onesrvnet/certifly/main/cli/install.sh | sh
#
# The archive is checked against the release's checksums.txt (SHA-256) before anything is
# installed. Afterwards `certifly update` keeps it current.
#
# Settings, as environment variables:
#   CERTIFLY_VERSION   a version such as 0.2.1 instead of the latest release
#   INSTALL_DIR        where the binary goes, default /usr/local/bin (sudo is used if needed)

set -eu

REPO="https://github.com/onesrvnet/certifly"

fail() {
	echo "certifly install: $*" >&2
	exit 1
}

# Everything runs from main, so a download cut off halfway runs nothing.
main() {
	command -v curl >/dev/null 2>&1 || fail "curl is required"
	command -v tar >/dev/null 2>&1 || fail "tar is required"

	case "$(uname -s)" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) fail "unsupported system $(uname -s); on Windows, download the .zip from $REPO/releases" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) fail "unsupported architecture $(uname -m)" ;;
	esac

	version="${CERTIFLY_VERSION:-}"
	if [ -z "$version" ]; then
		# /releases/latest redirects to /releases/tag/v<version>; no API call, no token.
		latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPO/releases/latest")" ||
			fail "could not reach $REPO"
		version="${latest##*/tag/}"
	fi
	version="${version#v}"
	case "$version" in
	[0-9]*.[0-9]*.[0-9]*) ;;
	*) fail "\"$version\" is not a release version" ;;
	esac

	if command -v sha256sum >/dev/null 2>&1; then
		sha256() { sha256sum "$1" | cut -d ' ' -f 1; }
	elif command -v shasum >/dev/null 2>&1; then
		sha256() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
	else
		fail "sha256sum or shasum is required to check the download"
	fi

	asset="certifly_${version}_${os}_${arch}.tar.gz"
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM

	echo "Downloading certifly $version for $os/$arch …"
	curl -fsSL -o "$tmp/$asset" "$REPO/releases/download/v$version/$asset" ||
		fail "could not download $asset; is $version a release with a build for $os/$arch?"
	curl -fsSL -o "$tmp/checksums.txt" "$REPO/releases/download/v$version/checksums.txt" ||
		fail "could not download checksums.txt"

	want="$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$tmp/checksums.txt")"
	[ -n "$want" ] || fail "checksums.txt lists no $asset"
	got="$(sha256 "$tmp/$asset")"
	[ "$got" = "$want" ] || fail "$asset does not match its checksum; nothing was installed"

	tar -xzf "$tmp/$asset" -C "$tmp" certifly

	dir="${INSTALL_DIR:-/usr/local/bin}"
	sudo=""
	mkdir -p "$dir" 2>/dev/null || true
	if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
		if [ "$(id -u)" -ne 0 ]; then
			command -v sudo >/dev/null 2>&1 || fail "no write access to $dir; run as root or set INSTALL_DIR"
			sudo="sudo"
			echo "Installing to $dir needs sudo."
		fi
	fi
	# install (not mv) so the binary belongs to whoever installs it, root with sudo: a binary in
	# a system folder that its user could rewrite would hand them root on its next sudo run.
	$sudo mkdir -p "$dir"
	$sudo install -m 755 "$tmp/certifly" "$dir/certifly"

	echo "Installed $("$dir/certifly" --version) at $dir/certifly."
	found="$(command -v certifly 2>/dev/null || true)"
	if [ -z "$found" ]; then
		echo "$dir is not on your PATH; add it to run certifly by name."
	elif [ "$found" != "$dir/certifly" ]; then
		echo "Note: \`certifly\` runs $found first on your PATH, not the one just installed."
	fi
	echo "Keep it current with \`certifly update\`."
}

main "$@"
