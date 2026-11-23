#!/usr/bin/env bash
# Notarizes the macOS binaries of a published CLI release from your Mac, for when CI has no App
# Store Connect API key. Notarizing a bare binary does not change it, so the release archives,
# checksums and the Homebrew formula stay as they are; Gatekeeper finds the ticket online.
#
# The first run asks for your Apple ID and an app-specific password (appleid.apple.com → Sign-In
# and Security → App-Specific Passwords) and keeps them in the keychain. The team is taken from
# the release's signature, so it is always the team that signed it.
#
#   cli/scripts/notarize-release.sh v1.2.3
set -euo pipefail

tag="${1:?usage: notarize-release.sh <tag, e.g. v1.2.3>}"
profile="${NOTARY_PROFILE:-certifly}"
repo="onesrvnet/certifly"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Downloading the macOS archives of $tag …"
gh release download "$tag" --repo "$repo" --pattern '*_darwin_*.tar.gz' --dir "$work"

# The team that signed the release, from the first binary's signature.
first="$(ls "$work"/*_darwin_*.tar.gz | head -1)"
mkdir -p "$work/probe" && tar -xzf "$first" -C "$work/probe"
team="$(codesign -dv --verbose=4 "$work/probe/certifly" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
[ -n "$team" ] && [ "$team" != "not set" ] || { echo "✗ the release is not signed with a Developer ID team" >&2; exit 1; }
rm -rf "$work/probe"

# First run: store the Apple ID credentials for this team in the keychain (notarytool asks).
if ! xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1; then
  echo "No notarization credentials stored yet. Enter your Apple ID and an app-specific password for team $team:"
  xcrun notarytool store-credentials "$profile" --team-id "$team"
fi

for archive in "$work"/*_darwin_*.tar.gz; do
  name="$(basename "$archive" .tar.gz)"
  dir="$work/$name"
  mkdir -p "$dir"
  tar -xzf "$archive" -C "$dir"
  bin="$dir/certifly"

  # Apple only notarizes code signed with the hardened runtime and a secure timestamp.
  info="$(codesign -dv --verbose=4 "$bin" 2>&1)" || { echo "✗ $name is not signed" >&2; exit 1; }
  grep -q 'Authority=Developer ID Application' <<<"$info" || { echo "✗ $name is not signed with a Developer ID" >&2; exit 1; }
  grep -qE 'flags=0x[0-9a-f]*\(.*runtime' <<<"$info" || { echo "✗ $name lacks the hardened runtime; it must be re-signed before notarizing" >&2; exit 1; }
  grep -q '^Timestamp=' <<<"$info" || { echo "✗ $name has no secure timestamp; it must be re-signed before notarizing" >&2; exit 1; }

  echo "Notarizing $name (this can take a few minutes) …"
  (cd "$dir" && /usr/bin/ditto -c -k --keepParent certifly "$work/$name.zip")
  xcrun notarytool submit "$work/$name.zip" --keychain-profile "$profile" --wait
done

echo "Checking with Gatekeeper …"
for bin in "$work"/*_darwin_*/certifly; do
  spctl --assess --type execute --verbose=2 "$bin" 2>&1 | sed "s|$work/||"
done
echo "✓ $tag notarized. The release files are unchanged."
