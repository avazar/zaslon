#!/bin/bash
# Native acceptance test: private HOME/XDG, offline archives, no guard startup.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
version="$(tr -d '\r\n' < "$repo/VERSION")"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/zaslon-installer-test.XXXXXXXX")"
cleanup() {
  case "$test_root" in "${TMPDIR:-/tmp}"/zaslon-installer-test.*) rm -rf -- "$test_root";; *) return 1;; esac
}
trap cleanup EXIT
export HOME="$test_root/home"
export XDG_CONFIG_HOME="$test_root/config"
export XDG_DATA_HOME="$test_root/data"
unset ZASLON_DIR
mkdir -p "$HOME"
case "$(uname -s)" in
  Darwin)
    archive="$repo/dist/zaslon-$version-macos-universal.zip"
    target="$HOME/Library/Application Support/Zaslon/program"
    profile="$HOME/Library/Application Support/Zaslon"
    binary="$target/Zaslon.app/Contents/MacOS/zaslon"
    helper="$target/Zaslon.app/Contents/MacOS/zaslon-recover"
    launcher="$HOME/Applications/Zaslon.app";;
  Linux)
    archive="$repo/dist/zaslon-$version-linux-amd64.tar.gz"
    target="$XDG_DATA_HOME/zaslon/program"; profile="$XDG_CONFIG_HOME/zaslon"
    binary="$target/zaslon"; helper="$target/zaslon-recover"
    launcher="$HOME/.local/bin/zaslon";;
  *) echo 'Native Unix test only.' >&2; exit 2;;
esac
# Exercise the public pipe entry point with the real installer and offline package.
# curl serves only the two local release fixtures; no external downloads are made.
mkdir -p "$test_root/bin"
export ZASLON_TEST_INSTALLER_VERSION="$version"
export ZASLON_TEST_INSTALLER_SCRIPT="$test_root/release-install.sh"
export ZASLON_TEST_INSTALLER_SUMS="$test_root/release-sums.txt"
sed "s/__ZASLON_VERSION__/$version/g" "$repo/scripts/install.sh" > "$ZASLON_TEST_INSTALLER_SCRIPT"
if command -v sha256sum >/dev/null 2>&1; then
  installer_hash="$(sha256sum "$ZASLON_TEST_INSTALLER_SCRIPT" | awk '{print $1}')"
else installer_hash="$(shasum -a 256 "$ZASLON_TEST_INSTALLER_SCRIPT" | awk '{print $1}')"; fi
printf '%s  install.sh\n' "$installer_hash" > "$ZASLON_TEST_INSTALLER_SUMS"
cat > "$test_root/bin/curl" <<'CURL'
#!/bin/sh
set -eu
url=''; output=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2;;
    --proto|--connect-timeout|--max-time) shift 2;;
    -fsSL|--tlsv1.2) shift;;
    https://*) url=$1; shift;;
    *) echo "Unexpected curl argument: $1" >&2; exit 2;;
  esac
done
base="https://github.com/avazar/zaslon/releases/download/v$ZASLON_TEST_INSTALLER_VERSION"
case "$url" in
  "$base/install.sh") cp "$ZASLON_TEST_INSTALLER_SCRIPT" "$output";;
  "$base/SHA256SUMS.txt") cp "$ZASLON_TEST_INSTALLER_SUMS" "$output";;
  *) echo "Unexpected external request: $url" >&2; exit 2;;
esac
CURL
chmod 700 "$test_root/bin/curl"
export PATH="$test_root/bin:$PATH"
install() { cat "$repo/install.sh" | sh -s -- --version "$version" --package "$archive" --checksums "$archive.sha256" --no-start "$@"; }
# Existing user launchers must never be replaced.
mkdir -p "$(dirname "$launcher")"
printf 'keep user data\n' > "$launcher"
if install; then echo 'Foreign launcher was accepted.' >&2; exit 1; fi
test "$(cat "$launcher")" = 'keep user data'
rm -- "$launcher"
install
test -L "$launcher"
test "$("$binary" version)" = "zaslon $version"
test "$("$helper" -version)" = "zaslon-recover $version"
if [ "$(uname -s)" = Darwin ]; then codesign --verify --deep --strict "$target/Zaslon.app"; fi
printf 'apps: []\n' > "$profile/config.yaml"
cp "$profile/config.yaml" "$test_root/config-before"
printf '{"version":1,"entries":{"123":{"phase":"frozen"}}}\n' > "$profile/process-recovery.json"
cp "$profile/process-recovery.json" "$test_root/journal-before"
install
cmp "$profile/config.yaml" "$test_root/config-before"
cmp "$profile/process-recovery.json" "$test_root/journal-before"
test -f "$target/install-receipt.json"
if install --uninstall; then echo 'Uninstall accepted unresolved recovery.' >&2; exit 1; fi
test -f "$helper"
printf '{"version":1,"entries":{}}\n' > "$profile/process-recovery.json"
install --uninstall
cmp "$profile/config.yaml" "$test_root/config-before"
test ! -e "$binary"
test ! -e "$launcher"
test ! -L "$launcher"
echo 'Unix installer passed: install, update, complete helper, launchers, settings/journal preservation, safe uninstall.'
