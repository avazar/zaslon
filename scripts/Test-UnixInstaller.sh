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
install() { sh "$repo/scripts/install.sh" --version "$version" --package "$archive" --checksums "$archive.sha256" --no-start "$@"; }
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
