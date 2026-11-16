#!/bin/bash
# Pipe entry point, mocked HTTPS downloads, no application or installer startup.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/zaslon-bootstrap-test.XXXXXXXX")"
# Keep the original prefix for cleanup when TMPDIR is isolated below.
original_tmp="${TMPDIR:-/tmp}"
cleanup() {
  case "$test_root" in "$original_tmp"/zaslon-bootstrap-test.*) rm -rf -- "$test_root";; *) return 1;; esac
}
trap cleanup EXIT
mkdir -p "$test_root/bin" "$test_root/tmp"
export TMPDIR="$test_root/tmp"
export ZASLON_BOOTSTRAP_FIXTURE="$test_root"
export ZASLON_BOOTSTRAP_FIXTURE_VERSION="$(tr -d '\r\n' < "$repo/INSTALL_VERSION")"
export ZASLON_BOOTSTRAP_FIXTURE_MODE=ok
export PATH="$test_root/bin:$PATH"
cat > "$test_root/backend.sh" <<'BACKEND'
#!/bin/sh
set -eu
: > "$ZASLON_BOOTSTRAP_FIXTURE/capture"
for argument do printf '%s\n' "$argument" >> "$ZASLON_BOOTSTRAP_FIXTURE/capture"; done
if IFS= read -r unexpected; then echo 'Backend read bootstrap stdin.' >&2; exit 1; fi
BACKEND
if command -v sha256sum >/dev/null 2>&1; then
  hash="$(sha256sum "$test_root/backend.sh" | awk '{print $1}')"
else hash="$(shasum -a 256 "$test_root/backend.sh" | awk '{print $1}')"; fi
printf '%s  install.sh\n' "$hash" > "$test_root/SHA256SUMS.txt"
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
printf '%s\n' "$url" >> "$ZASLON_BOOTSTRAP_FIXTURE/requests"
base="https://github.com/avazar/zaslon/releases/download/v$ZASLON_BOOTSTRAP_FIXTURE_VERSION"
case "$url" in
  https://raw.githubusercontent.com/avazar/zaslon/dev/INSTALL_VERSION)
    if [ "$ZASLON_BOOTSTRAP_FIXTURE_MODE" = invalid-version ]; then printf '../../outside\n'
    else printf '%s\n' "$ZASLON_BOOTSTRAP_FIXTURE_VERSION"; fi;;
  "$base/install.sh")
    cp "$ZASLON_BOOTSTRAP_FIXTURE/backend.sh" "$output"
    if [ "$ZASLON_BOOTSTRAP_FIXTURE_MODE" = partial-download ]; then exit 22; fi
    if [ "$ZASLON_BOOTSTRAP_FIXTURE_MODE" = tampered ]; then printf '# changed\n' >> "$output"; fi;;
  "$base/SHA256SUMS.txt")
    cp "$ZASLON_BOOTSTRAP_FIXTURE/SHA256SUMS.txt" "$output"
    if [ "$ZASLON_BOOTSTRAP_FIXTURE_MODE" = duplicate ]; then cat "$ZASLON_BOOTSTRAP_FIXTURE/SHA256SUMS.txt" >> "$output"; fi
    if [ "$ZASLON_BOOTSTRAP_FIXTURE_MODE" = missing ]; then sed 's/install.sh/other.sh/' "$ZASLON_BOOTSTRAP_FIXTURE/SHA256SUMS.txt" > "$output"; fi;;
  *) echo "Unexpected URL: $url" >&2; exit 2;;
esac
CURL
chmod 700 "$test_root/bin/curl"
cat "$repo/install.sh" | sh
printf '%s\n' --version "$ZASLON_BOOTSTRAP_FIXTURE_VERSION" > "$test_root/expected"
cmp "$test_root/capture" "$test_root/expected"
cat "$repo/install.sh" | sh -s uninstall --no-start --install-dir '/program path'
printf '%s\n' --version "$ZASLON_BOOTSTRAP_FIXTURE_VERSION" --uninstall --no-start --install-dir '/program path' > "$test_root/expected"
cmp "$test_root/capture" "$test_root/expected"
export ZASLON_BOOTSTRAP_FIXTURE_VERSION=2.0.0
: > "$test_root/requests"
cat "$repo/install.sh" | sh -s -- --version 2.0.0 --no-start
printf '%s\n' --version 2.0.0 --version 2.0.0 --no-start > "$test_root/expected"
cmp "$test_root/capture" "$test_root/expected"
test "$(wc -l < "$test_root/requests" | tr -d ' ')" = 2
for mode in invalid-version tampered duplicate missing partial-download; do
  rm -f -- "$test_root/capture"
  export ZASLON_BOOTSTRAP_FIXTURE_MODE="$mode"
  if cat "$repo/install.sh" | sh; then echo "Unsafe bootstrap accepted: $mode" >&2; exit 1; fi
  test ! -e "$test_root/capture"
  test -z "$(ls -A "$TMPDIR")"
done
export ZASLON_BOOTSTRAP_FIXTURE_MODE=ok
: > "$test_root/requests"
test "$(tail -n 1 "$repo/install.sh")" = ')'
if sed '$d' "$repo/install.sh" | sh; then echo 'Truncated bootstrap was accepted.' >&2; exit 1; fi
test ! -s "$test_root/requests"
test -z "$(ls -A "$TMPDIR")"
echo 'Unix bootstrap passed: piped install/uninstall, arguments, version selection, checksum and interrupted-download rejection.'
