#!/bin/sh
# Entire body is parsed before running, including when downloaded through a pipe.
(
set -eu
umask 077
case "${1-}" in
  uninstall) shift; set -- --uninstall "$@";;
esac
version=''
expect_version=0
for argument do
  if [ "$expect_version" = 1 ]; then version=${argument#v}; expect_version=0; continue; fi
  [ "$argument" != --version ] || expect_version=1
done
[ "$expect_version" = 0 ] || { echo '--version requires x.y.z.' >&2; exit 2; }
if [ -z "$version" ]; then
  version=$(curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 \
    https://raw.githubusercontent.com/avazar/zaslon/dev/INSTALL_VERSION)
  version=$(printf '%s' "$version" | tr -d '\r')
fi
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
  echo 'The published installer version must be x.y.z.' >&2; exit 2;
}
work=$(mktemp -d "${TMPDIR:-/tmp}/zaslon-bootstrap.XXXXXXXX")
cleanup() {
  rm -f -- "$work/install.sh" "$work/SHA256SUMS.txt"
  rmdir -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
base="https://github.com/avazar/zaslon/releases/download/v$version"
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 "$base/install.sh" -o "$work/install.sh"
curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 "$base/SHA256SUMS.txt" -o "$work/SHA256SUMS.txt"
expected=$(awk '$2=="install.sh" { n++; if(NF!=2 || length($1)!=64 || $1!~/^[[:xdigit:]]+$/)exit 1; print tolower($1) } END { if(n!=1)exit 1 }' "$work/SHA256SUMS.txt")
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$work/install.sh" | awk '{print tolower($1)}')
else actual=$(shasum -a 256 "$work/install.sh" | awk '{print tolower($1)}'); fi
[ "$expected" = "$actual" ] || { echo 'Installer checksum mismatch.' >&2; exit 1; }
# The release installer owns installation/recovery checks and never reads the pipe.
sh "$work/install.sh" --version "$version" "$@" </dev/null
)
