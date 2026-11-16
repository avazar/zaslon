#!/bin/sh
# Per-user Linux/macOS bootstrap. Release packaging pins the default version.
# Extraction and replacement use the packaged helper under the profile lock.
set -eu
umask 077
version='__ZASLON_VERSION__'
archive=''
checksums=''
target=''
profile=${ZASLON_DIR:-}
no_start=0
no_links=0
headless=0
uninstall=0
custom_profile=0
[ -z "$profile" ] || custom_profile=1
usage() {
  echo 'Usage: sh install.sh [--version x.y.z] [--package ARCHIVE --checksums SHA256SUMS.txt] [--no-start] [--headless] [--uninstall]'
  echo 'Advanced: --install-dir ABSOLUTE_PATH; --profile-dir ABSOLUTE_PATH requires --no-links.'
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--package|--checksums|--install-dir|--profile-dir)
      [ "$#" -ge 2 ] || { echo "Missing value: $1" >&2; exit 2; }
      case "$1" in
        --version) version=${2#v};;
        --package) archive=$2;;
        --checksums) checksums=$2;;
        --install-dir) target=$2;;
        --profile-dir) profile=$2; custom_profile=1;;
      esac
      shift 2;;
    --no-start) no_start=1; shift;;
    --no-links) no_links=1; shift;;
    --headless) headless=1; shift;;
    --uninstall) uninstall=1; no_start=1; shift;;
    --help|-h) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2;;
  esac
done
case "$version" in ''|*[!0-9.]*) echo 'Invalid release version.' >&2; exit 2;; esac
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
  echo 'Use a pinned release installer or supply --version x.y.z.' >&2; exit 2;
}
[ "$custom_profile" = 0 ] || [ "$no_links" = 1 ] || { echo 'Custom profiles require --no-links.' >&2; exit 2; }
[ "$(id -u)" != 0 ] || { echo 'Run as your regular desktop user, without sudo.' >&2; exit 2; }
case "$(uname -s)" in
  Darwin)
    platform=macos; arch=universal; ext=zip
    [ -n "$target" ] || target="$HOME/Library/Application Support/Zaslon/program"
    [ -n "$profile" ] || profile="$HOME/Library/Application Support/Zaslon"
    member=Zaslon.app/Contents/MacOS/zaslon-recover;;
  Linux)
    platform=linux; ext=tar.gz; member=zaslon-recover
    case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported Linux architecture.' >&2; exit 2;; esac
    [ -n "$target" ] || target="${XDG_DATA_HOME:-$HOME/.local/share}/zaslon/program"
    [ -n "$profile" ] || profile="${XDG_CONFIG_HOME:-$HOME/.config}/zaslon";;
  *) echo 'This installer supports Linux and macOS.' >&2; exit 2;;
esac
name="zaslon-$version-$platform-$arch.$ext"
work=$(mktemp -d "${TMPDIR:-/tmp}/zaslon-install.XXXXXXXX")
cleanup() {
  case "$work" in "${TMPDIR:-/tmp}"/zaslon-install.*) rm -rf -- "$work";; *) return 1;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
if [ -n "$archive" ]; then
  [ -n "$checksums" ] || { echo '--package requires --checksums from the trusted release.' >&2; exit 2; }
  cp -- "$archive" "$work/$name"
  cp -- "$checksums" "$work/SHA256SUMS.txt"
else
  [ -z "$checksums" ] || { echo '--checksums requires --package.' >&2; exit 2; }
  base="https://github.com/avazar/zaslon/releases/download/v$version"
  curl -fL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 "$base/$name" -o "$work/$name"
  curl -fL --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 30 "$base/SHA256SUMS.txt" -o "$work/SHA256SUMS.txt"
fi
expected=$(awk -v name="$name" '$2==name { n++; if(NF!=2 || length($1)!=64 || $1!~/^[[:xdigit:]]+$/)exit 1; print tolower($1) } END { if(n!=1)exit 1 }' "$work/SHA256SUMS.txt")
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$work/$name" | awk '{print tolower($1)}')
else actual=$(shasum -a 256 "$work/$name" | awk '{print tolower($1)}'); fi
[ "$expected" = "$actual" ] || { echo 'Archive checksum mismatch.' >&2; exit 1; }
# Only one fixed member is written to a known fresh file. No archive paths
# become extraction destinations; the helper validates every complete entry.
if [ "$platform" = macos ]; then unzip -p "$work/$name" "$member" > "$work/helper"
else tar -xOzf "$work/$name" "$member" > "$work/helper"; fi
chmod 700 "$work/helper"
set -- "$work/helper" -install-dir "$target"
if [ "$custom_profile" = 1 ]; then set -- "$@" -dir "$profile"; fi
if [ "$no_links" = 1 ]; then set -- "$@" -no-links; fi
if [ "$uninstall" = 1 ]; then set -- "$@" -uninstall
else set -- "$@" -install-archive "$work/$name" -package-version "$version"; fi
"$@"
if [ "$uninstall" = 1 ]; then echo 'Zaslon removed; settings and backups kept.'; exit 0; fi
echo "Installed Zaslon $version: $target"
echo "Previous files, if any: $target.backup-*"
if [ "$no_start" = 0 ]; then
  if [ "$custom_profile" = 1 ]; then export ZASLON_DIR="$profile"; fi
  if [ "$platform" = macos ] && [ "$headless" = 0 ]; then open "$target/Zaslon.app"
  else
    binary="$target/zaslon"
    [ "$platform" != macos ] || binary="$target/Zaslon.app/Contents/MacOS/zaslon"
    if [ "$headless" = 1 ]; then set -- "$binary" headless; else set -- "$binary"; fi
    nohup "$@" </dev/null >"$profile/installer-startup.log" 2>&1 &
    echo 'Startup requested; verify protection in the panel.'
  fi
fi
