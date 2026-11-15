#!/bin/bash
# Builds complete versioned Windows ZIPs, including the independent recovery helper.
# No cgo on Windows, so this cross-compiles from macOS or Linux.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(tr -d '\r\n' < VERSION)}"
VERSION="${VERSION#v}"
mkdir -p dist build/package
go run ./tools/mkicons build/icons
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid version' >&2; exit 1; }

# Restore pre-existing resources even if a cross-build fails.
repo="$(pwd -P)"
backup="$(mktemp -d "$repo/build/resource-backup.XXXXXX")"
for package in zaslon zaslon-recover; do
  for arch in amd64 arm64; do
    resource="cmd/$package/rsrc_windows_$arch.syso"
    if [ -f "$resource" ]; then cp "$resource" "$backup/$package-$arch.syso"; fi
  done
done
cleanup() {
  for package in zaslon zaslon-recover; do
    for arch in amd64 arm64; do
      resource="$repo/cmd/$package/rsrc_windows_$arch.syso"
      if [ -f "$backup/$package-$arch.syso" ]; then cp "$backup/$package-$arch.syso" "$resource"
      else rm -f "$resource"; fi
    done
  done
  case "$backup" in "$repo"/build/resource-backup.*) rm -r -- "$backup" ;; *) return 1 ;; esac
}
trap cleanup EXIT
for package in zaslon zaslon-recover; do
  manifest=gui
  description='Zaslon - application network protection'
  if [ "$package" = zaslon-recover ]; then manifest=cli; description='Zaslon - process recovery'; fi
  (cd "cmd/$package" && go run github.com/tc-hib/go-winres@v0.3.3 simply \
    --icon ../../build/icons/zaslon.ico --manifest "$manifest" \
    --product-name Zaslon --file-description "$description" \
    --copyright "ef1m03, Efimov Dev, MIT" --original-filename "$package.exe" \
    --product-version "$VERSION" --file-version "$VERSION" --arch amd64,arm64)
done
for arch in ${ARCHES:-amd64 arm64}; do
  target="build/package/windows-$arch"
  mkdir -p "$target"
  CGO_ENABLED=0 GOOS=windows GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -H windowsgui -X main.version=$VERSION" -o "$target/zaslon.exe" ./cmd/zaslon
  CGO_ENABLED=0 GOOS=windows GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "$target/zaslon-recover.exe" ./cmd/zaslon-recover
  go run ./tools/package -os windows -arch "$arch" -version "$VERSION" \
    -main "$target/zaslon.exe" -recover "$target/zaslon-recover.exe"
done
