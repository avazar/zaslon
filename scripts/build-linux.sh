#!/bin/bash
# Builds complete versioned Linux tarballs; does not install or launch protection.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(tr -d '\r\n' < VERSION)}"
VERSION="${VERSION#v}"
for arch in ${ARCHES:-amd64 arm64}; do
  target="build/package/linux-$arch"
  mkdir -p "$target"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "$target/zaslon" ./cmd/zaslon
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "$target/zaslon-recover" ./cmd/zaslon-recover
  go run ./tools/package -os linux -arch "$arch" -version "$VERSION" \
    -main "$target/zaslon" -recover "$target/zaslon-recover"
done
