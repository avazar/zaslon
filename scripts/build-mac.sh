#!/bin/bash
# Builds a complete universal app and versioned ZIP with the recovery helper.
# The ad-hoc signature is verified after extraction; no Developer ID/notarization.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(tr -d '\r\n' < VERSION)}"
VERSION="${VERSION#v}"
APP=dist/Zaslon.app
rm -rf "$APP" build/mac
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" build/mac

for arch in arm64 amd64; do
  carch=$([ $arch = amd64 ] && echo x86_64 || echo arm64)
  # The panel window (WebKit) has C++ parts, so both compilers get the target arch.
  CC="clang -arch $carch" CXX="clang++ -arch $carch" CGO_CXXFLAGS="-Wno-deprecated-literal-operator" \
  CGO_ENABLED=1 GOOS=darwin GOARCH=$arch MACOSX_DEPLOYMENT_TARGET=11.0 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o build/mac/zaslon-$arch ./cmd/zaslon
  CGO_ENABLED=0 GOOS=darwin GOARCH=$arch MACOSX_DEPLOYMENT_TARGET=11.0 \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o build/mac/zaslon-recover-$arch ./cmd/zaslon-recover
done
lipo -create build/mac/zaslon-arm64 build/mac/zaslon-amd64 -output "$APP/Contents/MacOS/zaslon"
lipo -create build/mac/zaslon-recover-arm64 build/mac/zaslon-recover-amd64 -output "$APP/Contents/MacOS/zaslon-recover"

go run ./tools/mkicons build/icons
iconutil -c icns build/icons/Zaslon.iconset -o "$APP/Contents/Resources/Zaslon.icns"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Zaslon</string>
  <key>CFBundleDisplayName</key><string>Zaslon</string>
  <key>CFBundleIdentifier</key><string>io.github.avazar.zaslon</string>
  <key>CFBundleExecutable</key><string>zaslon</string>
  <key>CFBundleIconFile</key><string>Zaslon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHumanReadableCopyright</key><string>ef1m03 · Efimov Dev · MIT</string>
</dict>
</plist>
EOF

codesign --force --sign - "$APP/Contents/MacOS/zaslon-recover"
codesign --force --deep --sign - "$APP"
go run ./tools/package -os darwin -arch universal -version "$VERSION" \
  -main "$APP" -recover "$APP/Contents/MacOS/zaslon-recover"
echo "built $APP ($VERSION)"
