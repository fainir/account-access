#!/bin/sh
# Build the genuine macOS installer/owner app. Developer ID signing is optional
# for local development; public distribution requires signing and notarization.
set -eu
AC_SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
AC_OUTPUT="$AC_SOURCE/dist/macos"
AC_APP="$AC_OUTPUT/Account Access.app"
mkdir -p "$AC_APP/Contents/MacOS" "$AC_APP/Contents/Resources"
for AC_ARCH in arm64 x86_64; do
  xcrun swiftc -O -parse-as-library -target "$AC_ARCH-apple-macos13" \
    -framework AppKit -framework CryptoKit -lsqlite3 \
    "$AC_SOURCE/macos/AccountAccess.swift" "$AC_SOURCE/macos/MessagesReader.swift" -o "$AC_OUTPUT/AccountAccess-$AC_ARCH"
done
lipo -create "$AC_OUTPUT/AccountAccess-arm64" "$AC_OUTPUT/AccountAccess-x86_64" \
  -output "$AC_APP/Contents/MacOS/AccountAccess"
cp "$AC_SOURCE/install.sh" "$AC_APP/Contents/Resources/install.sh"
cat > "$AC_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.fainir.accountaccess</string>
<key>CFBundleName</key><string>Account Access</string>
<key>CFBundleDisplayName</key><string>Account Access</string>
<key>CFBundleExecutable</key><string>AccountAccess</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.6.0</string>
<key>CFBundleVersion</key><string>7</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
if [ -n "${ACCOUNT_ACCESS_SIGNING_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp \
    --sign "$ACCOUNT_ACCESS_SIGNING_IDENTITY" "$AC_APP"
else
  codesign --force --sign - "$AC_APP"
fi
ditto -c -k --keepParent "$AC_APP" "$AC_OUTPUT/Account-Access-Mac.zip"
printf '%s\n' "$AC_OUTPUT/Account-Access-Mac.zip"
