#!/bin/sh
# Build the genuine macOS installer/owner app. Developer ID signing is optional
# for local development; public distribution requires signing and notarization.
set -eu
AC_SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
AC_OUTPUT=${ACCOUNT_ACCESS_MAC_OUTPUT:-"$AC_SOURCE/dist/macos"}
AC_APP="$AC_OUTPUT/Account Access.app"
AC_WHEEL="$AC_SOURCE/dist/account_access-0.8.0-py3-none-any.whl"
if [ ! -f "$AC_WHEEL" ]; then
  echo "Build the 0.8.0 wheel with uv build before building the Mac installer." >&2
  exit 1
fi
# The runtime lock is shipped inside the signed wheel. Refuse a source lock that
# differs from the dependency graph exercised in CI.
AC_LOCK_CHECK=$(mktemp)
trap 'rm -f "$AC_LOCK_CHECK"' EXIT HUP INT TERM
uv export --project "$AC_SOURCE" --locked --no-dev --no-emit-project --no-annotate --no-header \
  --format requirements.txt --output-file "$AC_LOCK_CHECK" > /dev/null
if ! cmp -s "$AC_SOURCE/account_access/runtime-requirements.txt" "$AC_LOCK_CHECK"; then
  echo "Refresh the runtime dependency export from uv.lock and rebuild the wheel first." >&2
  exit 1
fi
AC_WHEEL_HASH=$(shasum -a 256 "$AC_WHEEL" | awk '{ print $1 }')
mkdir -p "$AC_APP/Contents/MacOS" "$AC_APP/Contents/Resources" "$AC_APP/Contents/Library/LaunchAgents"
for AC_ARCH in arm64 x86_64; do
  xcrun swiftc -O -parse-as-library -target "$AC_ARCH-apple-macos14" \
    -framework AppKit -framework CryptoKit -framework ServiceManagement -lsqlite3 -lbsm \
    "$AC_SOURCE/macos/AccountAccess.swift" "$AC_SOURCE/macos/MailboxOAuthLoopback.swift" "$AC_SOURCE/macos/OwnerGateway.swift" "$AC_SOURCE/macos/DesktopOwnerConnection.swift" "$AC_SOURCE/macos/BrowserNativeHost.swift" "$AC_SOURCE/macos/ManagedAgentSetup.swift" "$AC_SOURCE/macos/WorkerBootstrap.swift" "$AC_SOURCE/macos/BackgroundRecovery.swift" "$AC_SOURCE/macos/MessageText.swift" "$AC_SOURCE/macos/MessagesReader.swift" "$AC_SOURCE/macos/SystemMessagesReader.swift" -o "$AC_OUTPUT/AccountAccess-$AC_ARCH"
  xcrun swiftc -O -parse-as-library -target "$AC_ARCH-apple-macos14" \
    -framework Foundation -framework CryptoKit -framework ServiceManagement \
    "$AC_SOURCE/macos/BackgroundRecovery.swift" "$AC_SOURCE/macos/BackgroundHost.swift" -o "$AC_OUTPUT/AccountAccessBackground-$AC_ARCH"
done
lipo -create "$AC_OUTPUT/AccountAccess-arm64" "$AC_OUTPUT/AccountAccess-x86_64" \
  -output "$AC_APP/Contents/MacOS/AccountAccess"
lipo -create "$AC_OUTPUT/AccountAccessBackground-arm64" "$AC_OUTPUT/AccountAccessBackground-x86_64" \
  -output "$AC_APP/Contents/MacOS/AccountAccessBackground"
cp "$AC_SOURCE/macos/com.fainir.accountaccess.background.plist" "$AC_APP/Contents/Library/LaunchAgents/"
cp "$AC_SOURCE/install.sh" "$AC_APP/Contents/Resources/install.sh"
cp "$AC_WHEEL" "$AC_APP/Contents/Resources/account_access.whl"
mkdir -p "$AC_APP/Contents/Resources/GoogleMessagesExtension"
for AC_BROWSER_FILE in manifest.json background.js reader.js popup.js popup.html popup.css; do
  cp "$AC_SOURCE/account_access/google_messages_extension/$AC_BROWSER_FILE" "$AC_APP/Contents/Resources/GoogleMessagesExtension/"
done
cat > "$AC_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.fainir.accountaccess</string>
<key>CFBundleName</key><string>Account Access</string>
<key>CFBundleDisplayName</key><string>Account Access</string>
<key>CFBundleExecutable</key><string>AccountAccess</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.8.0</string>
<key>CFBundleVersion</key><string>66</string>
<key>AccountAccessBackgroundFormat</key><integer>1</integer>
<key>AccountAccessBrowserExtensionFormat</key><integer>1</integer>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/libexec/PlistBuddy -c "Add :AccountAccessWheelSHA256 string $AC_WHEEL_HASH" "$AC_APP/Contents/Info.plist"
if [ "${ACCOUNT_ACCESS_SYSTEM_INSTALL:-0}" = 1 ]; then
  /usr/libexec/PlistBuddy -c 'Add :AccountAccessSystemInstallationRequired bool true' "$AC_APP/Contents/Info.plist"
fi
if [ -n "${ACCOUNT_ACCESS_SIGNING_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --identifier com.fainir.accountaccess.background \
    --sign "$ACCOUNT_ACCESS_SIGNING_IDENTITY" "$AC_APP/Contents/MacOS/AccountAccessBackground"
  codesign --force --options runtime --timestamp \
    --sign "$ACCOUNT_ACCESS_SIGNING_IDENTITY" "$AC_APP"
else
  codesign --force --identifier com.fainir.accountaccess.background --sign - "$AC_APP/Contents/MacOS/AccountAccessBackground"
  codesign --force --sign - "$AC_APP"
fi
ditto -c -k --keepParent "$AC_APP" "$AC_OUTPUT/Account-Access-Mac.zip"
printf '%s\n' "$AC_OUTPUT/Account-Access-Mac.zip"
