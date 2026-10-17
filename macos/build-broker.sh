#!/bin/bash
# Build only. Installation/provisioning requires its separate trusted package.
set -euo pipefail
AC_BROKER_SOURCE=$(cd -- "$(dirname -- "$0")/.." && pwd)
AC_BROKER_OUTPUT=${1:-"$AC_BROKER_SOURCE/dist/system-broker"}
mkdir -p "$AC_BROKER_OUTPUT"
AC_BROKER_TEMP=$(mktemp -d)
trap 'rm -rf -- "$AC_BROKER_TEMP"' EXIT
AC_BROKER_SWIFT=(RootVaultKeyStore RootWorkerChannel WorkerBootstrap OwnerGateway OwnerGatewayHost OwnerAuthorizationPolicy RootActivatedListeners RootWorkerProcess RootWorkerSupervisor RootMessagesCollector RootBrokerHost RootStoreInitializer RootStorePublication RootInitialEnrollment SystemBroker)
AC_BROKER_FILES=()
for AC_BROKER_FILE in "${AC_BROKER_SWIFT[@]}"; do AC_BROKER_FILES+=("$AC_BROKER_SOURCE/macos/$AC_BROKER_FILE.swift"); done
for AC_BROKER_ARCH in arm64 x86_64; do
  xcrun clang -arch "$AC_BROKER_ARCH" -mmacosx-version-min=14.0 -O2 -Wall -Wextra -Werror \
    -c "$AC_BROKER_SOURCE/macos/KeychainInteraction.c" -o "$AC_BROKER_TEMP/keychain-$AC_BROKER_ARCH.o"
  xcrun clang -arch "$AC_BROKER_ARCH" -mmacosx-version-min=14.0 -O2 -Wall -Wextra -Werror \
    -c "$AC_BROKER_SOURCE/macos/NativeBroker.c" -o "$AC_BROKER_TEMP/native-$AC_BROKER_ARCH.o"
  xcrun swiftc -O -parse-as-library -warnings-as-errors -D ACCOUNT_ACCESS_SYSTEM_BROKER_MAIN \
    -target "$AC_BROKER_ARCH-apple-macos14" -framework Foundation -framework Security -framework CryptoKit \
    -import-objc-header "$AC_BROKER_SOURCE/macos/NativeBroker.h" "${AC_BROKER_FILES[@]}" \
    "$AC_BROKER_TEMP/keychain-$AC_BROKER_ARCH.o" "$AC_BROKER_TEMP/native-$AC_BROKER_ARCH.o" -o "$AC_BROKER_TEMP/broker-$AC_BROKER_ARCH"
  xcrun swiftc -O -parse-as-library -warnings-as-errors -D ACCOUNT_ACCESS_WORKER_BOOTSTRAP_MAIN \
    -target "$AC_BROKER_ARCH-apple-macos14" -framework Foundation "$AC_BROKER_SOURCE/macos/WorkerBootstrap.swift" \
    -o "$AC_BROKER_TEMP/bootstrap-$AC_BROKER_ARCH"
done
for AC_BROKER_KIND in broker bootstrap; do
  xcrun lipo -create "$AC_BROKER_TEMP/$AC_BROKER_KIND-arm64" "$AC_BROKER_TEMP/$AC_BROKER_KIND-x86_64" \
    -output "$AC_BROKER_OUTPUT/AccountAccess-$AC_BROKER_KIND"
  if [[ -n "${ACCOUNT_ACCESS_SIGNING_IDENTITY:-}" ]]; then
    codesign --force --options runtime --timestamp --identifier "com.fainir.accountaccess.$AC_BROKER_KIND" \
      --sign "$ACCOUNT_ACCESS_SIGNING_IDENTITY" "$AC_BROKER_OUTPUT/AccountAccess-$AC_BROKER_KIND"
  else
    codesign --force --options runtime --identifier "com.fainir.accountaccess.$AC_BROKER_KIND" \
      --sign - "$AC_BROKER_OUTPUT/AccountAccess-$AC_BROKER_KIND"
  fi
  codesign --verify --strict "$AC_BROKER_OUTPUT/AccountAccess-$AC_BROKER_KIND"
done
