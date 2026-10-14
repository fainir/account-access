#!/bin/sh
# Reproducible preview APK: Android SDK + JDK 17, no Gradle or cloud build.
set -eu
umask 077
AC_SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
AC_OUTPUT="$AC_SOURCE/dist/android"
AC_SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
AC_JAVA="${ACCOUNT_ACCESS_JAVA_HOME:-${JAVA_HOME:-/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home}}"
if [ ! -x "$AC_JAVA/bin/javac" ] && [ -x /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home/bin/javac ]; then
 AC_JAVA=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
fi
AC_TOOLS="$AC_SDK/build-tools/36.0.0"
AC_PLATFORM="$AC_SDK/platforms/android-36/android.jar"
export JAVA_HOME="$AC_JAVA"
export PATH="$AC_JAVA/bin:$PATH"
mkdir -p "$AC_OUTPUT/classes" "$AC_OUTPUT/dex"
AC_ZXING="$AC_OUTPUT/zxing-core-3.5.3.jar"
if [ ! -f "$AC_ZXING" ]; then
 curl --proto '=https' --proto-redir '=https' -fL --retry 2 https://repo.maven.apache.org/maven2/com/google/zxing/core/3.5.3/core-3.5.3.jar -o "$AC_ZXING"
fi
if command -v shasum >/dev/null 2>&1; then
 AC_HASH=$(shasum -a 256 "$AC_ZXING" | awk '{print $1}')
else
 AC_HASH=$(sha256sum "$AC_ZXING" | awk '{print $1}')
fi
if [ "$AC_HASH" != 8d8064c1636fdaef7189dd9055c7d59950a8940a12f2293956446ec3c109fd82 ]; then
 echo 'QR library checksum mismatch. Build stopped.'; exit 1
fi
"$AC_JAVA/bin/javac" -source 8 -target 8 -encoding UTF-8 -classpath "$AC_PLATFORM:$AC_ZXING" -d "$AC_OUTPUT/classes" "$AC_SOURCE"/android/app/src/com/fainir/accountaccess/*.java
"$AC_JAVA/bin/jar" cf "$AC_OUTPUT/app-classes.jar" -C "$AC_OUTPUT/classes" .
"$AC_TOOLS/d8" --min-api 26 --lib "$AC_PLATFORM" --output "$AC_OUTPUT/dex" "$AC_OUTPUT/app-classes.jar" "$AC_ZXING"
"$AC_TOOLS/aapt2" link -I "$AC_PLATFORM" --manifest "$AC_SOURCE/android/app/AndroidManifest.xml" -o "$AC_OUTPUT/unsigned.apk"
(cd "$AC_OUTPUT/dex" && zip -q "$AC_OUTPUT/unsigned.apk" classes*.dex)
"$AC_TOOLS/zipalign" -f 4 "$AC_OUTPUT/unsigned.apk" "$AC_OUTPUT/aligned.apk"
AC_KEY="$AC_OUTPUT/preview.keystore"
if [ ! -f "$AC_KEY" ]; then
 "$AC_JAVA/bin/keytool" -genkeypair -keystore "$AC_KEY" -storepass account-access-preview -keypass account-access-preview -alias preview -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=Account Access development preview'
fi
"$AC_TOOLS/apksigner" sign --ks "$AC_KEY" --ks-key-alias preview --ks-pass pass:account-access-preview --key-pass pass:account-access-preview --out "$AC_OUTPUT/Account-Access-Phone-preview.apk" "$AC_OUTPUT/aligned.apk"
"$AC_TOOLS/apksigner" verify "$AC_OUTPUT/Account-Access-Phone-preview.apk"
printf '%s\n' "$AC_OUTPUT/Account-Access-Phone-preview.apk"
