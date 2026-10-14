#!/bin/sh
set -eu
umask 077
AC_SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
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
mkdir -p "$AC_OUTPUT/test-classes" "$AC_OUTPUT/test-dex"
"$AC_JAVA/bin/javac" -source 8 -target 8 -encoding UTF-8 -classpath "$AC_PLATFORM:$AC_OUTPUT/app-classes.jar" -d "$AC_OUTPUT/test-classes" "$AC_SOURCE"/android/test/src/com/fainir/accountaccess/*.java
"$AC_JAVA/bin/jar" cf "$AC_OUTPUT/test-classes.jar" -C "$AC_OUTPUT/test-classes" .
"$AC_TOOLS/d8" --min-api 26 --lib "$AC_PLATFORM" --lib "$AC_OUTPUT/app-classes.jar" --output "$AC_OUTPUT/test-dex" "$AC_OUTPUT/test-classes.jar"
"$AC_TOOLS/aapt2" link -I "$AC_PLATFORM" --manifest "$AC_SOURCE/android/test/AndroidManifest.xml" -o "$AC_OUTPUT/test-unsigned.apk"
(cd "$AC_OUTPUT/test-dex" && zip -q "$AC_OUTPUT/test-unsigned.apk" classes*.dex)
"$AC_TOOLS/zipalign" -f 4 "$AC_OUTPUT/test-unsigned.apk" "$AC_OUTPUT/test-aligned.apk"
"$AC_TOOLS/apksigner" sign --ks "$AC_OUTPUT/preview.keystore" --ks-key-alias preview --ks-pass pass:account-access-preview --key-pass pass:account-access-preview --out "$AC_OUTPUT/Account-Access-Phone-tests.apk" "$AC_OUTPUT/test-aligned.apk"
