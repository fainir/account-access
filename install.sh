#!/bin/sh
# Official Account Access bootstrap. No Git, Python, uv, or admin rights needed on macOS.
set -eu
umask 077
AC_VERSION=0.8.0
AC_RELEASE="https://github.com/fainir/account-access/releases/download/v$AC_VERSION"
AC_RUNTIME="${ACCOUNT_ACCESS_INSTALL_DIR:-$HOME/.local/share/account-access/runtime}"
AC_SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/account-access-install.XXXXXX")
trap 'rm -rf "$AC_SCRATCH"' EXIT HUP INT TERM
case "$(uname -s)" in
  Darwin)
    AC_MAC_VERSION=$(sw_vers -productVersion 2>/dev/null || true)
    AC_MAC_MAJOR=${AC_MAC_VERSION%%.*}
    case "$AC_MAC_MAJOR" in
      ''|*[!0-9]*) echo "Could not verify macOS. Account Access requires macOS 14 or later."; exit 1 ;;
    esac
    if [ ${#AC_MAC_MAJOR} -gt 3 ] || [ "$AC_MAC_MAJOR" -lt 14 ]; then
      echo "Account Access requires macOS 14 (Sonoma) or later. Update macOS before installing."
      exit 1
    fi ;;
  Linux) ;;
  *) echo "This installer supports macOS and Linux. Windows is not supported yet."; exit 1 ;;
esac
printf '\nAccount Access\nInstalling what you need. No developer setup required.\n\n'
mkdir -p "$AC_RUNTIME"
if [ -x "$AC_RUNTIME/uv/uv" ]; then
  # Finder-launched apps have a smaller PATH than a terminal. Reuse the
  # bootstrap installed by the earlier setup instead of downloading it again.
  AC_UV="$AC_RUNTIME/uv/uv"
elif command -v uv >/dev/null 2>&1; then
  AC_UV=$(command -v uv)
elif [ -x "$HOME/.local/bin/uv" ]; then
  AC_UV="$HOME/.local/bin/uv"
else
  printf '1/4 Preparing the installer…\n'
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 https://astral.sh/uv/install.sh -o "$AC_SCRATCH/uv-install.sh"
  UV_INSTALL_DIR="$AC_RUNTIME/uv" UV_NO_MODIFY_PATH=1 sh "$AC_SCRATCH/uv-install.sh"
  AC_UV="$AC_RUNTIME/uv/uv"
fi
AC_WHEEL="account_access-$AC_VERSION-py3-none-any.whl"
AC_PINNED="${ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256:-}"
printf '2/4 Downloading Account Access…\n'
if [ -n "${ACCOUNT_ACCESS_BUNDLED_WHEEL:-}" ]; then
  # The native app supplies the resource from its signed bundle and its pinned
  # hash. Refuse a missing pin; a path alone is never a trust decision.
  if [ ${#AC_PINNED} -ne 64 ]; then
    echo "Bundled package verification failed. Installation stopped."; exit 1
  fi
  cp "$ACCOUNT_ACCESS_BUNDLED_WHEEL" "$AC_SCRATCH/$AC_WHEEL"
  AC_EXPECTED="$AC_PINNED"
else
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$AC_RELEASE/$AC_WHEEL" -o "$AC_SCRATCH/$AC_WHEEL"
  curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$AC_RELEASE/SHA256SUMS" -o "$AC_SCRATCH/SHA256SUMS"
  AC_EXPECTED=$(awk -v file="$AC_WHEEL" '$2 == file { print $1 }' "$AC_SCRATCH/SHA256SUMS")
fi
if command -v shasum >/dev/null 2>&1; then
  AC_ACTUAL=$(shasum -a 256 "$AC_SCRATCH/$AC_WHEEL" | awk '{ print $1 }')
elif command -v sha256sum >/dev/null 2>&1; then
  AC_ACTUAL=$(sha256sum "$AC_SCRATCH/$AC_WHEEL" | awk '{ print $1 }')
else
  echo "A SHA-256 verification tool is required. Installation stopped."; exit 1
fi
if [ ${#AC_EXPECTED} -ne 64 ] || [ "$AC_EXPECTED" != "$AC_ACTUAL" ] || \
   { [ -n "$AC_PINNED" ] && [ "$AC_PINNED" != "$AC_ACTUAL" ]; }; then
  echo "Download verification failed. Installation stopped."; exit 1
fi
printf '3/4 Preparing Python and the secure local app…\n'
"$AC_UV" python install 3.13
AC_PYTHON=$("$AC_UV" python find --managed-python 3.13)
# Extract only the stdlib bootstrap and dependency lock from the verified wheel.
# No imported application or registry package runs before hash enforcement.
"$AC_PYTHON" -I - "$AC_SCRATCH/$AC_WHEEL" "$AC_SCRATCH" <<'PY'
import sys, zipfile
from pathlib import Path
with zipfile.ZipFile(sys.argv[1]) as wheel:
    for name in ['runtime_bootstrap.py', 'runtime-requirements.txt']:
        entry = wheel.getinfo('account_access/' + name)
        if entry.file_size > 256000:
            raise SystemExit('Installer resource exceeds its limit.')
        Path(sys.argv[2], name).write_bytes(wheel.read(entry))
PY
"$AC_PYTHON" -I "$AC_SCRATCH/runtime_bootstrap.py" "$AC_UV" "$AC_SCRATCH/$AC_WHEEL" \
  "$AC_RUNTIME" "$AC_SCRATCH/runtime-requirements.txt" "${ACCOUNT_ACCESS_DATA_DIR:-}" \
  "${ACCOUNT_ACCESS_NO_OPEN:-0}"
if [ "$(uname -s)" = Linux ]; then
  printf 'Linux may need browser system libraries and sandbox policy. See the Linux setup guide.\n'
fi
