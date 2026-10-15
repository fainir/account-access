#!/bin/sh
# Official Account Access bootstrap. No Git, Python, uv, or admin rights needed on macOS.
set -eu
umask 077
AC_VERSION=0.7.2
AC_RELEASE="https://github.com/fainir/account-access/releases/download/v$AC_VERSION"
AC_RUNTIME="${ACCOUNT_ACCESS_INSTALL_DIR:-$HOME/.local/share/account-access/runtime}"
AC_SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/account-access-install.XXXXXX")
trap 'rm -rf "$AC_SCRATCH"' EXIT HUP INT TERM
case "$(uname -s)" in
  Darwin|Linux) ;;
  *) echo "This installer supports macOS and Linux. Windows is not supported yet."; exit 1 ;;
esac
printf '\nAccount Access\nInstalling what you need. No developer setup required.\n\n'
mkdir -p "$AC_RUNTIME"
if command -v uv >/dev/null 2>&1; then
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
printf '2/4 Downloading Account Access…\n'
curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$AC_RELEASE/$AC_WHEEL" -o "$AC_SCRATCH/$AC_WHEEL"
curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "$AC_RELEASE/SHA256SUMS" -o "$AC_SCRATCH/SHA256SUMS"
AC_EXPECTED=$(awk -v file="$AC_WHEEL" '$2 == file { print $1 }' "$AC_SCRATCH/SHA256SUMS")
if command -v shasum >/dev/null 2>&1; then
  AC_ACTUAL=$(shasum -a 256 "$AC_SCRATCH/$AC_WHEEL" | awk '{ print $1 }')
elif command -v sha256sum >/dev/null 2>&1; then
  AC_ACTUAL=$(sha256sum "$AC_SCRATCH/$AC_WHEEL" | awk '{ print $1 }')
else
  echo "A SHA-256 verification tool is required. Installation stopped."; exit 1
fi
AC_PINNED="${ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256:-}"
if [ ${#AC_EXPECTED} -ne 64 ] || [ "$AC_EXPECTED" != "$AC_ACTUAL" ] || \
   { [ -n "$AC_PINNED" ] && [ "$AC_PINNED" != "$AC_ACTUAL" ]; }; then
  echo "Download verification failed. Installation stopped."; exit 1
fi
printf '3/4 Preparing Python and the secure local app…\n'
export UV_TOOL_DIR="$AC_RUNTIME/tools"
export UV_TOOL_BIN_DIR="$AC_RUNTIME/bin"
"$AC_UV" tool install --python 3.13 --force "$AC_SCRATCH/$AC_WHEEL"
AC_PYTHON="$UV_TOOL_DIR/account-access/bin/python"
printf '4/4 Preparing website access…\n'
if [ "$(uname -s)" = Linux ]; then
  "$AC_PYTHON" -m playwright install chromium
  printf 'Linux may need browser system libraries and sandbox policy. See the Linux setup guide.\n'
else
  "$AC_PYTHON" -m playwright install chromium
fi
AC_LAUNCHER_DIR="$HOME/Applications"
mkdir -p "$AC_LAUNCHER_DIR"
# Write a POSIX-quoted path so spaces and apostrophes in the home path are safe.
"$AC_PYTHON" - "$AC_RUNTIME/bin/account-access" "$AC_LAUNCHER_DIR/Account Access.command" "${ACCOUNT_ACCESS_DATA_DIR:-}" <<'PY'
import os, shlex, sys
from pathlib import Path
target = Path(sys.argv[2])
if target.is_symlink():
    raise SystemExit("Refusing to replace a symlink launcher.")
marker = '# account-access-launcher-v1'
if target.exists() and marker not in target.read_text():
    raise SystemExit("Another file already uses the Account Access launcher name. Installation stopped.")
command = [sys.argv[1]]
if sys.argv[3]:
    command += ['--root', sys.argv[3]]
command += ['start']
target.write_text('#!/bin/sh\n' + marker + '\nexec ' + shlex.join(command) + '\n')
os.chmod(target, 0o700)
PY
printf '\nInstallation complete. Opening your account setup…\n'
set -- "$AC_RUNTIME/bin/account-access"
if [ -n "${ACCOUNT_ACCESS_DATA_DIR:-}" ]; then
  set -- "$@" --root "$ACCOUNT_ACCESS_DATA_DIR"
fi
set -- "$@" start
if [ "${ACCOUNT_ACCESS_NO_OPEN:-0}" = 1 ]; then
  set -- "$@" --no-open
fi
"$@"
