#!/bin/zsh
# Owner opens this file locally. No key is created until explicit confirmation.
set -u
umask 077
ac_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd) || exit 1
cd -- "$ac_repo" || exit 1
uv run --no-sync python -m scripts.android_publisher_setup \
  --publisher-name 'Nir Fainshtein' \
  --publisher-directory "$HOME/Library/Application Support/Account Access Publisher/android-phone-1" \
  --version-code 2 --version-name 0.8.0 \
  --output "$ac_repo/dist/android-publisher-2"
ac_result=$?
printf '\nPress Return to close this setup.\n'
read -r ac_close
exit "$ac_result"
