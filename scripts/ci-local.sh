#!/bin/bash
# Local source CI only. No hosted runner, publisher identity, install or account access.
set -euo pipefail

AC_CI_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}:$HOME/.local/bin:$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin"
export PATH
AC_CI_CHECK=0
AC_CI_OUTPUT=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) AC_CI_CHECK=1; shift ;;
    --output)
      [ "$#" -ge 2 ] || { echo '--output requires a new directory' >&2; exit 2; }
      AC_CI_OUTPUT=$2; shift 2 ;;
    --help|-h)
      echo 'Usage: bash scripts/ci-local.sh [--check] [--output NEW_DIRECTORY]'
      echo '--check validates local inputs and disabled automatic workflows without running CI.'
      exit 0 ;;
    *) echo 'Unknown local CI option' >&2; exit 2 ;;
  esac
done
cd -- "$AC_CI_ROOT"
AC_CI_UV=$(command -v uv) || { echo 'uv is unavailable in installed tool paths' >&2; exit 1; }

AC_CI_APP_SOURCES=(
  macos/AccountAccess.swift macos/MailboxOAuthLoopback.swift macos/OwnerGateway.swift
  macos/DesktopOwnerConnection.swift macos/BrowserNativeHost.swift macos/ManagedAgentSetup.swift
  macos/WorkerBootstrap.swift macos/WorkerListenerBindings.swift macos/BackgroundRecovery.swift
  macos/MessageText.swift macos/MessagesReader.swift macos/SystemMessagesReader.swift
)
AC_CI_APP_LIBS=(-framework AppKit -framework CryptoKit -framework CoreBluetooth -framework ServiceManagement -lsqlite3 -lbsm)
for AC_CI_INPUT in "${AC_CI_APP_SOURCES[@]}" macos/Tests/OwnerScreenChecks.swift \
  macos/Tests/DesktopOwnerConnectionChecks.swift macos/Tests/BrowserNativeHostChecks.swift \
  macos/Tests/MailboxOAuthLoopbackChecks.swift scripts/mac_owner_gateway_smoke.py \
  scripts/mac_full_image_installed_probe.py scripts/mac_runtime_upgrade_probe.py scripts/mac_owner_upgrade_probe.py; do
  [ -f "$AC_CI_INPUT" ] || { echo "Missing local CI source: $AC_CI_INPUT" >&2; exit 1; }
done

ci_workflows() {
  "$1" - <<'PY'
from pathlib import Path
import yaml
workflows = sorted(Path('.github/workflows').glob('*.yml'))
assert workflows, 'No workflow definitions found'
for path in workflows:
    data = yaml.safe_load(path.read_text())
    events = data.get('on', data.get(True))
    assert isinstance(events, dict) and set(events) == {'workflow_dispatch'}, str(path)
print(f'{len(workflows)} historical workflows have no automatic triggers')
PY
}

if [ "$AC_CI_CHECK" -eq 1 ]; then
  [ -x .venv/bin/python ] || { echo '--check needs the existing project virtualenv (no sync was run)' >&2; exit 1; }
  /bin/bash -n "$0"
  ci_workflows "$AC_CI_ROOT/.venv/bin/python"
  echo 'Local CI input checks passed; dependencies, tests, builds and native checks were not run.'
  exit 0
fi
[ "$(uname -s)" = Darwin ] && [ "$(id -u)" -ne 0 ] && [ "$(id -u)" = "$(id -ru)" ] || {
  echo 'Run local CI as the ordinary Mac owner, never root or a hosted runner' >&2; exit 1;
}
[ "${GITHUB_ACTIONS:-false}" != true ] && [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] || {
  echo 'GitHub Actions execution is forbidden by the $0 CI policy' >&2; exit 1;
}
command -v xcrun >/dev/null || { echo 'The existing Mac compiler is unavailable' >&2; exit 1; }
umask 077
if [ -z "$AC_CI_OUTPUT" ]; then
  AC_CI_OUTPUT="$AC_CI_ROOT/dist/local-ci-$(date -u +%Y%m%dT%H%M%SZ)"
fi
case "$AC_CI_OUTPUT" in /*) ;; *) AC_CI_OUTPUT="$PWD/$AC_CI_OUTPUT" ;; esac
[ ! -e "$AC_CI_OUTPUT" ] && [ ! -L "$AC_CI_OUTPUT" ] || { echo 'CI output must be a new directory' >&2; exit 1; }
mkdir -p -- "$(dirname -- "$AC_CI_OUTPUT")"
mkdir -m 700 -- "$AC_CI_OUTPUT"
AC_CI_WORK=$(mktemp -d /tmp/aa-ci.XXXXXX)
trap 'rm -rf -- "$AC_CI_WORK"' EXIT
mkdir -p "$AC_CI_WORK/modules" "$AC_CI_WORK/home" "$AC_CI_WORK/data" "$AC_CI_WORK/runtime"
export PYTHONDONTWRITEBYTECODE=1
export UV_OFFLINE=1
export ACCOUNT_ACCESS_DATA_DIR="$AC_CI_WORK/data"
export ACCOUNT_ACCESS_INSTALL_DIR="$AC_CI_WORK/runtime"
unset ACCOUNT_ACCESS_SIGNING_IDENTITY ACCOUNT_ACCESS_INSTALLER_IDENTITY ACCOUNT_ACCESS_NOTARY_PROFILE GH_TOKEN GITHUB_TOKEN
AC_CI_FAILURES=0

ci_unrun() {
  echo 'UNRUN: production publisher signing/notarization and publisher-signed XPC peers.'
  echo 'UNRUN: privileged Installer, cross-user service/vault journeys and macOS 14/15/26 matrix.'
  echo 'UNRUN: Linux sandbox/AppArmor, Android/emulator/physical phone and private MFA acceptance.'
}
ci_step() {
  local label=$1
  shift
  echo "RUN: $label"
  if "$@" >"$AC_CI_OUTPUT/$label.log" 2>&1; then
    echo "PASS: $label"
  else
    local result=$?
    AC_CI_FAILURES=$((AC_CI_FAILURES + 1))
    echo "FAIL: $label (exit $result)" >&2
    tail -n 25 "$AC_CI_OUTPUT/$label.log" >&2
    return 1
  fi
}
ci_uv() { "$AC_CI_UV" run --locked "$@"; }
ci_requirements() {
  "$AC_CI_UV" export --locked --no-dev --no-emit-project --no-annotate --no-header \
    --format requirements.txt --output-file "$AC_CI_WORK/runtime-requirements.txt" >/dev/null || return
  cmp account_access/runtime-requirements.txt "$AC_CI_WORK/runtime-requirements.txt"
}
ci_gateway() {
  # Only ad-hoc signatures on new synthetic binaries, never publisher keys.
  ci_uv python scripts/mac_owner_gateway_smoke.py --workdir "$AC_CI_WORK/gateway" \
    --diagnostics "$AC_CI_OUTPUT/gateway-diagnostics" --report "$AC_CI_OUTPUT/native-gateway.json"
}
ci_probe() {
  local label=$1
  local script=$2
  local folder="$AC_CI_WORK/$label"
  ci_step "$label" ci_uv python "$script" --output "$folder" || true
  if [ -f "$folder/result.json" ]; then cp "$folder/result.json" "$AC_CI_OUTPUT/$label.json"; fi
  # Keep bounded public compiler diagnostics, not megabytes of copied sources,
  # module caches and fixture binaries after the stage finishes.
  "$AC_CI_ROOT/.venv/bin/python" - "$folder" "$AC_CI_OUTPUT/$label-diagnostics.txt" <<'PY'
from pathlib import Path
import sys
folder, target = map(Path, sys.argv[1:])
parts = []
for path in sorted(folder.glob('*.stderr'))[:8]:
    raw = path.read_bytes()
    if raw:
        parts.append(path.name.encode() + b'\n' + raw[-8192:])
if parts:
    target.write_bytes(b'\n'.join(parts))
PY
  rm -rf -- "$folder"
}

echo "Local CI results: $AC_CI_OUTPUT"
ci_unrun | tee "$AC_CI_OUTPUT/unrun.log"
if ! ci_step locked-dependencies "$AC_CI_UV" sync --locked; then
  echo 'UNRUN: remaining local stages because locked dependency setup failed.'
  exit 1
fi
ci_step workflow-policy ci_workflows "$AC_CI_ROOT/.venv/bin/python" || true
ci_step dependency-audit ci_uv pip-audit --local || true
ci_step requirements-pin ci_requirements || true
ci_step lint ci_uv ruff check account_access tests scripts macos/notarize.py macos/system_package.py \
  macos/payload_audit.py macos/runtime_prepare.py macos/runtime_image.py macos/runtime_ca.py \
  macos/full_image_update.py macos/bitwarden_runtime.py macos/bitwarden_sources.py macos/bitwarden_notices.py || true
# No browser installation or phone setup: tests use only existing tools and
# synthetic fixtures. Missing platform dependencies remain real failures/skips.
ci_step pytest ci_uv pytest -q -p no:cacheprovider --basetemp "$AC_CI_WORK/pytest" || true
rm -rf -- "$AC_CI_WORK/pytest"
ci_step python-build "$AC_CI_UV" build --out-dir "$AC_CI_OUTPUT/build" || true

for AC_CI_ARCH in arm64 x86_64; do
  ci_step "gateway-typecheck-$AC_CI_ARCH" xcrun swiftc -j 2 -parse-as-library -warnings-as-errors -typecheck \
    -target "$AC_CI_ARCH-apple-macos13" -module-cache-path "$AC_CI_WORK/modules" \
    -framework Foundation -framework Security macos/OwnerGateway.swift || true
  ci_step "owner-typecheck-$AC_CI_ARCH" xcrun swiftc -j 2 -parse-as-library -warnings-as-errors -typecheck \
    -target "$AC_CI_ARCH-apple-macos14" -module-cache-path "$AC_CI_WORK/modules" \
    "${AC_CI_APP_LIBS[@]}" "${AC_CI_APP_SOURCES[@]}" || true
done

if ci_step owner-ui-compile xcrun swiftc -j 2 -O -parse-as-library -D ACCOUNT_ACCESS_UI_CHECKS \
  -module-cache-path "$AC_CI_WORK/modules" "${AC_CI_APP_LIBS[@]}" "${AC_CI_APP_SOURCES[@]}" \
  macos/Tests/OwnerScreenChecks.swift -o "$AC_CI_WORK/owner-ui"; then
  ci_step owner-ui "$AC_CI_WORK/owner-ui" || true
else
  echo 'UNRUN: owner-ui execution because compilation failed.'
fi
ci_step native-gateway ci_gateway || true
if ci_step desktop-channel-compile xcrun swiftc -j 2 -O -parse-as-library -warnings-as-errors \
  -D ACCOUNT_ACCESS_GATEWAY_CHECKS -module-cache-path "$AC_CI_WORK/modules" \
  -framework Foundation -framework Security macos/OwnerGateway.swift macos/DesktopOwnerConnection.swift \
  macos/Tests/DesktopOwnerConnectionChecks.swift -o "$AC_CI_WORK/desktop-channel"; then
  ci_step desktop-channel "$AC_CI_WORK/desktop-channel" || true
else
  echo 'UNRUN: desktop-channel execution because compilation failed.'
fi
if ci_step browser-bridge-compile xcrun swiftc -j 2 -O -parse-as-library -warnings-as-errors \
  -D ACCOUNT_ACCESS_GATEWAY_CHECKS -module-cache-path "$AC_CI_WORK/modules" \
  -framework Foundation -framework Security macos/OwnerGateway.swift macos/DesktopOwnerConnection.swift \
  macos/BrowserNativeHost.swift macos/Tests/BrowserNativeHostChecks.swift -o "$AC_CI_WORK/browser-bridge"; then
  ci_step browser-bridge "$AC_CI_WORK/browser-bridge" || true
else
  echo 'UNRUN: browser-bridge execution because compilation failed.'
fi
if ci_step mailbox-callback-compile xcrun swiftc -j 2 -O -parse-as-library \
  -module-cache-path "$AC_CI_WORK/modules" -framework Foundation -framework Network -framework Security \
  macos/MailboxOAuthLoopback.swift macos/OwnerGateway.swift macos/Tests/MailboxOAuthLoopbackChecks.swift \
  -o "$AC_CI_WORK/mailbox-callback"; then
  ci_step mailbox-callback "$AC_CI_WORK/mailbox-callback" || true
else
  echo 'UNRUN: mailbox-callback execution because compilation failed.'
fi

# The old production launch harness calls AccountAccess() and could discover an
# installed owner profile. Inject fixture-only dependencies instead; do not run
# ACCOUNT_ACCESS_LAUNCH_CHECKS on the owner's production installation.
cat >"$AC_CI_WORK/LocalLaunchChecks.swift" <<'SWIFT'
import AppKit
import Foundation
@main struct LocalLaunchChecks {
    static func main() throws {
        let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["ACCOUNT_ACCESS_DATA_DIR"]!)
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.urlCache = nil
        let session = URLSession(configuration: config)
        let helpers = ManagedAgentSetup(helper: { _ in throw ManagedAgentSetupFailure.unavailable },
            readToken: { throw ManagedAgentSetupFailure.unavailable })
        let app = NSApplication.shared
        let owner = AccountAccess(fixtureRoot: root, session: session, managedAgents: helpers,
            ownerProfile: { throw DesktopOwnerFailure.profile })
        precondition(!owner.systemOwnerConfigured)
        app.delegate = owner
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            guard let window = owner.window, window.isVisible else { exit(1) }
            window.orderOut(nil)
            _ = owner.applicationShouldHandleReopen(app, hasVisibleWindows: false)
            guard window.isVisible, !owner.systemOwnerConfigured else { exit(1) }
            print("PASS: optimized synthetic startup retains its delegate and reopens its own window")
            app.terminate(nil)
        }
        withExtendedLifetime(owner) { app.run() }
    }
}
SWIFT
if ci_step launch-compile xcrun swiftc -j 2 -O -parse-as-library -D ACCOUNT_ACCESS_UI_CHECKS \
  -module-cache-path "$AC_CI_WORK/modules" "${AC_CI_APP_LIBS[@]}" "${AC_CI_APP_SOURCES[@]}" \
  "$AC_CI_WORK/LocalLaunchChecks.swift" -o "$AC_CI_WORK/launch"; then
  ci_step launch "$AC_CI_WORK/launch" || true
else
  echo 'UNRUN: synthetic launch execution because compilation failed.'
fi
ci_probe full-image-source scripts/mac_full_image_installed_probe.py
ci_probe runtime-source scripts/mac_runtime_upgrade_probe.py
ci_probe owner-upgrade-source scripts/mac_owner_upgrade_probe.py
echo "Local source checks finished: $AC_CI_FAILURES failed stage(s). External journeys remain UNRUN."
echo "Reports: $AC_CI_OUTPUT"
[ "$AC_CI_FAILURES" -eq 0 ]
