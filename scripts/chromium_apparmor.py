"""Generate an AppArmor user-namespace profile for installed Playwright binaries.

Linux administrator helper: prints exact paths and writes a reviewable policy.
It does not install the policy, run sudo, or change global namespace settings.
"""

import argparse
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This helper is only for Linux with AppArmor 4.x or later")
    with sync_playwright() as pw:
        executable = Path(pw.chromium.executable_path)
    cache = executable.parents[2]
    binaries = {executable.resolve(strict=True)}
    for filename in ["chrome-headless-shell", "headless_shell"]:
        binaries.update(p.resolve(strict=True) for p in cache.glob("chromium_headless_shell-*/chrome-*/" + filename) if p.is_file())
    if len(binaries) < 2:
        parser.error("Install both Playwright Chromium and its headless shell first")
    policy = ["abi <abi/4.0>,", "include <tunables/global>", ""]
    for index, binary in enumerate(sorted(binaries)):
        path = str(binary)
        if any(character in path for character in '\\"\n\r*?[]{}'):
            parser.error("Executable path contains unsupported AppArmor pattern characters")
        policy.extend([f'profile account-access-chromium-{index} "{path}" flags=(unconfined) {{',
                       "  userns,", "}", ""])
        print("Allow user namespaces for: " + path)
    args.output.write_text("\n".join(policy))
    print("Policy written for administrator review: " + str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
