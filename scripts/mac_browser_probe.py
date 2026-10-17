"""Credential-free browser canary for the disposable Mac worker CI VM.

No website, account store, mailbox or phone is opened. Only fixed diagnostic
labels leave this process; Playwright's raw error text is never printed.
"""

import json
import os
import re
import sys

from playwright.sync_api import sync_playwright


def main():
    if sys.platform != "darwin" or os.getuid() == 0 or not sys.flags.isolated:
        return 1
    phase = "driver_start"
    try:
        with sync_playwright() as playwright:
            phase = "browser_launch"
            with playwright.chromium.launch(headless=True, chromium_sandbox=True) as browser:
                phase = "blank_page"
                page = browser.new_page()
                assert page.url == "about:blank"
        print(json.dumps({"status": "PASSED", "phase": "blank_page"}))
        return 0
    except Exception as error:
        # Diagnostic matching is confined to a fresh browser with no account
        # input. Never output the exception or browser subprocess arguments.
        message = str(error)
        labels = [("bootstrap_check_in", "mach_bootstrap_registration_failed"),
                  ("bootstrap_look_up", "mach_bootstrap_registration_failed"),
                  ("bootstrap_register", "mach_bootstrap_registration_failed"),
                  ("MachPortRendezvous", "mach_bootstrap_registration_failed"),
                  ("ProcessSingleton", "browser_profile_unavailable"),
                  ("Executable doesn't exist", "browser_not_installed"),
                  ("Operation not permitted", "browser_launch_not_permitted"),
                  ("Permission denied", "browser_launch_permission_denied"),
                  ("Target page, context or browser has been closed", "browser_closed_during_launch")]
        reason = next((label for text, label in labels if text in message), "browser_canary_failed")
        sites = sorted(set(re.findall(r"\b([a-z_]+\.(?:cc|mm):[0-9]{1,6})\b", message)))[:8]
        print(json.dumps({"status": "FAILED", "phase": phase, "reason": reason, "chromium_sites": sites}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
