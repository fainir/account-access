# Installed build 128 acceptance - 5 November 2026

Actual completed installation and a later kernel restart are accepted here. This is the local exact 127-to-128 update; public fresh-128/multi-OS delivery and real Harel email/SMS/authenticator acceptance are not claimed.

## Installed update and restart

The public macOS Installer log identifies the exact corrected package, component `com.fainir.accountaccess.harelemail128`, and package_script_service PID 36662:
- 09:07:57 +02: postinstall starts.
- 09:09:31 +02: `UPDATED_GUI_UNVERIFIED`, `checkpoint=complete`; Installer records the package installed.
- 09:10:59 +02: actual new kernel boot, epoch 1793862659, after installation.

Actual owner plist reports version 0.8.0/build 128. Broker PID 654 and worker PID 7621 are present. Both installed agent launchers report service version 0.8.0, background recovery RUNNING with zero failures, and browser READY. Each independently discovers the same four standing account/operation grants. Namecheap and Lemon remain paused; no private challenge was resubmitted.

This accepts real post-update startup. The exact number of initial startup retries is not exposed and is not inferred from PID timing; root fault-injection and Pause-to-Resume fixture integration remain unrun.

## Public image and preserved data boundaries

All 14 selected public files match the qualified corrected target manifest; all 73 installed Python sources match git 605a0495345742194a8e82397da25ac9b6bc3e37. All 12 previous metadata identities match using `lstat`. The application alias retains its original inode/ownership/mode and points to the qualified owner bundle. Following it with `stat` measures the intentionally replaced public target, so that earlier measurement was corrected rather than treating its new inode as loss of owner data. The new Harel Email namespace is root-owned 0700.

Actual read-back:
```json
{"installed_build": "128", "qualified_public_files_matched": 14, "packaged_python_sources_matched": 73, "prior_metadata_identities_preserved": 12, "new_harel_namespace": "root-owned 0700", "application_alias": "matches qualified manifest; prior symlink identity preserved", "metadata_measurement": "lstat; public owner bundle replacement may change its target inode", "private_credential_or_policy_contents_read": false, "installed_paths_changed": false}
```

No credential, key, login-code, QR, policy or Chrome-store contents were read. No installation, source change, data reset, new grant or update replay was performed by this acceptance run.

## Approved installed agent operations

The following are actual installed launcher results after the restart. Betterloop is an existing private status-only grant; these reads confirm saved approved access and do not prove that a password was submitted again. The earlier real Chrome import/fresh-password evidence remains [F2/D15](../betterloop-private-2026-11-02/acceptance.md). Public store results are examples and do not qualify private MFA.

Codex private status:
```json
{
  "status": "COMPLETED",
  "account": "personal-betterloop",
  "operation": "status",
  "environment": "live",
  "environment_source": "connector-configuration",
  "data": {
    "authenticated": true
  },
  "untrusted_data": true
}
```

Claude Code private status:
```json
{
  "status": "COMPLETED",
  "account": "personal-betterloop",
  "operation": "status",
  "environment": "live",
  "environment_source": "connector-configuration",
  "data": {
    "authenticated": true
  },
  "untrusted_data": true
}
```

Codex public example:
```json
{
  "status": "COMPLETED",
  "account": "personal-store",
  "operation": "inventory",
  "environment": "public-example",
  "environment_source": "connector-configuration",
  "data": {
    "items": [
      {
        "name": "Sauce Labs Backpack",
        "price": "$29.99"
      },
      {
        "name": "Sauce Labs Bike Light",
        "price": "$9.99"
      },
      {
        "name": "Sauce Labs Bolt T-Shirt",
        "price": "$15.99"
      },
      {
        "name": "Sauce Labs Fleece Jacket",
        "price": "$49.99"
      },
      {
        "name": "Sauce Labs Onesie",
        "price": "$7.99"
      },
      {
        "name": "Test.allTheThings() T-Shirt (Red)",
        "price": "$15.99"
      }
    ]
  },
  "untrusted_data": true
}
```

Claude Code public example:
```json
{
  "status": "COMPLETED",
  "account": "personal-store",
  "operation": "inventory",
  "environment": "public-example",
  "environment_source": "connector-configuration",
  "data": {
    "items": [
      {
        "name": "Sauce Labs Backpack",
        "price": "$29.99"
      },
      {
        "name": "Sauce Labs Bike Light",
        "price": "$9.99"
      },
      {
        "name": "Sauce Labs Bolt T-Shirt",
        "price": "$15.99"
      },
      {
        "name": "Sauce Labs Fleece Jacket",
        "price": "$49.99"
      },
      {
        "name": "Sauce Labs Onesie",
        "price": "$7.99"
      },
      {
        "name": "Test.allTheThings() T-Shirt (Red)",
        "price": "$15.99"
      }
    ]
  },
  "untrusted_data": true
}
```

## Independent installed check

A separate read-only checker independently confirmed actual128, all14 selected public files (hash/size/mode), exactly73 installed Python files with no extras/missing entries, all12 lstat identities, the scoped09:09:31 completion followed by09:10:59 kernel boot, stable broker654, and both launchers' health/four retained grants. Discovery alone reports verified_now=false, as expected; the four actual operations above supply the separate approved-read results. The checker performed no private operation, native UI change, install, protected-content read or file edit. The full public manifest was not rehashed, and real Harel enrollment remains unverified.

The completed installation follow-up was deleted from the app; returned deleteStatus is deleted. Personal enrollment is handed off locally without another polling monitor.

## Native Harel setup and remaining owner action

The real installed Accounts screen shows automatic AI integration, Betterloop Connected, the public example labeled separately, and the two paused private connections. Automatic sign-in > Connect Harel with email opens the installed Harel wizard. It has the existing checked mailbox selected, empty secure identity/mobile fields, unchecked `Allow this Harel email setup` and a disabled `Send Harel login email` button. Consent explicitly limits AI results to sign-in status and excludes policy, medical and payment information.

Action 21 (installation/restart) is complete. New action 22 is local first-use Harel enrollment: enter the owner's identity number and registered mobile number in this open native form, approve its narrow setup consent, and send the first login email. Keep identity and any first-use code in the native app. The stored mailbox needs no new password. Later pattern approval and the separate automatic second-email test remain native owner decisions; saving happens only after success.

No Harel request, first message/code, identity/phone enrollment, email pattern, automatic test or Harel grant has occurred in this run. Harel email remains unverified, followed by SMS and then Google Authenticator in the owner's order. The existing Lemon task and Namecheap challenge are preserved. No full product or unattended-MFA completion is claimed.

