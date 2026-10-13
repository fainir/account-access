# Graphical Mac app

This is a genuine native installer and owner interface for macOS 13 or later, on Apple silicon or Intel. It runs the published, checksum-verified bootstrap, shows installation progress, installs the selected agent skills, and connects supported accounts through the authenticated local owner API. Reopening it starts the saved local service; no terminal window is required.

The included account catalog contains public SauceDemo and The Internet examples. It does not add support for arbitrary websites, password-manager imports, or personal phone factors.

Build with Xcode's command-line tools:

```sh
sh macos/build.sh
```

For Developer ID signing, set `ACCOUNT_ACCESS_SIGNING_IDENTITY` to your own certificate name before building. The app and ZIP are written to `dist/macos/`.

Public Mac distribution needs Apple notarization as well as signing. The current recorded build is Developer ID signed and works locally; notarization remains pending because the configured Xcode account could not authenticate. A public preview download can therefore be blocked by Gatekeeper. The recording demonstrates the actual graphical build, rather than the older `.command` launcher.

The app never displays the owner bearer token, saved passwords, or client tokens. Owner metadata is checked for file ownership and private permissions, the local server identity is verified with a fresh HMAC challenge, and HTTP redirects are refused. Connection retries retain the service's login throttle and stop for genuine owner-presence challenges.
