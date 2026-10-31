# Publisher-signed browser failure - 31 October 2026

The user authorized saving the public SauceDemo example and its narrow product
read in response to the staged consent question. The native app saved it and
reported Mac approval accepted. No repeat consent or AI enrollment is needed.

The connection and installed read failed. The service returned
`RETRYABLE/internal_error`. A credential-free probe under the existing broker
identity then reproduced a driver crash before any website request:
default Node exited -5 and reported failure reserving its V8 CodeRange; the
same binary with `--jitless` exited zero. Resource limits were unlimited and
system memory was available. Both signed V8 executable entitlements were empty.

A private copy of that exact Node, publisher-signed with only `allow-jit`,
executed successfully. [Copy probe](node-copy.json). The installed runtime was
not modified by this diagnostic. Apple's [JIT entitlement documentation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit)
states that hardened applications need this exception for MAP_JIT memory and
that code relying on it may otherwise fail. The evidence supports granting it
only to the reviewed Node and Chromium executables, while retaining library
validation, debugging restrictions and executable page protections.

Build 121 is being prepared as an exact signed successor to build 120. Its
acceptance must execute the actual publisher-signed installed driver and
sandboxed browser, not merely check their signatures and daemon registration.
The native screen also needs the D2 correction: adding a correctly classified
public example must not make an already verified AI connection look unverified.

The live [SauceDemo public login page](https://www.saucedemo.com/) now declares
`/assets/index-DnLqFcJI.js`; the stylesheet remains
`/assets/index-aSZoiKGF.css`. The connector's previous exact script path is stale.
Build 121 refreshes only that exact same-origin path. Its existing saved example
must be reconnected through the reviewed native catalog after update; its
permission remains product names and prices. No font-host or URL wildcard is added.

Private Namecheap access remains paused on its existing challenge. The new
public example and these synthetic probes do not establish private acceptance.
