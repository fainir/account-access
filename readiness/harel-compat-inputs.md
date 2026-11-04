# Harel release - retained compatibility inputs

Read back 4 November 2026. **All eight exact public fixture sets are available and verified.** Releases 122-125 are still inside retained signed updater packages and need only their five JSON members materialized for native execution. This lane streamed those members in memory; it downloaded, extracted to disk, rebuilt, compiled, signed or installed nothing. Only this memo was written.

All paths below are relative to `/Users/nirfeinstein/.codex/worktrees/upgrade-continuation/login soltion/`.

## Five-file map

For a directory row, the five source paths are `<directory>/plan.json`, `/before.json`, `/after.json`, `/old-identity.json`, `/new-identity.json`. For a package row, use the five logical `Scripts` CPIO members in the mapping directly below.

| Release | Verified directory or retained package | Units |
|---|---|---:|
|120|`dist/root-recovery-release/harel128/compat/120/`|189|
|121|`dist/root-recovery-release/harel128/compat/121/`|17|
|122|`dist/customer-release-0.8.0/Account-Access-0.8.0-update-from-build121.pkg`|14|
|123|`dist/customer-release-0.8.0/Account-Access-0.8.0-update-from-build122.pkg`|15|
|124|`dist/customer-release-0.8.0/Account-Access-0.8.0-update-from-build123.pkg`|15|
|125|`dist/customer-release-0.8.0/Account-Access-0.8.0-update-from-build124.pkg`|7|
|126|`dist/root-recovery-release/automatic126/native-inputs/`|15|
|127|`dist/root-recovery-release/login127/native-inputs/`|15|

| Native fixture filename | Exact packaged source member |
|---|---|
|`plan.json`|`Scripts` gzip CPIO: `./RuntimeUpgradePlan.json`|
|`before.json`|`Scripts` gzip CPIO: `./BaseManifest.json`|
|`after.json`|`Scripts` gzip CPIO: `./TargetManifest.json`|
|`old-identity.json`|`Scripts` gzip CPIO: `./BaseIdentity.json`|
|`new-identity.json`|`Scripts` gzip CPIO: `./TargetIdentity.json`|

Each set passed SHA-256 equality for raw plan/before/after against `scripts.build_direct_runtime_upgrade_candidate.RELEASES[number]`, predecessor identity equality against `Release.base_identity`, `macos.full_image_update._identity` for both manifests' public `package-identity.json` hash/size/peer schema, and exact canonical `macos.direct_runtime_upgrade_plan.parse(..., release=number)` using the plan's own `target_source_files`.

The coordinator retrieved the initially absent 120/121 archives during this task. Their retained `compat/release120-native-inputs.tar.gz` and `compat/release121-native-inputs.tar.gz` now match `artifacts/release120-native-inputs.json` / `release121-native-inputs.json`; 121 also matches its 2,538,606-byte contract. Both extracted directories have exactly the five expected files. This lane independently verified those recovered bytes after they appeared.

**Do not substitute** generic `dist/root-recovery-release/candidate/scripts/` or `candidate.pkg` for 120. Both contain the old `d73f29c0...` plan, not RELEASE120's `7949dee7...`; their target manifest is old `630e7760...`. `candidate120-retained/scripts` is currently absent despite the reported keep entry. The original working checkout's dist is empty, and the runtime121-acceptance worktree has no dist directory.

## Public Scripts streaming method

The current Mac's `/usr/bin/tar -tf <package>` exposes the outer XAR member as **`ScriptsScripts`** (while `/usr/bin/xar -tf` calls it `Scripts`). Use the exact name observed by tar; requesting `Scripts` with tar fails for these retained packages. Stream `/usr/bin/tar -xOf <package> ScriptsScripts` into `gzip.GzipFile`. The inner archive is old ASCII CPIO (`070707`), with 76-byte headers; no full payload expansion is required.

Minimal read-only method used, returning only the five metadata values:

```python
import gzip, subprocess
names = dict(zip(
    ("RuntimeUpgradePlan.json", "BaseManifest.json", "TargetManifest.json", "BaseIdentity.json", "TargetIdentity.json"),
    ("plan.json", "before.json", "after.json", "old-identity.json", "new-identity.json")))
def read_exact(stream, size):
    value = stream.read(size)
    assert len(value) == size
    return value
def public_inputs(package):
    proc = subprocess.Popen(["/usr/bin/tar", "-xOf", str(package), "ScriptsScripts"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    found = {}
    with gzip.GzipFile(fileobj=proc.stdout) as archive:
        while True:
            header = read_exact(archive, 76)
            assert header[:6] == b"070707"
            size = int(header[65:76], 8)
            name = read_exact(archive, int(header[59:65], 8)).rstrip(b"\0").decode()
            if name == "TRAILER!!!": break
            name = name[2:] if name.startswith("./") else name
            if name in names:
                assert int(header[18:24], 8) & 0o170000 == 0o100000
                assert names[name] not in found and size <= 34 * 1024 * 1024
                found[names[name]] = read_exact(archive, size)
            else:
                while size:
                    chunk = archive.read(min(size, 65536))
                    assert chunk
                    size -= len(chunk)
        while archive.read(65536): pass
    proc.stdout.close()
    assert proc.wait() == 0 and set(found) == set(names.values())
    return found
```

Skip unselected entries in bounded chunks; never write their bodies. The coordinator can write the returned five public values to a fresh private fixture directory and repeat the same hash/planner checks before execution. No credential/config/vault/Chrome input is involved.

## One native binary is suitable

**Yes, one current-source `DirectRuntimeUpgradeSourceChecks` binary can test all eight sets.** `macos/Tests/DirectRuntimeUpgradeSourceChecks.swift:98` reads the directory from argv; lines 106-115 load the five files and select the compiled release tuple by the raw plan hash. Lines 120-128 take `target_source_files` from that fixture's plan. Later count/namespace checks select the matching retained release, not a compile-time input path. No fixture bytes are embedded by `scripts/mac_direct_runtime_upgrade_probe.py`; its compiled source list is identical for every input directory.

Run that binary once per directory and retain the actual per-release JSON result, expected units/changed counts and current compiled-source digest inventory. **Do not use `--resume` to change fixtures**: the Python probe deliberately requires its saved input bytes to remain identical. Reusing the already compiled binary directly is the applicable route. When adding 128, compile after Q's tuple/pin/assertion changes, then run all historical sets and 128 against that same binary. Native execution/qualification was not performed by this research lane.
