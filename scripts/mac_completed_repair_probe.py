"""Qualify the read-only completed repair verifier inside the existing CI fixture.

Called only after repair91 actual Installer acceptance in a fresh hosted Mac.
No owner-host entrypoint, installation, account access or enrollment is added.
"""
import json
from pathlib import Path
import re
import runpy

PINS = "artifacts/repair91-full-image-pins.swift"
PINS_SHA = "dab62cbad1c11821681be4ab480d8153457da7b16a6ec2e012a5d341555c0ba4"
FIELDS = {"requested", "native_source_verified", "expected_state_verified", "same_evidence_twice",
          "foreign_audit_refused", "public_metadata_unchanged", "production_ready"}


def acceptance_passed(value, *, foreign):
    if not isinstance(value, dict) or set(value) != FIELDS:
        return False
    return (value["requested"] is True and value["production_ready"] is False
            and all(value[key] is True for key in FIELDS - {"production_ready", "same_evidence_twice", "foreign_audit_refused"})
            and value["same_evidence_twice"] is (not foreign)
            and value["foreign_audit_refused"] is (not foreign))


def run(*, controller, args, stage, scripts, report, command):
    # The host guard must run before reading any path or accepting a callback.
    controller.guard()
    c, h, f = controller, controller.h, controller.f
    c.require(args.cohort == 91 and report["checks"]["reapplication_preserved_bytes_and_ids"] is True)
    revision = report["controller_revision"]
    def source(name):
        raw = (args.repository / name).read_bytes()
        c.require(raw == h.git_bytes(args.repository, ["show", revision + ":" + name], maximum=2 * 1024**2))
        return raw
    source("scripts/mac_completed_repair_probe.py")
    source("scripts/mac_full_image_installed_probe.py")
    probe = runpy.run_path(str(args.repository / "scripts/mac_full_image_installed_probe.py"))
    names = ["macos/" + n for n in probe["DEPENDENCIES"]]
    names += ["macos/FullImageInstalledIO.swift", "macos/FullImagePredecessorAuthority.swift"]
    originals = {name: source(name) for name in [*names, "macos/ComponentUpdate.swift", *probe["FRAGMENTS"]]}
    c.require(all(c.digest(raw) == probe["EXACT_INPUTS"][name] for name, raw in originals.items()))
    code = stage / "completed-proof-source"
    code.mkdir(mode=0o700)
    paths = []
    for name in names:
        target = code / Path(name).name
        c.create_file(target, originals[name], 0o600)
        paths.append(str(target))
    composed = b"\n".join(originals[n] for n in ["macos/ComponentUpdate.swift", *probe["FRAGMENTS"]])
    c.require(c.digest(composed) == probe["COMPOSED_SHA256"])
    extra = {
        "ComponentUpdate.swift": composed,
        "CompletedBrokerRepairProbe.swift": source("macos/Tests/CompletedBrokerRepairProbe.swift"),
        "FullImageUpdateCompiledPins.swift": source(PINS),
        "BrokerRepairCompiledPins.swift": ('enum BrokerRepairCompiledPins { static let value = BrokerRepairSource.Pins('
            f'planSHA256: "{c.PLAN}", predecessorPlanSHA256: "{f.CONFIGURATION_PINS[1]}", '
            f'beforeManifestSHA256: "{c.BEFORE}", afterManifestSHA256: "{c.AFTER}", sourceCommit: "{c.SOURCE}") }}\n').encode(),
    }
    c.require(c.digest(extra["FullImageUpdateCompiledPins.swift"]) == PINS_SHA)
    for name, raw in extra.items():
        target = code / name
        c.create_file(target, raw, 0o600)
        paths.append(str(target))
    binary = code / "completed-repair-probe"
    command(["/usr/bin/xcrun", "swiftc", "-j", "2", "-O", "-whole-module-optimization", "-parse-as-library",
        "-warnings-as-errors", "-target", "arm64-apple-macos14", "-module-cache-path", str(code / "cache"),
        "-framework", "Foundation", "-framework", "CryptoKit", "-framework", "Security",
        *paths, "-o", str(binary)], "completed-proof-compile.log", 900)
    f.normalize_owned_resource_ancestors(stage)
    f.inventory(scripts, normalize=True)
    foreign = args.scenario == "foreign-binding"
    outcome = dict.fromkeys(FIELDS, False)
    outcome.update(requested=True, native_source_verified=True)
    report["completed_predecessor"] = outcome
    def state():
        # Public records only. Never descend into the private account store.
        roots = [c.NAMESPACE, h.BASE / "broker"]
        selected = [p for p in roots[0].rglob("*") if p.is_file()]
        selected += [roots[1] / n for n in ("worker.json", "host.json", "install.json")]
        selected += [h.BASE / "owner.json", h.JOB]
        return {str(p): c.snapshot(p, maximum=16 * 1024**2) for p in selected}
    before = state()
    def invoke(label, expected):
        result = command(["/usr/bin/env", "GITHUB_ACTIONS=true", "CI=true", "RUNNER_ENVIRONMENT=github-hosted",
            "RUNNER_OS=macOS", "RUNNER_ARCH=ARM64", "GITHUB_REPOSITORY=fainir/account-access",
            str(binary), str(scripts)], label, 600, check=False)
        c.require(result.returncode == (0 if expected == "VERIFIED" else 78) and result.stderr == b"")
        value = json.loads(result.stdout)
        c.require(type(value.get("schema")) is int and value["schema"] == 1 and value.get("status") == expected)
        if expected == "VERIFIED":
            c.require(set(value) == {"schema", "status", "evidence_sha256"}
                      and re.fullmatch("[a-f0-9]{64}", value["evidence_sha256"]))
        else:
            c.require(set(value) == {"schema", "status", "reason"} and value["reason"] != "hosted_fixture_required")
        return value
    first = invoke("completed-proof-first.log", "REFUSED" if foreign else "VERIFIED")
    outcome["expected_state_verified"] = True
    if not foreign:
        second = invoke("completed-proof-second.log", "VERIFIED")
        c.require(first == second)
        outcome["same_evidence_twice"] = True
        # Only an invocation-created audit fixture is added and then removed.
        unknown = c.NAMESPACE / ("transition-" + c.PLAN) / "foreign-audit-fixture.json"
        c.create_file(unknown, b'{"schema":1,"foreign":true}')
        try:
            invoke("completed-proof-foreign-audit.log", "REFUSED")
            outcome["foreign_audit_refused"] = True
        finally:
            c.require(h.read_file(unknown, maximum=512) == b'{"schema":1,"foreign":true}')
            unknown.unlink()
    c.require(state() == before)
    outcome["public_metadata_unchanged"] = True
    c.require(acceptance_passed(outcome, foreign=foreign))
