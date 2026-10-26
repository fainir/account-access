"""Ordinary-user launch check on a fresh hosted Mac, before any installation."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(value):
    if not value:
        raise ValueError("owner_compatibility_refused")


def hosted_guard():
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0
            and platform.machine() == "arm64" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access"
            and os.environ.get("RUNNER_TEMP") == "/Users/runner/work/_temp"
            and re.fullmatch(r"[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")))


def main():
    hosted_guard()  # Before any input/output path access or process invocation.
    require(len(sys.argv) == 1)
    source = os.environ["GITHUB_SHA"]
    temp = Path(os.environ["RUNNER_TEMP"])
    inputs, output = temp / "account-access-owner-compatibility-inputs", temp / "owner-entrypoint-review"
    require(inputs.is_dir() and not inputs.is_symlink() and not os.path.lexists(output))
    output.mkdir(mode=0o700)
    report = {"schema": 1, "status": "FAILED", "source_commit": source,
              "checks": dict.fromkeys(("fixed_inputs", "target_metadata", "wrapper_binding", "signature", "ordinary_entrypoint"), False),
              "stage": "source", "installed_reads": False, "installed_writes": False,
              "owner_machine": False, "production_ready": False, "logs": {}}
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}

    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def command(label, args, *, expected=0, timeout=60):
        result = subprocess.run([str(v) for v in args], cwd=ROOT, env=environment,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False)
        require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536)
        for kind in ("stdout", "stderr"):
            raw = getattr(result, kind)
            name = label + "." + kind
            (output / name).write_bytes(raw)
            report["logs"][name] = digest(raw)
        require(result.returncode == expected)
        return result

    try:
        require(command("revision", ["/usr/bin/git", "rev-parse", "HEAD"]).stdout.decode().strip() == source)
        for name in ("scripts/mac_owner_upgrade_compatibility_probe.py", "scripts/download_owner_upgrade_inputs.py",
                     "scripts/build_owner_upgrade_review.py"):
            require(command("source-" + Path(name).stem, ["/usr/bin/git", "show", source + ":" + name]).stdout
                    == (ROOT / name).read_bytes())
        version = command("host-version", ["/usr/bin/sw_vers", "-productVersion"]).stdout.decode().strip()
        require(re.fullmatch(r"15\.[0-9]+(?:\.[0-9]+)?", version))
        report["host_macos"] = version
        download = runpy.run_path(str(ROOT / "scripts/download_owner_upgrade_inputs.py"))
        raw_contract = (ROOT / download["CONTRACT"]).read_bytes()
        require(command("source-contract", ["/usr/bin/git", "show", source + ":" + download["CONTRACT"]]).stdout == raw_contract
                and (inputs / "asset-contract.json").read_bytes() == raw_contract)
        contract = download["validate"](json.loads(raw_contract))
        require({p.name for p in inputs.iterdir()} == download["FILES"] | {"asset-contract.json", "controller.json"})
        require(json.loads((inputs / "controller.json").read_bytes()) == {
            "schema": 1, "controller_revision": source, "contract_sha256": digest(raw_contract)})
        for name, row in contract["assets"].items():
            path = inputs / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == row["bytes"] <= 16 * 1024**2)
            require(digest(path.read_bytes()) == row["sha256"])
        review = json.loads((inputs / "owner-review.json").read_bytes())
        require(review["controller_source"] == download["SOURCE"] and review["installed"] is False
                and review["production_ready"] is False and review["postinstall_helper_binding_verified"] is True)
        report["checks"]["fixed_inputs"] = True
        report["stage"] = "expansion"
        expanded = output / "expanded"
        command("expand", ["/usr/sbin/pkgutil", "--expand-full", inputs / "owner-upgrade.pkg", expanded], timeout=180)
        scripts = expanded / "Scripts"
        helper = scripts / "AccountAccess-ownerupgrade"
        require(helper.is_file() and not helper.is_symlink() and helper.stat().st_size <= 16 * 1024**2)
        raw = helper.read_bytes()
        require(digest(raw) == review["helper_sha256"])
        builder = runpy.run_path(str(ROOT / "scripts/build_owner_upgrade_review.py"))
        report["stage"] = "target_metadata"
        target = builder["helper_target"](raw)
        require(target == review["helper_target"])
        report["helper_sha256"], report["helper_target"] = digest(raw), target
        report["checks"]["target_metadata"] = True
        builder["verify_wrapper_binding"]((scripts / "postinstall").read_bytes(), digest(raw))
        report["checks"]["wrapper_binding"] = True
        report["stage"] = "signature"
        command("signature", ["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
            '"com.fainir.accountaccess.componentupdate" and certificate leaf[subject.OU] = "WBULD6N4NQ" '
            'and !(entitlement["com.apple.security.get-task-allow"] exists)', helper])
        report["checks"]["signature"] = True
        report["stage"] = "ordinary_entrypoint"
        refused = command("ordinary-refusal", [helper], expected=78, timeout=30)
        require(not refused.stderr and json.loads(refused.stdout) == {
            "schema": 1, "status": "REFUSED", "reason": "owner_upgrade_installer_context_required"})
        report["checks"]["ordinary_entrypoint"] = True
        report["status"], report["stage"] = "PASSED", None
    except Exception:
        pass  # No exception text or arbitrary tool output in the public result.
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "stage", "checks")}))
    return 0 if report["status"] == "PASSED" else 78


if __name__ == "__main__":
    raise SystemExit(main())
