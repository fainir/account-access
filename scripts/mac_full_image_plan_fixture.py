"""Create fictional native-plan inputs from the Python planner's pure fixture.

No payload, provider, installed account or service operation is performed. Only
the fresh imported test module's two cohort digests are replaced; production has
no alternate-cohort flag and tracked source is never changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--configuration-extension", action="store_true")
    args = parser.parse_args()
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("ordinary_fixture_required")
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))
    import test_full_image_ca_update as fixture

    value = fixture.ca_inputs.__wrapped__(fixture.inputs.__wrapped__())
    if args.configuration_extension:
        path = fixture.plan.PACKAGE + "/models.py"
        value["before"]["roots"][fixture.plan.SUPPORT][path] = dict(fixture.plan.CONFIGURATION_MODEL_BEFORE)
        value["after"]["roots"][fixture.plan.SUPPORT][path] = dict(fixture.plan.CONFIGURATION_MODEL_AFTER)
        value["provenance"]["target_source_files"]["account_access/models.py"] = fixture.plan.CONFIGURATION_MODEL_AFTER["sha256"]
    data = fixture.ca_arguments(value)
    model = fixture.plan
    model.CA_BASE_MANIFEST = model.digest(data["before_manifest"])
    model.CA_TARGET_MANIFEST = model.digest(data["after_manifest"])
    raw = model.derive(**data)
    parsed = model.parse(raw, expected_plan_sha256=model.digest(raw), **data)
    assert len([unit for unit in parsed["units"] if unit["kind"] == "public_tree"]) == 13
    assert len([unit for unit in parsed["units"] if unit["kind"] == "public_file"]) == 12
    provenance = data["provenance"]
    pins = {
        "planSHA256": model.digest(raw), "targetSourceCommit": provenance["target_source_commit"],
        "targetManifestSHA256": model.digest(data["after_manifest"]), "caReceiptSHA256": model.digest(data["ca_receipt"]),
        "predecessor": {"planSHA256": provenance["component_plan_sha256"],
            "originalManifestSHA256": provenance["original_manifest_sha256"],
            "manifestSHA256": model.digest(data["before_manifest"]), "headSHA256": provenance["component_head_sha256"]},
        "predecessorSourceCommit": provenance["component_source_commit"], "targetSourceFiles": provenance["target_source_files"],
        "providerManifestSHA256": model.digest(data["provider_manifest"]),
        "providerSourceBundleSHA256": provenance["provider_source_bundle_sha256"],
        "fixtureExpected": {"changed_nodes": len(parsed["changed"]), "target_manifest_sha256": model.digest(data["after_manifest"])},
    }
    files = {"plan.json": raw, "before.json": data["before_manifest"], "after.json": data["after_manifest"],
        "old-identity.json": data["old_identity"], "new-identity.json": data["new_identity"],
        "provider.json": data["provider_manifest"], "ca.json": data["ca_receipt"], "pins.json": model.encoded(pins)}
    os.mkdir(args.output, mode=0o700)  # Refuse any existing directory/link/node.
    root = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(root, 0o700)
        for name, contents in files.items():
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(root)
    finally:
        os.close(root)
    print(json.dumps({"schema": 1, "status": "PREPARED_SYNTHETIC_CA_PLAN", "changed_nodes": len(parsed["changed"]),
        "tree_units": 13, "file_units": 12, "files_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
        "installed_private_operations": False, "production_ready": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print('{"status":"REFUSED","reason":"synthetic_plan_fixture_refused"}')
        raise SystemExit(78) from None
