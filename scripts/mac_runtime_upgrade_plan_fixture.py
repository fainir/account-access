"""Write fictional runtime-upgrade plan inputs for ordinary native checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("ordinary_fixture_required")
    root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root), str(root / "tests")]
    import pytest
    import test_runtime_upgrade_plan as fixture

    with pytest.MonkeyPatch.context() as patch:
        old, new, arguments = fixture.fixture.__wrapped__(patch)
        for name in ("__init__", "aliases", "utf_8"):
            path = "runtime/lib/python3.12/encodings/__pycache__/" + name + ".cpython-312.pyc"
            for rows in (old, new):
                fixture.put(rows, path, fixture.file_node())
        # Exercise every metadata replacement, including the existing CA receipt.
        for path in fixture.plan.FILES:
            if path not in ("package-identity.json", "broker-repair-identity.json"):
                new[path] = fixture.file_node(b"replacement-metadata")
        inputs = arguments()
        raw = fixture.plan.derive(**inputs)
        parsed = fixture.plan.parse(raw, expected_sha256=fixture.plan.image.digest(raw), **inputs)
    files = {"plan.json": raw, "before.json": inputs["before_manifest"], "after.json": inputs["after_manifest"],
             "old-identity.json": inputs["old_identity"], "new-identity.json": inputs["new_identity"]}
    args.output.mkdir(mode=0o700)
    descriptor = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(descriptor, 0o700)
        for name, contents in files.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=descriptor)
            with os.fdopen(fd, "wb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({"status": "PREPARED_SYNTHETIC_RUNTIME_PLAN", "units": len(parsed["units"]),
                      "files_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
                      "installed_reads": False, "production_ready": False}, sort_keys=True))


if __name__ == "__main__":
    main()
