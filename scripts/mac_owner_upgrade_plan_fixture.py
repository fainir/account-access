"""Create fictional public-owner inputs for ordinary native parser checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("ordinary_fixture_required")
    root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root), str(root / "tests")]
    import pytest
    import test_owner_upgrade_plan as fixture

    with pytest.MonkeyPatch.context() as patch:
        _, _, arguments = fixture.fixture.__wrapped__(patch)
        inputs = arguments()
        raw = fixture.plan.derive(**inputs)
        fixture.plan.parse(raw, expected_sha256=fixture.plan.image.digest(raw), **inputs)
    files = {
        "plan.json": raw,
        "before.json": inputs["before_manifest"],
        "after.json": inputs["after_manifest"],
        "old-identity.json": inputs["old_identity"],
        "new-identity.json": inputs["new_identity"],
    }
    args.output.mkdir(mode=0o700)
    for name, data in files.items():
        descriptor = os.open(
            args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    print(
        json.dumps(
            {
                "status": "PREPARED_SYNTHETIC_OWNER_PLAN",
                "files_sha256": {
                    name: hashlib.sha256(data).hexdigest() for name, data in files.items()
                },
                "installed_reads": False,
                "production_ready": False,
            }
        )
    )


if __name__ == "__main__":
    main()
