"""Review explicit test-only permissions for an ad-hoc disposable Mac package.

This is never a production permission profile. Ad-hoc runtime/library signatures
have no publisher team; the fixture needs library-validation exceptions that
must not be treated as evidence for the production signer/profile.
"""

import argparse
import json
import os
from pathlib import Path
import sys


def fixture_plan(plan):
    if (
        type(plan) is not dict
        or set(plan) != {"schema", "python_sha256", "browsers_sha256", "executables"}
        or type(plan.get("schema")) is not int
        or plan["schema"] != 1
        or type(plan.get("executables")) is not dict
    ):
        raise ValueError("invalid_fixture_runtime_plan")
    result = json.loads(json.dumps(plan))
    for row in result["executables"].values():
        if (
            type(row) is not dict
            or set(row) != {"paths", "entitlements"}
            or not isinstance(row["paths"], list)
            or not row["paths"]
            or any(
                type(path) is not str or not path.startswith(("python/", "browsers/", "wheels/"))
                for path in row["paths"]
            )
            or row["entitlements"] != {}
        ):
            raise ValueError("fixture_plan_must_start_from_empty_review")
        exceptions = {"com.apple.security.cs.disable-library-validation": True}
        for path in row["paths"]:
            name = Path(path).name.lower()
            if (
                path.startswith("python/")
                or name == "node"
                or (
                    path.startswith("browsers/")
                    and "chrome" in path.lower()
                    and "crashpad" not in name
                    and "ffmpeg" not in name
                )
            ):
                exceptions["com.apple.security.cs.allow-jit"] = True
        row["entitlements"] = exceptions
    return result


def main(argv=None):
    if (
        sys.platform != "darwin"
        or os.getuid() == 0
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "macOS"
    ):
        raise RuntimeError("prepared_fixture_plan_requires_disposable_mac_ci")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    result = fixture_plan(json.loads(args.input.read_bytes()))
    with args.output.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print("Wrote explicit ad-hoc fixture permissions; no production profile was generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
