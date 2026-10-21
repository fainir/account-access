"""Retired unguarded agent QA entry point; use the isolated verification harness."""

import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", choices=["codex", "claude"])
    parser.add_argument("--workspace", required=True)
    parser.parse_known_args()
    raise SystemExit(
        "This legacy harness is retired because its global-client boundary was not enforced. "
        "Use: uv run python scripts/agent_verification_smoke.py AGENT "
        "--workspace /absolute/path/to/a-new-empty-test-workspace")


if __name__ == "__main__":
    main()
