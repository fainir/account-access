"""Native host launcher entrypoint, intentionally separate from the agent CLI."""
import argparse
import sys
from pathlib import Path

from .broker import Broker
from .chrome import run_host
from .storage import Store, load_key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--key-file")
    parser.add_argument("origin")
    args = parser.parse_args()
    try:
        root = Path(args.root)
        broker = Broker(Store(root, load_key(root, Path(args.key_file) if args.key_file else None)))
        return run_host(broker)
    except Exception:
        return 2


if __name__ == "__main__":
    sys.exit(main())
