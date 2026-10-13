"""Register an unpacked extension's exact ID with the owner-only native host."""
import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

from account_access.storage import Store, load_key, private_file

parser = argparse.ArgumentParser(description="Register the explicit Account Access Chrome extension ID")
parser.add_argument("extension_id")
parser.add_argument("--root", required=True)
parser.add_argument("--development-key-file")
args = parser.parse_args()
if not re.fullmatch("[a-p]{32}", args.extension_id):
    raise SystemExit("Expected the extension ID shown by Chrome")
root = Path(args.root).expanduser().resolve()
store = Store(root, load_key(root, Path(args.development_key_file) if args.development_key_file else None))
extension_origin = "chrome-extension://" + args.extension_id + "/"
store.put("chrome-extension-origin", extension_origin)
launcher = root / "chrome-native-host"
command = [sys.executable, "-m", "account_access.chrome_entry", "--root", str(root)]
if args.development_key_file:
    command += ["--key-file", args.development_key_file]
script = "#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n'
private_file(launcher, script.encode(), replace=launcher.exists())
os.chmod(launcher, 0o700)
if sys.platform == "darwin":
    folder = Path.home() / "Library/Application Support/Google/Chrome/NativeMessagingHosts"
elif sys.platform.startswith("linux"):
    folder = Path.home() / ".config/google-chrome/NativeMessagingHosts"
else:
    raise SystemExit("Automatic native-host registration is currently implemented for macOS and Linux")
manifest = folder / "com.account_access.session.json"
private_file(manifest, json.dumps({"name": "com.account_access.session", "description": "Explicit Account Access session connector",
                                   "path": str(launcher), "type": "stdio", "allowed_origins": [extension_origin]}).encode(), replace=manifest.exists())
print(json.dumps({"status": "REGISTERED", "extension_id": args.extension_id, "manifest": str(manifest)}))
