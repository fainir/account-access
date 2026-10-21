"""Owner-user Chrome registration for the protected native app; no vault access."""

import json
import os
from pathlib import Path
import pwd
import shlex
import sys

from .agent_setup import RUNTIME, _checked, _directories
from .errors import AccessError
from .google_messages_host import HOST, extension_id
from .storage import private_file
from .worker_bootstrap import root_managed_path

APP = Path("/Library/Application Support/Account Access/owner.app/Contents/MacOS/AccountAccess")
RESOURCES = Path("/Library/Application Support/Account Access/owner.app/Contents/Resources/GoogleMessagesExtension")
RELATIVE = Path("Library/Application Support/Account Access/browser-v1")
CHROME = Path("Library/Application Support/Google/Chrome/NativeMessagingHosts")
FILES = ["manifest.json", "background.js", "reader.js", "popup.js", "popup.html", "popup.css"]


def prepare(home, *, app=APP, resources=RESOURCES, protected=root_managed_path):
    home = Path(home)
    protected(app)
    for name in FILES:
        protected(resources / name)
    # The compiled host pins the same public extension identity. Do not stage
    # another bundle's key or copy mutable extension code into the user's vault.
    from .google_messages_host import RESOURCES as package_resources
    if any((resources / name).read_bytes() != (package_resources / name).read_bytes() for name in FILES):
        raise AccessError("DENIED", "browser_extension_payload_changed")
    for relative in [RELATIVE, CHROME]:
        _directories(home, relative)
    launcher = home / RELATIVE / "native-host"
    registration = home / CHROME / (HOST + ".json")
    command = ("#!/bin/sh\nexec " + shlex.join([str(app), "--browser-native-host"]) + ' "$@"\n').encode()
    origin = "chrome-extension://" + extension_id() + "/"
    if launcher.exists() or launcher.is_symlink():
        if _checked(launcher, private=True) != command:
            raise AccessError("NEEDS_USER", "existing_browser_host_needs_review")
    if registration.exists() or registration.is_symlink():
        previous = json.loads(_checked(registration, private=True))
        if (type(previous) is not dict
                or set(previous) != {"name", "description", "path", "type", "allowed_origins"}
                or previous["name"] != HOST or previous["type"] != "stdio"
                or previous["allowed_origins"] != [origin]
                or previous["path"] not in {
                    str(launcher), str(home / "Library/Application Support/Account Access/google-messages-native-host")
                }):
            raise AccessError("NEEDS_USER", "existing_browser_host_needs_review")
    for relative in [RELATIVE, CHROME]:
        _directories(home, relative, create=True)
    private_file(launcher, command, replace=launcher.exists())
    os.chmod(launcher, 0o700)
    body = dict(name=HOST, description="Account Access approved browser connections",
                path=str(launcher), type="stdio", allowed_origins=[origin])
    private_file(registration, json.dumps(body).encode(), replace=registration.exists())
    return dict(status="PREPARED", extension_path=str(resources), extension_id=extension_id())


def main():
    try:
        if (len(sys.argv) != 1 or sys.platform != "darwin" or os.getuid() == 0
                or os.getuid() != os.geteuid() or Path(sys.executable).resolve() != RUNTIME.resolve()):
            raise AccessError("DENIED", "ordinary_owner_context_required")
        root_managed_path(RUNTIME)
        root_managed_path(Path(__file__))
        result = prepare(Path(pwd.getpwuid(os.getuid()).pw_dir))
        print(json.dumps(result))
        return 0
    except Exception:
        print('{"status":"NEEDS_USER","reason":"browser_setup_not_completed"}')
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
