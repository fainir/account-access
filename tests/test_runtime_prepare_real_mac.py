"""Ordinary-user signing probe in a disposable Mac; never an owner-Mac probe."""

import importlib.util
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

import pytest

from account_access.worker_bootstrap import root_managed_path
from macos.runtime_prepare import digest, preparation_plan, prepare
from macos.system_package import command


@pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true",
    reason="Requires ordinary-user disposable Mac CI and its fixture browser",
)
def test_prepared_node_uses_reviewed_jit_for_sandboxed_playwright_without_debug_entitlement():
    assert os.getuid() != 0 and os.environ.get("RUNNER_OS") == "macOS"
    browsers = Path(os.environ["PLAYWRIGHT_BROWSERS_PATH"]).resolve(strict=True)
    assert browsers.parent.parent == Path("/Library/PrivilegedHelperTools")
    assert (
        browsers.parent.name.startswith("account-access-worker-qa-") and browsers.name == "browsers"
    )
    root_managed_path(browsers)
    node = (
        Path(next(iter(importlib.util.find_spec("playwright").submodule_search_locations)))
        / "driver/node"
    )
    original_node = digest(node)
    with tempfile.TemporaryDirectory(prefix="account-access-system-package-") as temporary:
        stage = Path(temporary).resolve(strict=True)
        payload = stage / "payload"
        for name in ["python", "browsers", "wheels"]:
            (payload / name).mkdir(parents=True)
        source = stage / "fixture.c"
        source.write_text("int main(void) { return 0; }\n")
        fixture = payload / "python/python"
        command(["/usr/bin/xcrun", "clang", str(source), "-o", str(fixture)])
        shutil.copyfile(fixture, payload / "browsers/browser")
        project = payload / "wheels/project.whl"
        with zipfile.ZipFile(project, "w") as archive:
            archive.writestr("fixture.py", "# controlled package")
        wheel = payload / "wheels/node_fixture.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.write(node, "driver/node")
            archive.writestr("fixture.dist-info/RECORD", "controlled fixture")
        upstream = digest(wheel)
        lock = b"node-fixture==1 --hash=sha256:" + upstream.encode() + b"\n"
        plan = preparation_plan(payload, lock, project.name, digest(project))
        plan["executables"][original_node]["entitlements"] = {
            "com.apple.security.cs.allow-jit": True
        }
        derived, receipt = prepare(
            payload,
            lock,
            project.name,
            digest(project),
            "-",
            "fixture",
            plan,
            command,
            development=True,
        )
        assert receipt["development"] is True and receipt["notarization_verified"] is False
        assert receipt["installed_runtime_verified"] is False
        assert upstream.encode() not in derived and digest(wheel).encode() in derived
        prepared_node = stage / "prepared-node"
        with zipfile.ZipFile(wheel) as archive:
            prepared_node.write_bytes(archive.read("driver/node"))
        prepared_node.chmod(0o755)
        public = command(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(prepared_node)])
        assert plistlib.loads(public.stdout) == {"com.apple.security.cs.allow-jit": True}
        home = stage / "home"
        home.mkdir(mode=0o700)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "LANG": "C",
            "PLAYWRIGHT_NODEJS_PATH": str(prepared_node),
            "PLAYWRIGHT_BROWSERS_PATH": str(browsers),
        }
        jit = subprocess.run(
            [
                str(prepared_node),
                "-e",
                "const vm=require('node:vm'),crypto=require('node:crypto');"
                "if(new vm.Script('let n=0;for(let i=0;i<100000;i++)n+=i;n').runInNewContext()!==4999950000)process.exit(1);"
                "if(crypto.createHash('sha256').update('fixture').digest('hex').length!==64)process.exit(1);"
                "process.stdout.write('JIT_OK')",
            ],
            env=env,
            cwd=stage,
            capture_output=True,
            timeout=20,
        )
        assert jit.returncode == 0 and jit.stdout == b"JIT_OK", jit.stderr.decode(errors="replace")[
            :1000
        ]
        browser = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "from playwright.sync_api import sync_playwright\n"
                "with sync_playwright() as p:\n"
                " b=p.chromium.launch(chromium_sandbox=True)\n"
                " c=b.new_context()\n"
                " c.route('**/*',lambda route:route.abort())\n"
                " page=c.new_page()\n"
                " page.set_content('<h1>Runtime fixture</h1>')\n"
                " assert page.locator('h1').inner_text()=='Runtime fixture'\n"
                " b.close()\n"
                " print('BROWSER_OK')\n",
            ],
            env=env,
            cwd=stage,
            capture_output=True,
            timeout=45,
        )
        assert browser.returncode == 0 and browser.stdout.strip() == b"BROWSER_OK", (
            browser.stderr.decode(errors="replace")[:2000]
        )
        assert digest(node) == original_node
