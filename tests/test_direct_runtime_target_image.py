from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path
import zipfile

import pytest

from scripts.build_direct_runtime_target_image import replace_project_wheel


def wheel(path: Path, *, extra: bool = False) -> None:
    files = {
        "account_access/__init__.py": b"def main():\n    return 0\n",
        "account_access-0.8.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: account-access\nVersion: 0.8.0\n",
        "account_access-0.8.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "account_access-0.8.0.dist-info/entry_points.txt": b"[console_scripts]\naccount-access = account_access:main\n",
    }
    if extra:
        files["unrelated.py"] = b"must not be installed\n"
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, data in sorted(files.items()):
        encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        writer.writerow([name, "sha256=" + encoded, len(data)])
    record_name = "account_access-0.8.0.dist-info/RECORD"
    writer.writerow([record_name, "", ""])
    files[record_name] = record.getvalue().encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)


def runtime(root: Path) -> Path:
    value = root / "runtime"
    site = value / "lib/python3.12/site-packages"
    scripts = value / "bin"
    (site / "account_access").mkdir(parents=True)
    (site / "account_access-0.8.0.dist-info").mkdir()
    (site / "account_access/__init__.py").write_text("old = True\n")
    (site / "account_access-0.8.0.dist-info/METADATA").write_text("old metadata\n")
    scripts.mkdir()
    (scripts / "account-access").write_text("old launcher\n")
    return value


def test_replaces_only_the_project_package_and_launcher(tmp_path):
    target = runtime(tmp_path)
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    project = tmp_path / "account_access-0.8.0-py3-none-any.whl"
    wheel(project)

    assert replace_project_wheel(target, project, wheelhouse) == ("account-access",)
    site = target / "lib/python3.12/site-packages"
    assert (site / "account_access/__init__.py").read_bytes() == b"def main():\n    return 0\n"
    assert (site / "account_access-0.8.0.dist-info/INSTALLER").read_bytes() == (
        b"account-access-static-runtime-image 1\n"
    )
    assert (target / "bin/account-access").read_text().startswith("#!")
    assert (wheelhouse / project.name).read_bytes() == project.read_bytes()


def test_refuses_project_wheel_with_files_outside_its_package(tmp_path):
    target = runtime(tmp_path)
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    project = tmp_path / "account_access-0.8.0-py3-none-any.whl"
    wheel(project, extra=True)

    with pytest.raises(ValueError, match="project_wheel_contents_refused"):
        replace_project_wheel(target, project, wheelhouse)


def test_refuses_existing_package_symlink(tmp_path):
    target = runtime(tmp_path)
    site = target / "lib/python3.12/site-packages"
    (site / "account_access").rename(site / "account_access-old")
    (site / "account_access").symlink_to("account_access-old")
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    project = tmp_path / "account_access-0.8.0-py3-none-any.whl"
    wheel(project)

    with pytest.raises(ValueError, match="existing_project_install_invalid"):
        replace_project_wheel(target, project, wheelhouse)
