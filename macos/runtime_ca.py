"""Refresh packaging tools only in a private, fresh offline build copy.

The exact upstream pip wheel is installed as data. Neither the supplied Python
nor pip/ensurepip is executed. This is not an installed-service repair.
"""

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import zipfile

from installer import install
from installer.sources import WheelFile

from .runtime_image import Destination
from .runtime_prepare import build_stage, tree_digest

VERSION = "26.2.2"
WHEEL_NAME = "pip-26.2.2-py3-none-any.whl"
WHEEL_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
WHEEL_BYTES = 1819850
CA_SHA256 = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"
BAD_ROOTS = frozenset((
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4",
))
LIBRARY = Path("lib/python3.12/site-packages")
ENSUREPIP = Path("lib/python3.12/ensurepip")
DIST = "pip-26.2.2.dist-info"
EXECUTABLE_MEMBERS = {"pip/_internal/__init__.py", "pip/_vendor/certifi/tests/test_certify.py"}
SOURCE_DIST = "pip-26.2.1.dist-info"
SOURCE_SEED = "pip-25.0.1-py3-none-any.whl"
SOURCE_PINS = {
    str(LIBRARY / "pip/__init__.py"): "04aa76ceab0f4341e292daae35637f2f8718b183313cc2fb588d1304cb9c0443",
    str(LIBRARY / "pip/_vendor/vendor.txt"): "3df0c9601bfa2e0dca23cc574a4f900a4d7fdad060ab203fab8354350ed93320",
    str(LIBRARY / "pip/_vendor/certifi/__init__.py"): "f96d51ff2f1609a4a44f5b5d8eec47ff34c1658d581fac5081d3759db05a8ce1",
    str(LIBRARY / "pip/_vendor/certifi/cacert.pem"): "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0",
    str(ENSUREPIP / "__init__.py"): "90f6c76cd9ef7ed6daa198bb9ef771139683487f1b061211be7aa511831b2028",
    str(ENSUREPIP / "_bundled" / SOURCE_SEED): "c46efd13b6aa8279f33f2864459c8ce587ea6a1a59ee20de055868d8f7688f7f",
}


def _fail():
    raise ValueError("runtime_ca_refresh_refused")


def _require(value):
    if not value:
        _fail()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _fingerprints(raw):
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\r\n]+?)-----END CERTIFICATE-----", raw)
    _require(0 < len(blocks) <= 500 and raw.count(b"-----BEGIN CERTIFICATE-----") == len(blocks)
             and raw.count(b"-----END CERTIFICATE-----") == len(blocks))
    result = [_sha(base64.b64decode(re.sub(rb"\s+", b"", block), validate=True)) for block in blocks]
    _require(len(result) == len(set(result)) and not BAD_ROOTS.intersection(result))
    return result


def _contents(raw):
    """Bounded inert wheel structure; the public caller also requires its pin."""
    _require(type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        _require(0 < len(entries) <= 2000 and sum(row.file_size for row in entries) <= 16 * 1024 * 1024)
        files, folded = {}, set()
        for row in entries:
            name = row.filename
            mode = row.external_attr >> 16
            _require(not row.is_dir() and not row.flag_bits & 1 and 0 <= row.file_size <= 1024 * 1024
                     and re.fullmatch(r"[A-Za-z0-9_./-]+", name) is not None
                     and all(part not in {"", ".", ".."} for part in name.split("/"))
                     and name.split("/", 1)[0] in {"pip", DIST}
                     and "/" in name and name.casefold() not in folded
                     and stat.S_IFMT(mode) == stat.S_IFREG
                     and stat.S_IMODE(mode) == (0o755 if name in EXECUTABLE_MEMBERS else 0o644))
            folded.add(name.casefold())
            files[name] = archive.read(row)
    record = DIST + "/RECORD"
    rows = list(csv.reader(io.StringIO(files[record].decode("utf-8"), newline="")))
    _require(len(rows) == len(files))
    names = set()
    for row in rows:
        _require(len(row) == 3 and row[0] in files and row[0] not in names)
        name, pin, size = row
        names.add(name)
        expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).decode().rstrip("=")
        _require((pin == size == "") if name == record else (pin == expected and size == str(len(files[name]))))
    _require(names == set(files)
             and b'__version__ = "26.2.2"' in files["pip/__init__.py"]
             and b'__version__ = "2026.10.19"' in files["pip/_vendor/certifi/__init__.py"]
             and files["pip/_vendor/vendor.txt"].splitlines().count(b"    certifi==2026.10.19") == 1
             and files[DIST + "/entry_points.txt"] == b"[console_scripts]\npip=pip._internal.cli.main:main\npip3=pip._internal.cli.main:main\n\n"
             and files[DIST + "/WHEEL"].splitlines().count(b"Root-Is-Purelib: true") == 1
             and files[DIST + "/WHEEL"].splitlines().count(b"Tag: py3-none-any") == 1
             and files[DIST + "/METADATA"].splitlines().count(b"Name: pip") == 1
             and files[DIST + "/METADATA"].splitlines().count(b"Version: 26.2.2") == 1)
    ca = files["pip/_vendor/certifi/cacert.pem"]
    _require(_sha(ca) == CA_SHA256)
    return files, _fingerprints(ca)


def wheel_contents(raw):
    try:
        _require(type(raw) is bytes and len(raw) == WHEEL_BYTES and _sha(raw) == WHEEL_SHA256)
        return _contents(raw)
    except (ValueError, TypeError, KeyError, UnicodeError, zipfile.BadZipFile, RecursionError):
        _fail()


def _regular(root, relative, maximum=2 * 1024 * 1024):
    parts = Path(relative).parts
    _require(parts and not Path(relative).is_absolute() and all(p not in {"", ".", ".."} for p in parts))
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum)
            pieces, size = [], 0
            while True:
                piece = os.read(fd, min(65536, maximum + 1 - size))
                if not piece:
                    break
                pieces.append(piece)
                size += len(piece)
                _require(size <= maximum)
            after = os.fstat(fd)
            fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns")
            _require(size == before.st_size and all(getattr(before, p) == getattr(after, p) for p in fields))
            return b"".join(pieces)
        finally:
            os.close(fd)
    except OSError:
        _fail()
    finally:
        os.close(directory)


def _plain_tree(root):
    _require(root.is_dir() and not root.is_symlink())
    count = 0
    for path in root.rglob("*"):
        count += 1
        info = path.lstat()
        _require(count <= 5000 and not stat.S_ISLNK(info.st_mode)
                 and (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)))


class _PipDestination(Destination):
    def write_script(self, name, module, attr, section):
        _require(name in {"pip", "pip3"} and module == "pip._internal.cli.main" and attr == "main"
                 and section == "console")
        return super().write_script(name, module, attr, section)


def _verify(root, files, ensurepip_sha256):
    _require(_sha(_regular(root, ENSUREPIP / "__init__.py")) == ensurepip_sha256
             and {p.name for p in (root / ENSUREPIP / "_bundled").iterdir()} == {WHEEL_NAME})
    wheel_contents(_regular(root, ENSUREPIP / "_bundled" / WHEEL_NAME))
    library = root / LIBRARY
    _require({p.name for p in library.glob("pip-*.dist-info")} == {DIST})
    for prefix in ("pip", DIST):
        _plain_tree(library / prefix)
        actual = {p.relative_to(library).as_posix() for p in (library / prefix).rglob("*") if p.is_file()}
        expected = {name for name in files if name.startswith(prefix + "/")}
        if prefix == DIST:
            expected.add(DIST + "/INSTALLER")
        _require(actual == expected)
    for name, raw in files.items():
        if name != DIST + "/RECORD":
            _require(_regular(library, name) == raw)
    wrappers = {}
    for name in ("pip", "pip3"):
        raw = _regular(root, "bin/" + name)
        _require(raw.startswith(b"#!/Library/Application Support/Account Access/runtime/bin/python\n")
                 or raw.startswith(b"#!/bin/sh\n'''exec' '/Library/Application Support/Account Access/runtime/bin/python'"))
        wrappers["../../../bin/" + name] = raw
    _require(not (root / "bin/pip3.12").exists() and not (root / "bin/pip3.12").is_symlink())
    # The static installer records generated wrapper bytes and INSTALLER too.
    installed = {name: _regular(library, name) for name in files}
    installed[DIST + "/INSTALLER"] = _regular(library, DIST + "/INSTALLER")
    installed.update(wrappers)
    record = DIST + "/RECORD"
    rows = list(csv.reader(io.StringIO(installed[record].decode(), newline="")))
    _require(len(rows) == len(installed))
    seen = set()
    for row in rows:
        _require(len(row) == 3 and row[0] in installed and row[0] not in seen)
        name, pin, size = row
        seen.add(name)
        digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(installed[name]).digest()).decode().rstrip("=")
        _require((pin == size == "") if name == record else pin == digest and size == str(len(installed[name])))
    _require(seen == set(installed))


def refresh(payload, wheel):
    payload = build_stage(payload)
    root = payload / "python"
    _require(Path(wheel).name == WHEEL_NAME)
    raw = _regular(Path(wheel).parent, Path(wheel).name)
    files, fingerprints = wheel_contents(raw)
    receipt = payload / "runtime-ca-refresh.json"
    _require(not receipt.exists() and not receipt.is_symlink())
    before = tree_digest(root)
    for relative, pin in SOURCE_PINS.items():
        _require(_sha(_regular(root, relative)) == pin)
    library, bundled = root / LIBRARY, root / ENSUREPIP / "_bundled"
    _require({p.name for p in library.glob("pip-*.dist-info")} == {SOURCE_DIST}
             and {p.name for p in bundled.iterdir()} == {SOURCE_SEED})
    _require(not any(path.suffix in {".pyc", ".pyo"} for path in (root / ENSUREPIP).rglob("*")))
    for path in (library / "pip", library / SOURCE_DIST, bundled):
        _plain_tree(path)
    for name in ("pip", "pip3", "pip3.12"):
        _regular(root, "bin/" + name)
    source = _regular(root, ENSUREPIP / "__init__.py")
    needle = b'_PIP_VERSION = "25.0.1"'
    _require(source.count(needle) == 1)
    replacement = source.replace(needle, b'_PIP_VERSION = "26.2.2"')
    # All input/profile/ZIP checks precede mutations. Failure discards this
    # fresh temporary package copy; source inputs and installed data are absent.
    shutil.rmtree(library / "pip")
    shutil.rmtree(library / SOURCE_DIST)
    for name in ("pip", "pip3", "pip3.12"):
        (root / "bin" / name).unlink()
    (bundled / SOURCE_SEED).unlink()
    target = bundled / WHEEL_NAME
    target.write_bytes(raw)
    _require(hashlib.sha256(target.read_bytes()).hexdigest() == WHEEL_SHA256)
    target.chmod(0o644)
    (root / ENSUREPIP / "__init__.py").write_bytes(replacement)
    with WheelFile.open(target) as source_wheel:
        install(source_wheel, _PipDestination(root, "pip"),
                additional_metadata={"INSTALLER": b"account-access-static-runtime-ca-refresh 1\n"})
    _verify(root, files, _sha(replacement))
    report = {
        "schema": 1, "transform": "account-access-frozen-python312-packaging-ca-refresh-v1",
        "source_python_sha256": before, "refreshed_python_sha256": tree_digest(root),
        "official_pip_wheel_sha256": WHEEL_SHA256, "pip_version": VERSION,
        "certifi_version": "2026.10.19", "ca_sha256": CA_SHA256, "ca_certificates": len(fingerprints),
        "removed_root_certificate_sha256": sorted(BAD_ROOTS),
        "source_profile_sha256": dict(SOURCE_PINS), "ensurepip_initializer_sha256": _sha(replacement),
        "both_active_and_seed_refreshed": True, "package_code_executed": False,
        "system_or_embedded_native_trust_stores_audited": False,
    }
    receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    receipt.chmod(0o644)
    return report


def verify_generated_runtime(payload, report):
    payload = build_stage(payload)
    files, _ = wheel_contents(_regular(payload / "python", ENSUREPIP / "_bundled" / WHEEL_NAME))
    for prefix in ("python", "runtime"):
        _verify(payload / prefix, files, report["ensurepip_initializer_sha256"])
