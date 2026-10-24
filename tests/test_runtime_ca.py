"""Owned synthetic package data; no supplied interpreter or pip is executed."""

import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import zipfile

import pytest

from macos import runtime_ca as ca


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(z, name, data):
    info = zipfile.ZipInfo(name)
    info.external_attr = 0o100644 << 16
    z.writestr(info, data)


def archive(files, *, extra=None):
    record = ca.DIST + "/RECORD"
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for name, raw in sorted(files.items()):
        checksum = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        writer.writerow([name, "sha256=" + checksum, len(raw)])
    writer.writerow([record, "", ""])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in {**files, record: text.getvalue().encode()}.items():
            put(z, name, data)
        if extra is not None:
            info, raw = extra
            z.writestr(info, raw)
    return stream.getvalue()


@pytest.fixture
def wheel_data(monkeypatch):
    pem = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"synthetic certificate data") + b"\n-----END CERTIFICATE-----\n"
    files = {
        "pip/__init__.py": b'__version__ = "26.2.2"\nraise AssertionError("package body must not execute")\n',
        "pip/empty.py": b"",
        "pip/_vendor/certifi/__init__.py": b'__version__ = "2026.10.19"\n',
        "pip/_vendor/vendor.txt": b"requests==2.34.2\n    certifi==2026.10.19\n",
        "pip/_vendor/certifi/cacert.pem": pem,
        ca.DIST + "/METADATA": b"Metadata-Version: 2.1\nName: pip\nVersion: 26.2.2\n",
        ca.DIST + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: inert-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ca.DIST + "/entry_points.txt": b"[console_scripts]\npip=pip._internal.cli.main:main\npip3=pip._internal.cli.main:main\n\n",
    }
    raw = archive(files)
    # Synthetic pins are confined to this fixture. Production has no pin or
    # destination override and still requires the exact official archive.
    monkeypatch.setattr(ca, "CA_SHA256", digest(pem))
    monkeypatch.setattr(ca, "WHEEL_BYTES", len(raw))
    monkeypatch.setattr(ca, "WHEEL_SHA256", digest(raw))
    return files, raw


@pytest.fixture
def staged(tmp_path, monkeypatch, wheel_data):
    files, raw = wheel_data
    source = tmp_path / "immutable-source"
    library = source / ca.LIBRARY
    originals = {
        "pip/__init__.py": b'__version__ = "26.2.1"\n',
        "pip/_vendor/vendor.txt": b"    certifi==2026.6.17\n",
        "pip/_vendor/certifi/__init__.py": b'__version__ = "2026.06.17"\n',
        "pip/_vendor/certifi/cacert.pem": b"old data - never executed",
        ca.SOURCE_DIST + "/METADATA": b"Name: pip\nVersion: 26.2.1\n",
        ca.SOURCE_DIST + "/RECORD": b"old manifest\n",
        "unrelated/__init__.py": b"unrelated source remains byte identical\n",
    }
    for name, data in originals.items():
        path = library / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    initializer = source / ca.ENSUREPIP / "__init__.py"
    initializer.parent.mkdir(parents=True)
    initializer.write_bytes(b'# synthetic ensurepip implementation\n_PIP_VERSION = "25.0.1"\n')
    seed = source / ca.ENSUREPIP / "_bundled" / ca.SOURCE_SEED
    seed.parent.mkdir()
    seed.write_bytes(b"old seed - never imported or executed")
    (source / "bin").mkdir()
    for name in ("pip", "pip3", "pip3.12"):
        (source / "bin" / name).write_bytes(b"old wrapper - never executed")
    pins = {name: digest((source / name).read_bytes()) for name in ca.SOURCE_PINS}
    monkeypatch.setattr(ca, "SOURCE_PINS", pins)
    payload = tmp_path / "private-copy"
    payload.mkdir()
    shutil.copytree(source, payload / "python")
    wheel = tmp_path / ca.WHEEL_NAME
    wheel.write_bytes(raw)
    monkeypatch.setattr(ca, "build_stage", lambda value: Path(value))
    return payload, wheel, source, files


def inventory(path):
    return {p.relative_to(path).as_posix(): p.read_bytes() for p in path.rglob("*") if p.is_file()}


def test_exact_source_profile_refreshed_in_private_copy_and_cloned_runtime(staged, monkeypatch):
    payload, wheel, source, files = staged
    before = inventory(source)
    # A package body cannot run, even if the host happens to have executable
    # Python available; the installer only renders its entrypoint as data.
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("runtime execution refused"))
    report = ca.refresh(payload, wheel)
    assert inventory(source) == before
    assert report["pip_version"] == "26.2.2"
    assert report["certifi_version"] == "2026.10.19"
    assert report["package_code_executed"] is False
    assert report["system_or_embedded_native_trust_stores_audited"] is False
    assert json.loads((payload / "runtime-ca-refresh.json").read_bytes()) == report
    python = payload / "python"
    assert b'_PIP_VERSION = "26.2.2"' in (python / ca.ENSUREPIP / "__init__.py").read_bytes()
    assert not (python / ca.ENSUREPIP / "_bundled" / ca.SOURCE_SEED).exists()
    assert not (python / "bin/pip3.12").exists()
    assert (python / ca.LIBRARY / "unrelated/__init__.py").read_bytes() == before[str(ca.LIBRARY / "unrelated/__init__.py")]
    shutil.copytree(python, payload / "runtime")
    ca.verify_generated_runtime(payload, report)
    (payload / "runtime" / ca.LIBRARY / "pip/_vendor/certifi/cacert.pem").write_bytes(b"substituted CA")
    with pytest.raises(ValueError, match="runtime_ca_refresh_refused"):
        ca.verify_generated_runtime(payload, report)


@pytest.mark.parametrize("fault", ["source", "seed-sibling", "unknown-dist", "source-link", "wrapper-link", "existing-receipt", "stale-bytecode"])
def test_source_conflicts_refuse_before_any_copy_mutation(staged, fault):
    payload, wheel, _, _ = staged
    root = payload / "python"
    if fault == "source":
        (root / ca.ENSUREPIP / "__init__.py").write_bytes(b"unknown source")
    elif fault == "seed-sibling":
        (root / ca.ENSUREPIP / "_bundled/unknown.whl").write_bytes(b"unknown seed")
    elif fault == "unknown-dist":
        (root / ca.LIBRARY / "pip-99.dist-info").mkdir()
    elif fault == "source-link":
        (root / ca.LIBRARY / "pip/linked.py").symlink_to("__init__.py")
    elif fault == "wrapper-link":
        (root / "bin/pip").unlink()
        (root / "bin/pip").symlink_to("pip3")
    elif fault == "existing-receipt":
        (payload / "runtime-ca-refresh.json").write_bytes(b"already present")
    else:
        (root / ca.ENSUREPIP / "stale.pyc").write_bytes(b"stale bytecode")
    before = inventory(root)
    with pytest.raises(ValueError, match="runtime_ca_refresh_refused"):
        ca.refresh(payload, wheel)
    assert inventory(root) == before


@pytest.mark.parametrize("fault", ["traversal", "absolute", "unknown-root", "case-collision", "symlink", "unexpected-executable", "record-hash", "record-size", "record-duplicate", "bad-version", "bad-ca"])
def test_untrusted_archive_structure_record_and_source_data_refused(wheel_data, fault):
    files, _ = wheel_data
    files = dict(files)
    extra = None
    if fault in {"traversal", "absolute", "unknown-root", "case-collision"}:
        name = {"traversal": "pip/../escape", "absolute": "/pip/escape", "unknown-root": "other/escape", "case-collision": "pip/__INIT__.py"}[fault]
        files[name] = b"forged"
    elif fault == "symlink":
        info = zipfile.ZipInfo("pip/link")
        info.external_attr = (0o120777 << 16)
        extra = info, b"__init__.py"
    elif fault == "unexpected-executable":
        info = zipfile.ZipInfo("pip/unreviewed-executable.py")
        info.external_attr = 0o100755 << 16
        extra = info, b"must never run"
    elif fault == "bad-version":
        files["pip/_vendor/certifi/__init__.py"] = b'__version__ = "2026.06.17"\n'
    elif fault == "bad-ca":
        files["pip/_vendor/certifi/cacert.pem"] += b"changed"
    raw = archive(files, extra=extra)
    if fault.startswith("record-"):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            rows = {i.filename: z.read(i) for i in z.infolist()}
        record = ca.DIST + "/RECORD"
        content = rows[record]
        if fault == "record-hash":
            content = content.replace(b"sha256=", b"sha512=", 1)
        elif fault == "record-size":
            content = content.replace(b",27\n", b",999\n", 1)
            if content == rows[record]:
                content = content.replace(b",", b",invalid", 1)
        else:
            content += content.splitlines(keepends=True)[0]
        rows[record] = content
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as z:
            for name, data in rows.items():
                put(z, name, data)
        raw = stream.getvalue()
    with pytest.raises((ValueError, KeyError)):
        ca._contents(raw)


def test_resealed_archive_is_not_an_official_wheel(wheel_data):
    _, raw = wheel_data
    for altered in (raw + b"changed", raw[:-1] + bytes([raw[-1] ^ 1])):
        with pytest.raises(ValueError, match="runtime_ca_refresh_refused"):
            ca.wheel_contents(altered)


def test_compromised_root_der_is_rejected_independently_of_bundle_labels(monkeypatch):
    der = b"synthetic compromised DER"
    monkeypatch.setattr(ca, "BAD_ROOTS", {digest(der)})
    raw = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der) + b"\n-----END CERTIFICATE-----\n"
    with pytest.raises(ValueError, match="runtime_ca_refresh_refused"):
        ca._fingerprints(raw)


def test_refresh_refuses_non_stage_before_reading_any_wheel(tmp_path, monkeypatch):
    monkeypatch.setattr(ca, "wheel_contents", lambda unused: pytest.fail("wheel must not be opened"))
    with pytest.raises(ValueError, match="ordinary_mac_runtime_preparation_required|private_package_build_copy_required"):
        ca.refresh(tmp_path, tmp_path / ca.WHEEL_NAME)


def test_duplicate_original_ensurepip_constant_refuses_even_with_fixture_source_pin(staged, monkeypatch):
    payload, wheel, _, _ = staged
    path = payload / "python" / ca.ENSUREPIP / "__init__.py"
    path.write_bytes(path.read_bytes() + b'_PIP_VERSION = "25.0.1"\n')
    pins = {**ca.SOURCE_PINS, str(ca.ENSUREPIP / "__init__.py"): digest(path.read_bytes())}
    monkeypatch.setattr(ca, "SOURCE_PINS", pins)
    before = inventory(payload / "python")
    with pytest.raises(ValueError, match="runtime_ca_refresh_refused"):
        ca.refresh(payload, wheel)
    assert inventory(payload / "python") == before
