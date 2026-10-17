"""Read-only native verification against Python-produced public payload fixtures.

These tests run as the ordinary user, never against installed code/account data.
Actual root execution belongs only to the disposable Mac Installer workflow.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from account_access import package_manifest

pytestmark = pytest.mark.skipif(sys.platform != "darwin" or os.getuid() == 0,
                                reason="ordinary Mac native fixture required")
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def native_verifier(tmp_path_factory):
    output = tmp_path_factory.mktemp("native-install-check") / "check"
    subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                    "-framework", "Foundation", "-framework", "CryptoKit",
                    str(ROOT / "macos/InstallerPayload.swift"),
                    str(ROOT / "macos/Tests/InstallerPayloadChecks.swift"), "-o", str(output)],
                   check=True, capture_output=True, timeout=120)
    return output


@pytest.fixture(scope="session")
def production_verifier(tmp_path_factory):
    output = tmp_path_factory.mktemp("native-install-production-context") / "AccountAccess-installerverify"
    subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                    "-D", "ACCOUNT_ACCESS_INSTALL_VERIFIER_MAIN", "-framework", "Foundation", "-framework", "CryptoKit",
                    str(ROOT / "macos/InstallerPayload.swift"), "-o", str(output)],
                   check=True, capture_output=True, timeout=120)
    return output


@pytest.mark.parametrize("arguments", [[], ["--manifest", "/unrelated"], ["--fixture-root", "/unrelated"],
                                     ["--install"], ["--verify-image-manifest-fd", "3"]])
def test_production_entrypoint_refuses_ordinary_user_before_reading_installed_or_supplied_paths(production_verifier, arguments):
    result = subprocess.run([str(production_verifier), *arguments], capture_output=True, timeout=10)
    assert result.returncode == 78 and not result.stderr
    assert json.loads(result.stdout) == {"schema": 1, "status": "FAILED", "reason": "installer_verifier_context_required"}


@pytest.fixture
def fixture(tmp_path):
    root = tmp_path / "public-image"
    support = root / package_manifest.SUPPORT
    app = root / package_manifest.OWNER_APP
    (support / "bin").mkdir(parents=True)
    (app / "Contents/MacOS").mkdir(parents=True)
    (support / "bin/tool").write_bytes(b"synthetic executable; never executed\n")
    (support / "bin/tool").chmod(0o755)
    (support / "public.json").write_text('{"fixture":true}\n')
    (support / "current").symlink_to("bin", target_is_directory=True)
    (support / "bin/alias").symlink_to("tool")
    (app / "Contents/MacOS/AccountAccess").write_bytes(b"synthetic application; never executed\n")
    for path in [root, *root.rglob("*")]:
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & 0o777 & ~0o022)
    path = tmp_path / "RecoveryManifest.json"
    path.write_bytes(package_manifest.build(root, "0.8.0", "arm64"))
    return root, support, app, path


def verify(native_verifier, fixture):
    root, _, _, manifest = fixture
    result = subprocess.run([str(native_verifier), str(manifest), str(root)],
                            capture_output=True, text=True, timeout=15)
    assert not result.stderr
    value = json.loads(result.stdout)
    assert (result.returncode == 0) == (value["status"] == "VERIFIED")
    return value


def test_native_verifier_accepts_python_inventory_and_can_repeat_without_changing_files(native_verifier, fixture):
    root, _, _, manifest = fixture
    before = package_manifest.build(root, "0.8.0", "arm64")
    value = verify(native_verifier, fixture)
    assert value == {"status": "VERIFIED", "files": 3, "directories": 5, "aliases": 2}
    assert package_manifest.build(root, "0.8.0", "arm64") == before == manifest.read_bytes()


@pytest.mark.parametrize("damage", ["bytes", "mode", "writable", "privileged", "hardlink", "missing", "extra", "fifo",
                                  "file-alias", "directory-alias", "alias-target", "alias-absolute", "ancestor-alias"])
def test_native_verifier_refuses_changed_unsafe_or_unlisted_public_payload(native_verifier, fixture, tmp_path, damage):
    root, support, _, _ = fixture
    path = support / "public.json"
    if damage == "bytes":
        path.write_bytes(b"changed fixture")
    elif damage in {"mode", "writable", "privileged"}:
        path.chmod({"mode": 0o600, "writable": 0o666, "privileged": 0o4644}[damage])
    elif damage == "hardlink":
        os.link(path, tmp_path / "unrelated-alias")
    elif damage in {"extra", "fifo"}:
        if damage == "fifo":
            (support / "bin/tool").unlink()
            os.mkfifo(support / "bin/tool")
        else:
            (support / "unlisted").write_bytes(b"extra fixture")
    elif damage == "missing":
        path.unlink()
    elif damage in {"file-alias", "directory-alias"}:
        target = tmp_path / "outside"
        if damage == "file-alias":
            target.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(target)
        else:
            (support / "bin").rename(target)
            (support / "bin").symlink_to(target, target_is_directory=True)
    elif damage == "ancestor-alias":
        (root / "Library").rename(root / "moved")
        (root / "Library").symlink_to(root / "moved", target_is_directory=True)
    else:
        (support / "bin/alias").unlink()
        (support / "bin/alias").symlink_to("../public.json" if damage == "alias-target" else str(path))
    assert verify(native_verifier, fixture)["status"] == "REFUSED"


@pytest.mark.parametrize("damage", ["schema", "version", "architecture", "extra-root", "extra-field", "mode-bool",
                                  "size-bool", "bad-hash", "hash-newline", "missing-parent", "parent-file", "dotdot",
                                  "absolute-name", "control-name", "backslash-name", "case-collision", "deep-name",
                                  "dangling-alias", "absolute-alias", "outside-return", "cycle", "non-directory-hop"])
def test_native_manifest_refuses_ambiguous_or_unsafe_image_metadata(native_verifier, fixture, damage):
    _, _, _, manifest = fixture
    value = json.loads(manifest.read_bytes())
    rows = value["roots"]["/" + str(package_manifest.SUPPORT)]
    if damage in {"schema", "version", "architecture", "extra-field"}:
        value[{"extra-field": "unrecognized"}.get(damage, damage)] = {"schema": True, "version": "0.7.4", "architecture": "x86_64"}.get(damage, True)
    elif damage == "extra-root":
        value["roots"]["/unrelated"] = {"": {"kind": "directory", "mode": 0o755}}
    elif damage in {"mode-bool", "size-bool", "bad-hash", "hash-newline"}:
        if damage.endswith("bool"):
            rows["public.json"][damage.split("-")[0]] = True
        else:
            rows["public.json"]["sha256"] = "invalid" if damage == "bad-hash" else rows["public.json"]["sha256"] + "\n"
    elif damage == "missing-parent":
        del rows["bin"]
    elif damage == "parent-file":
        rows["bin"] = rows["public.json"]
    elif damage in {"dotdot", "absolute-name", "control-name", "backslash-name", "case-collision", "deep-name"}:
        name = {"dotdot": "../escape", "absolute-name": "/escape", "control-name": "line\nbreak",
                "backslash-name": "back\\slash", "case-collision": "PUBLIC.JSON", "deep-name": "/".join(["child"] * 129)}[damage]
        rows[name] = rows["public.json"]
    else:
        target = {"dangling-alias": "missing", "absolute-alias": "/etc/passwd", "outside-return": "../../Account Access/bin/tool",
                  "cycle": "alias", "non-directory-hop": "tool/../tool"}[damage]
        rows["bin/alias"]["target"] = target
    manifest.write_text(json.dumps(value))
    assert verify(native_verifier, fixture)["status"] == "REFUSED"


def test_alias_graph_total_work_is_bounded_before_any_image_directory_is_opened(native_verifier, fixture):
    root, _, _, manifest = fixture
    value = json.loads(manifest.read_bytes())
    rows = value["roots"]["/" + str(package_manifest.SUPPORT)]
    for index in range(40):
        target = "chain" + str(index + 1) if index < 39 else "bin"
        rows["chain" + str(index)] = {"kind": "symlink", "target": target + "/." * 127}
    for index in range(200):
        rows["fanout" + str(index)] = {"kind": "symlink", "target": "chain0"}
    manifest.write_text(json.dumps(value))
    shutil.rmtree(root)
    assert verify(native_verifier, fixture) == {"status": "REFUSED", "reason": "installer_payload_limit"}


def test_native_check_accepts_standard_shared_applications_parent_without_changing_it(native_verifier, fixture):
    root, _, _, _ = fixture
    parent = root / "Applications"
    parent.chmod(0o775)
    assert verify(native_verifier, fixture)["status"] == "VERIFIED"
    assert parent.stat().st_mode & 0o777 == 0o775


def test_native_verifier_refuses_acl_write_grants_on_a_fixture_file(native_verifier, fixture):
    _, support, _, _ = fixture
    path = support / "public.json"
    subprocess.run(["/bin/chmod", "+a", "everyone allow write", str(path)], check=True, capture_output=True)
    try:
        assert verify(native_verifier, fixture)["status"] == "REFUSED"
    finally:
        subprocess.run(["/bin/chmod", "-N", str(path)], check=True, capture_output=True)


def test_native_manifest_file_cannot_be_a_symlink(native_verifier, fixture, tmp_path):
    *_, manifest = fixture
    moved = tmp_path / "other-manifest"
    shutil.move(manifest, moved)
    manifest.symlink_to(moved)
    assert verify(native_verifier, fixture)["status"] == "REFUSED"


@pytest.mark.parametrize("damage", [None, "strict-walk", "no-child", "wrong-parent", "no-sticky", "wrong-mode",
                                  "writable-child", "group-writable-child", "writable-descendant", "child-alias",
                                  "temporary-parent-alias", "parent-acl", "child-acl"])
def test_installer_resources_allow_only_exact_sticky_parent_with_protected_children(native_verifier, tmp_path, damage):
    root = tmp_path / "synthetic-root"
    shared = root / "private/tmp"
    resources = shared / "PKInstallSandbox.fixture/Scripts/package.fixture"
    resources.mkdir(parents=True)
    for path in [root, *root.rglob("*")]:
        path.chmod(0o755)
    shared.chmod(0o1777)
    requested = "/private/tmp/PKInstallSandbox.fixture/Scripts/package.fixture"
    argument = "--resources"
    acl_path = None
    if damage == "strict-walk":
        argument = "--directory"
    elif damage == "no-child":
        requested = "/private/tmp"
    elif damage == "wrong-parent":
        (root / "private").rename(root / "unrelated")
        requested = requested.replace("/private/", "/unrelated/")
    elif damage in {"no-sticky", "wrong-mode"}:
        shared.chmod(0o777 if damage == "no-sticky" else 0o1775)
    elif damage in {"writable-child", "group-writable-child"}:
        (shared / "PKInstallSandbox.fixture").chmod(0o777 if damage == "writable-child" else 0o775)
    elif damage == "writable-descendant":
        resources.chmod(0o777)
    elif damage in {"child-alias", "temporary-parent-alias"}:
        original = shared if damage == "temporary-parent-alias" else shared / "PKInstallSandbox.fixture"
        moved = root / "moved"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
    elif damage in {"parent-acl", "child-acl"}:
        acl_path = shared if damage == "parent-acl" else shared / "PKInstallSandbox.fixture"
        subprocess.run(["/bin/chmod", "+a", "everyone allow write", str(acl_path)], check=True, capture_output=True)
    try:
        before = {str(path): path.lstat().st_mode for path in [root, *root.rglob("*")]}
        result = subprocess.run([str(native_verifier), argument, str(root), requested], capture_output=True, timeout=10)
        assert not result.stderr
        assert (result.returncode == 0) == (damage is None)
        assert json.loads(result.stdout)["status"] == ("VERIFIED" if damage is None else "REFUSED")
        assert before == {str(path): path.lstat().st_mode for path in [root, *root.rglob("*")]}
    finally:
        if acl_path is not None:
            subprocess.run(["/bin/chmod", "-N", str(acl_path)], check=True, capture_output=True)


def test_ordinary_manifest_preflight_reads_only_stdin_metadata_and_does_not_verify_a_missing_image(production_verifier, fixture):
    root, _, _, path = fixture
    data = path.read_bytes()
    shutil.rmtree(root)
    result = subprocess.run([str(production_verifier), "--inspect-manifest"], input=data, capture_output=True, timeout=10)
    assert result.returncode == 0 and not result.stderr
    value = json.loads(result.stdout)
    assert value == {"schema": 1, "status": "INSPECTED", "manifest_sha256": hashlib.sha256(data).hexdigest(),
                     "files": 3, "directories": 5, "aliases": 2}
    assert not root.exists()


@pytest.mark.parametrize("data,reason", [(b"{}", "invalid_installer_payload_manifest"),
                                      (b"x" * (16 * 1024 * 1024 + 1), "installer_payload_limit")],
                         ids=["invalid-json", "oversized"])
def test_manifest_stdin_preflight_is_bounded_and_refuses_invalid_input(production_verifier, data, reason):
    result = subprocess.run([str(production_verifier), "--inspect-manifest"], input=data, capture_output=True, timeout=10)
    assert result.returncode == 78 and not result.stderr
    assert json.loads(result.stdout) == {"schema": 1, "status": "FAILED", "reason": reason}


@pytest.mark.parametrize('placement', ['opaque-branches', 'unlisted', 'nested-private-name', 'application-private-name'])
def test_public_image_recheck_excludes_only_fixed_top_level_private_branches(native_verifier, fixture, tmp_path, placement):
    root, support, app, manifest = fixture
    outside = tmp_path / 'opaque-synthetic-data'
    outside.write_bytes(b'synthetic private fixture; not an account')
    (support / 'vault').symlink_to(outside)
    (support / 'broker').mkdir(mode=0o700)
    (support / 'broker/opaque').write_bytes(b'opaque synthetic fixture')
    if placement == 'unlisted':
        (support / 'unknown').write_bytes(b'unlisted')
    elif placement == 'nested-private-name':
        (support / 'bin/vault').write_bytes(b'unlisted')
    elif placement == 'application-private-name':
        (app / 'vault').write_bytes(b'unlisted')
    assert verify(native_verifier, fixture)['status'] == 'REFUSED'
    result = subprocess.run([str(native_verifier), '--public-image', str(manifest), str(root)], capture_output=True, timeout=10)
    value = json.loads(result.stdout)
    assert not result.stderr
    assert (result.returncode == 0) == (placement == 'opaque-branches')
    assert value['status'] == ('VERIFIED' if placement == 'opaque-branches' else 'REFUSED')
    assert outside.read_bytes() == b'synthetic private fixture; not an account'


@pytest.fixture(scope='session')
def source_handoff(tmp_path_factory):
    path = tmp_path_factory.mktemp('ordinary-source-handoff')
    launcher, interpreter = path / 'launcher', path / 'interpreter'
    common = ['xcrun', 'swiftc', '-O', '-parse-as-library', '-warnings-as-errors', '-framework', 'Foundation', '-framework', 'CryptoKit']
    subprocess.run([*common, str(ROOT / 'macos/InstallerPayload.swift'), str(ROOT / 'macos/Tests/InstallerSourceLauncherChecks.swift'), '-o', str(launcher)],
                   check=True, capture_output=True, timeout=120)
    subprocess.run([*common, '-D', 'ACCOUNT_ACCESS_SOURCE_HANDOFF_USER_FIXTURE', str(ROOT / 'macos/Tests/InstallerSourceHandoff.swift'), '-o', str(interpreter)],
                   check=True, capture_output=True, timeout=120)
    return launcher, interpreter


@pytest.mark.parametrize('stdin', ['open-stdin', 'closed-stdin'])
def test_real_native_source_replacement_passes_only_public_handles_and_clean_environment(source_handoff, tmp_path, stdin):
    launcher, interpreter = source_handoff
    source = tmp_path / 'public-source'
    source.mkdir()
    manifest = tmp_path / 'public-metadata.json'
    manifest.write_bytes(b'{"fixture":"public metadata only"}')
    result = subprocess.run([str(launcher), str(interpreter), str(source), str(manifest), stdin], capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout.decode(errors='replace')
    value = json.loads(result.stdout)
    assert value['status'] == 'PASSED' and all(v is True for v in value['checks'].values())
    assert value['actual_python_or_provisioning_executed'] is False and value['private_signins'] == 0
