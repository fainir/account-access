"""Ordinary pure fresh-installer contracts; no SDK, download, root or Installer."""

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


def module(name, filename):
    source = Path(__file__).resolve().parents[1] / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, source)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


inputs = module("fresh_image_inputs", "download_fresh_image_installer_inputs.py")
probe = module("fresh_image_probe", "mac_fresh_image_installer_probe.py")
CI = {"GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "fainir/account-access",
    "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40}


def broker_job():
    return SimpleNamespace(returncode=0, stderr=b"", stdout=(
        "system/com.fainir.accountaccess.broker = {\n"
        "\tpath = /Library/LaunchDaemons/com.fainir.accountaccess.broker.plist\n"
        "\tstate = running\n"
        "\tprogram = /Library/Application Support/Account Access/bin/AccountAccess-broker\n"
        "\tpid = 12345\n"
        "\tendpoints = {\n\t\tstate = waiting\n\t\tpid = 999\n\t}\n}\n").encode())


def test_liveness_requires_the_fixed_running_job_not_nested_fields():
    assert probe.running_broker_pid(broker_job()) == 12345


@pytest.mark.parametrize("before,after", [
    ("system/com.fainir.accountaccess.broker", "system/com.apple.distnoted"),
    ("\tstate = running", "\tstate = waiting"),
    ("\tstate = running", "\t\tstate = running"),
    ("\tstate = running", "\tstate = running\n\tstate = running"),
    ("bin/AccountAccess-broker", "bin/AccountAccess-bootstrap"),
    ("\tprogram =", "\t\tprogram ="),
    ("broker.plist", "other.plist"),
    ("\tpid = 12345", "\t\tpid = 12345"),
    ("\tpid = 12345", "\tpid = 0"),
    ("\tpid = 12345", "\tpid = 1"),
    ("\tpid = 12345", "\tpid = -12"),
    ("\tpid = 12345", "\tpid = 2147483648"),
    ("\tpid = 12345", "\tpid = 12345\n\tpid = 54321"),
])
def test_liveness_refuses_wrong_missing_or_ambiguous_job_fields(before, after):
    result = broker_job()
    result.stdout = result.stdout.replace(before.encode(), after.encode())
    with pytest.raises(ValueError):
        probe.running_broker_pid(result)


@pytest.mark.parametrize("field,value", [
    ("returncode", 113), ("returncode", False), ("stderr", b"unavailable"),
    ("stdout", b""), ("stdout", b"x" * 16385), ("stdout", b"\xff"),
])
def test_liveness_refuses_failed_or_unbounded_observations(field, value):
    result = broker_job()
    setattr(result, field, value)
    with pytest.raises(ValueError):
        probe.running_broker_pid(result)


def contract():
    """Fictional future fresh-asset IDs for pure validation, never availability."""
    source = inputs.PACKAGING_SOURCE
    release = {"id": 100, "tag": "qa-fictional-fresh", "source": source}
    assets = {name: {"id": 10000 + index, "sha256": "c" * 64, "bytes": 100,
                     "release": copy.deepcopy(release)} for index, name in enumerate(sorted(inputs.FILES))}
    assets["full81-source.tar.gz"] = copy.deepcopy(inputs.FULL81_SOURCE)
    assets["fresh-manifest.json"]["sha256"] = inputs.MANIFEST
    return {"schema": 1, "status": "FROZEN_REVIEWED_ASSETS", "repository": inputs.REPOSITORY,
        "target_source": inputs.APP_SOURCE, "packaging_source": source, "target_manifest_sha256": inputs.MANIFEST,
        "installer_verifier_sha256": inputs.VERIFIER, "assets": assets}


def review():
    value = contract()
    return {"schema": 1, "status": "BUILT_NOT_INSTALLED_NOT_INSTALL_QUALIFIED",
        "package_sha256": value["assets"]["fresh.pkg"]["sha256"],
        "package_bytes": value["assets"]["fresh.pkg"]["bytes"],
        "target_manifest_sha256": inputs.MANIFEST, "target_source": inputs.APP_SOURCE,
        "packaging_source": value["packaging_source"], "installer_verifier_sha256": inputs.VERIFIER,
        "expanded_inventory_sha256": value["assets"]["fresh-expanded-inventory.json"]["sha256"],
        "actual_Installer_qualified": False, "production_ready": False}


def test_positive_contract_and_review_preserve_inputs_and_reuse_exact_public_source():
    value, report = contract(), review()
    before = copy.deepcopy((value, report))
    assert inputs.validate(value) is value
    assert probe.validate_review(report, value) is report
    assert (value, report) == before
    assert value["assets"]["full81-source.tar.gz"] == inputs.FULL81_SOURCE
    assert probe.MANIFEST_SHA == inputs.MANIFEST and probe.VERIFIER_SHA == inputs.VERIFIER
    assert not any(name.startswith(("base", "component")) for name in inputs.FILES)


def current_contract_and_review():
    value, report = contract(), review()
    manifest = "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da"
    app = "d30fda732c589b9ac4dc339a7237ad8ba00d0016"
    packaging = "47eac17c811ca27a12660d30f94ec955ad09df70"
    for item in (value, report):
        item.update(target_manifest_sha256=manifest, target_source=app, packaging_source=packaging)
    del value["assets"]["full81-source.tar.gz"]
    for asset in value["assets"].values():
        asset["release"]["source"] = packaging
    value["assets"]["fresh-manifest.json"]["sha256"] = manifest
    value["assets"]["full84-source.tar.gz"] = copy.deepcopy(inputs.FULL84_SOURCE)
    return value, report


def test_current_image_is_bound_without_mutating_legacy_profile():
    value, report = current_contract_and_review()
    assert inputs.validate(value, 84) is value
    assert probe.validate_review(report, value, 84) is report
    for wrong in (80, 85, True, "84", 84.0):
        with pytest.raises(ValueError):
            inputs.validate(value, wrong)
        with pytest.raises(ValueError):
            probe.validate_review(report, value, wrong)
    with pytest.raises(ValueError):
        inputs.validate(contract(), 84)
    with pytest.raises(ValueError):
        probe.validate_review(review(), contract(), 84)
    assert inputs.validate(contract()) and probe.validate_review(review(), contract())


@pytest.mark.parametrize("changed", ["source", "manifest", "packager", "archive", "asset-source"])
def test_current_contract_rejects_mixed_image_or_source(changed):
    value, _ = current_contract_and_review()
    if changed == "source":
        value["target_source"] = inputs.APP_SOURCE
    elif changed == "manifest":
        value["target_manifest_sha256"] = inputs.MANIFEST
    elif changed == "packager":
        value["packaging_source"] = inputs.PACKAGING_SOURCE
    elif changed == "archive":
        value["assets"]["full84-source.tar.gz"] = copy.deepcopy(inputs.FULL81_SOURCE)
    else:
        value["assets"]["fresh.pkg"]["release"]["source"] = inputs.PACKAGING_SOURCE
    with pytest.raises(ValueError):
        inputs.validate(value, 84)


def test_pinned_transfer_and_native_helper_match_current_reviewed_source():
    root = Path(__file__).resolve().parents[1]
    assert inputs.digest((root / inputs.TRANSFER_SOURCE).read_bytes()) == inputs.TRANSFER_SHA
    assert probe.digest((root / probe.HELPER).read_bytes()) == probe.HELPER_SHA


@pytest.mark.parametrize("cohort", [80, 84])
def test_committed_asset_contract_matches_only_its_reviewed_cohort(cohort):
    root = Path(__file__).resolve().parents[1]
    value = inputs.decode((root / inputs.cohort_pins(cohort)[3]).read_bytes())
    assert inputs.validate(value, cohort) is value
    with pytest.raises(ValueError):
        inputs.validate(value, 84 if cohort == 80 else 80)


def test_fresh_receipts_are_bound_to_the_selected_image(monkeypatch, tmp_path):
    import json
    manifest = probe.cohort_pins(84)[0]
    values = {"intent.json": {"managed_by": "account-access-public-image-install-v1", "schema": 1,
        "manifest_sha256": manifest, "owner_uid": 501}, "complete.json": {
        "manifest_sha256": manifest, "owner_uid": 501, "status": "REGISTERED"}}
    monkeypatch.setattr(probe, "h", SimpleNamespace(JOURNAL=tmp_path,
        read_file=lambda path, **_kwargs: json.dumps(values[path.name]).encode(),
        fixed_records=lambda: {"fixture": "unchanged"}), raising=False)
    assert probe.original_receipts(501, manifest_sha=manifest) == {"fixture": "unchanged"}
    with pytest.raises(ValueError):
        probe.original_receipts(501)


@pytest.mark.parametrize("path,value", [
    (("schema",), True), (("status",), "PENDING_ASSETS"), (("repository",), "other/repo"),
    (("target_source",), "1" * 40), (("target_manifest_sha256",), "2" * 64),
    (("packaging_source",), None), (("packaging_source",), "b" * 40),
    (("installer_verifier_sha256",), "3" * 64),
    (("assets", "fresh.pkg", "id"), None), (("assets", "fresh.pkg", "id"), True),
    (("assets", "fresh.pkg", "bytes"), True), (("assets", "fresh.pkg", "bytes"), 1024**3 + 1),
    (("assets", "fresh.pkg", "sha256"), "C" * 64),
    (("assets", "fresh.pkg", "release", "source"), "1" * 40),
    (("assets", "fresh.pkg", "release", "id"), 101),
    (("assets", "fresh.pkg", "release", "tag"), "../fresh"),
    (("assets", "fresh-manifest.json", "sha256"), "4" * 64),
    (("assets", "full81-source.tar.gz", "id"), 663422303),
    (("assets", "full81-source.tar.gz", "sha256"), "5" * 64),
])
def test_pending_or_changed_cohort_asset_or_source_refused(path, value):
    candidate = contract()
    current = candidate
    for name in path[:-1]:
        current = current[name]
    current[path[-1]] = value
    with pytest.raises(ValueError, match="^fresh_image_installer_input_contract_failed$"):
        inputs.validate(candidate)


def test_extra_escape_missing_and_duplicate_asset_identity_refused():
    for change in ["escape", "missing", "duplicate"]:
        value = contract()
        if change == "escape":
            value["assets"]["../fresh.pkg"] = value["assets"].pop("fresh.pkg")
        elif change == "missing":
            del value["assets"]["packaging-source.tar.gz"]
        else:
            value["assets"]["fresh.pkg"]["id"] = value["assets"]["fresh-review.json"]["id"]
        with pytest.raises(ValueError, match="^fresh_image_installer_input_contract_failed$"):
            inputs.validate(value)
    with pytest.raises(ValueError, match="^fresh_image_installer_input_contract_failed$"):
        inputs.decode(b'{"schema":1,"schema":1}')


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("status", "PASSED"), ("package_sha256", "1" * 64), ("package_bytes", True),
    ("target_source", "2" * 40), ("packaging_source", "3" * 40),
    ("target_manifest_sha256", "4" * 64), ("installer_verifier_sha256", "5" * 64),
    ("expanded_inventory_sha256", "6" * 64), ("actual_Installer_qualified", 0), ("production_ready", True),
])
def test_fresh_review_cannot_relabel_artifact_or_claim_readiness(field, value):
    candidate = review()
    candidate[field] = value
    with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
        probe.validate_review(candidate, contract())


@pytest.mark.parametrize("field,value", [
    ("uid", 501), ("euid", 501), ("platform", "linux"), ("machine", "x86_64"),
    ("GITHUB_ACTIONS", "false"), ("CI", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "X64"), ("GITHUB_REPOSITORY", "other/repo"),
    ("GITHUB_RUN_ID", "../1"), ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_SHA", "A" * 40),
])
def test_owner_mac_or_invalid_host_refuses_before_paths_imports_or_process(monkeypatch, field, value):
    def forbidden(*_args, **_kwargs):
        pytest.fail("refused host accessed a path, imported helpers or invoked a process")

    with monkeypatch.context() as patch:
        patch.setattr(probe.sys, "platform", "darwin")
        patch.setattr(probe.platform, "machine", lambda: "arm64")
        patch.setattr(probe.os, "getuid", lambda: 0)
        patch.setattr(probe.os, "geteuid", lambda: 0)
        for key, item in CI.items():
            patch.setenv(key, item)
        assert probe.guard() is None
        if field in {"uid", "euid"}:
            patch.setattr(probe.os, "getuid" if field == "uid" else "geteuid", lambda: value)
        elif field == "platform":
            patch.setattr(probe.sys, "platform", value)
        elif field == "machine":
            patch.setattr(probe.platform, "machine", lambda: value)
        else:
            patch.setenv(field, value)
        for name in ("read_bytes", "open", "mkdir", "lstat"):
            patch.setattr(Path, name, forbidden)
        patch.setattr(probe.os, "open", forbidden)
        patch.setattr(probe.runpy, "run_path", forbidden)
        with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
            probe.run(SimpleNamespace())


def test_absent_contract_cannot_load_transfer_source_or_reach_network(monkeypatch, tmp_path):
    monkeypatch.setattr(inputs.os, "getuid", lambda: 501)
    monkeypatch.setattr(inputs.os, "geteuid", lambda: 501)
    for key, value in CI.items():
        monkeypatch.setenv(key, value)
    missing, output = tmp_path / "absent-contract.json", tmp_path / "output"
    monkeypatch.setattr(inputs, "subprocess", SimpleNamespace(
        check_output=lambda *_args, **_kwargs: pytest.fail("missing contract invoked Git/network")))
    monkeypatch.setattr(inputs.runpy, "run_path", lambda *_args: pytest.fail("missing contract loaded transfer"))
    monkeypatch.setattr(inputs, "argparse", SimpleNamespace(ArgumentParser=lambda **_kwargs: SimpleNamespace(
        add_argument=lambda *_args, **_kwargs: None,
        parse_args=lambda: SimpleNamespace(contract=missing, output=output))))
    with pytest.raises(FileNotFoundError):
        inputs.main()
    assert not output.exists()


PACKAGE_INFO = b'''<pkg-info identifier="com.fainir.accountaccess.system" version="0.8.0" auth="root">
<payload numberOfFiles="0" installKBytes="0"/><scripts>
<preinstall file="./preinstall"/><postinstall file="./postinstall"/></scripts></pkg-info>'''


@pytest.mark.parametrize("before,after", [
    (b'numberOfFiles="0"', b'numberOfFiles="1"'),
    (b'version="0.8.0"', b'version="0.9.0"'), (b'auth="root"', b'auth="none"'),
    (b'file="./postinstall"', b'file="../postinstall"'),
    (b'<preinstall file="./preinstall"/>', b''),
])
def test_product_envelope_positive_then_refuses_payload_or_wrong_scripts(before, after):
    assert probe.validate_package_info(PACKAGE_INFO) is None
    with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
        probe.validate_package_info(PACKAGE_INFO.replace(before, after))


def packaged_image():
    support, app = "/Library/Application Support/Account Access", "/Applications/Account Access.app"
    manifest = {"roots": {support: {"": {"kind": "directory", "mode": 0o755},
        "file": {"kind": "file", "mode": 0o644, "size": 3, "sha256": "a" * 64}},
        app: {"": {"kind": "symlink", "target": support + "/owner.app"}}}}
    prefix = "payload.pkg/Scripts/PublicImage"
    rows = {prefix + suffix: {"kind": "directory", "mode": 0o755}
            for suffix in ["", "/Library", "/Library/Application Support", "/Applications", support]}
    rows[prefix + support + "/file"] = {"kind": "file", "mode": 0o644, "bytes": 3, "sha256": "a" * 64}
    rows[prefix + app] = {"kind": "symlink", "mode": 0o755, "target": support + "/owner.app"}
    return manifest, rows


@pytest.mark.parametrize("mutation", ["extra", "content", "mode", "alias", "root"])
def test_package_image_matches_manifest_and_refuses_extra_or_replaced_material(mutation):
    manifest, rows = packaged_image()
    assert probe.validate_packaged_image(manifest, rows) is None
    prefix = "payload.pkg/Scripts/PublicImage"
    if mutation == "extra":
        rows[prefix + "/unexpected"] = {"kind": "file", "bytes": 1, "sha256": "b" * 64, "mode": 0o644}
    elif mutation == "content":
        rows[prefix + "/Library/Application Support/Account Access/file"]["sha256"] = "b" * 64
    elif mutation == "mode":
        rows[prefix + "/Library/Application Support/Account Access/file"]["mode"] = 0o666
    elif mutation == "alias":
        rows[prefix + "/Applications/Account Access.app"]["target"] = "/other/app"
    else:
        manifest["roots"]["/other/root"] = manifest["roots"].pop("/Applications/Account Access.app")
    with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
        probe.validate_packaged_image(manifest, rows)


def test_expansion_mismatch_refuses_before_reading_scripts(monkeypatch):
    monkeypatch.setattr(probe, "inventory", lambda _path: {"": {"kind": "directory", "mode": 0o755}})
    monkeypatch.setattr(Path, "iterdir", lambda _path: pytest.fail("unreviewed expansion inspected scripts"))
    with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
        probe.validate_expansion(Path("/fictional/expanded"), {"": {"kind": "directory", "mode": 0o700}}, {})


def test_actual_productbuild_fragment_reference_and_bundle_metadata_are_supported():
    # Captured from the unchanged c607e267 fresh package produced by productbuild.
    raw = (Path(__file__).parent / "fixtures/fresh-product-distribution.xml").read_bytes()
    assert probe.validate_distribution(raw) is None


@pytest.mark.parametrize("mutation", ["remote", "other-component", "second-payload", "other-id", "architecture", "user-domain"])
def test_product_distribution_refuses_another_payload_or_installation_scope(mutation):
    raw = (Path(__file__).parent / "fixtures/fresh-product-distribution.xml").read_bytes()
    if mutation == "remote":
        raw = raw.replace(b"#payload.pkg", b"https://example.test/payload.pkg")
    elif mutation == "other-component":
        raw = raw.replace(b"#payload.pkg", b"#other.pkg")
    elif mutation == "second-payload":
        raw = raw.replace(b"<bundle-version/>", b"#other.pkg")
    elif mutation == "other-id":
        raw = raw.replace(b"com.fainir.accountaccess.system", b"com.other.package")
    elif mutation == "architecture":
        raw = raw.replace(b'hostArchitectures="arm64"', b'hostArchitectures="x86_64"')
    else:
        raw = raw.replace(b'enable_currentUserHome="false"', b'enable_currentUserHome="true"')
    with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
        probe.validate_distribution(raw)


def test_script_source_literals_are_read_without_importing_or_executing():
    raw = b'raise RuntimeError("must not execute")\nPREINSTALL = "first"\nPOSTINSTALL = "second"\n'
    assert probe.install_script_bodies(raw) == {"preinstall": b"first", "postinstall": b"second"}
    for wrong in [raw + b'PREINSTALL = "third"\n', raw.replace(b'"second"', b'function()')]:
        with pytest.raises(ValueError, match="^fresh_image_installer_acceptance_failed$"):
            probe.install_script_bodies(wrong)


def test_two_normal_gui_quits_keep_separate_exclusive_logs_and_failure_details(monkeypatch):
    writes, report = {}, {"logs": {}}

    def write(name, body):
        assert name not in writes
        writes[name] = body

    def close(_console, *, report, output):
        output.write("fresh-gui-initial-presence.log", b"fictional presence")
        report["logs"]["fresh-gui-initial-presence.log"] = "a" * 64
        report["normal_quit_requested"] = True

    monkeypatch.setattr(probe, "h", SimpleNamespace(close_fresh_gui=close), raising=False)
    for phase in ["fresh", "reapplied"]:
        probe.close_gui(501, phase, report, SimpleNamespace(write=write))
    assert set(writes) == set(report["logs"]) == {
        "gui-fresh-fresh-gui-initial-presence.log", "gui-reapplied-fresh-gui-initial-presence.log"}
    assert all(report["gui"][phase]["normal_quit_requested"] for phase in ["fresh", "reapplied"])


def test_public_identity_snapshot_preserves_observed_gid_and_detects_inode_change(monkeypatch):
    state = {"inode": 200, "gid": 80}
    checked = []

    def info(path):
        assert str(path) == "/fictional-public"
        return SimpleNamespace(st_dev=4, st_ino=state["inode"], st_uid=0, st_gid=state["gid"],
            st_mode=probe.stat.S_IFDIR | 0o755)

    manifest = {"roots": {"/fictional-public": {"": {"kind": "directory", "mode": 0o755}}}}
    monkeypatch.setattr(Path, "lstat", info)
    monkeypatch.setattr(probe, "h", SimpleNamespace(
        verify_image=lambda value: checked.append(value),
        stamp=lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode)), raising=False)
    first = probe.public_snapshot(manifest)
    assert first["/fictional-public"]["gid"] == 80 and first == probe.public_snapshot(manifest)
    state["inode"] = 201
    assert probe.public_snapshot(manifest) != first
    state["inode"], state["gid"] = 200, 20
    assert probe.public_snapshot(manifest) != first
    assert checked == [manifest] * 4


@pytest.mark.parametrize("cohort", [80, 84])
def test_workflow_has_one_fresh_host_and_only_committed_contract_trigger(cohort):
    root = Path(__file__).resolve().parents[1]
    filename = "mac-fresh-image-installer-review.yml" if cohort == 80 else "mac-fresh-image84-installer-review.yml"
    workflow = yaml.safe_load((root / ".github/workflows" / filename).read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert trigger == {"push": {"branches": ["codex/full-image-update"], "paths": [inputs.cohort_pins(cohort)[3]]}}
    actual = workflow["jobs"]["actual-installer"]
    assert actual["runs-on"] == "macos-15" and "strategy" not in actual
    shell = next(step["run"] for step in actual["steps"] if "run" in step)
    assert "env -i" in shell and "mac_fresh_image_installer_probe.py" in shell and "GH_TOKEN" not in shell
    assert "base.pkg" not in shell and "component.pkg" not in shell
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "uses" in step:
                assert inputs.hex_value(step["uses"].split("@")[-1], 40)
            if cohort == 84 and "run" in step and "scripts/" in step["run"]:
                assert "--cohort 84" in step["run"]
