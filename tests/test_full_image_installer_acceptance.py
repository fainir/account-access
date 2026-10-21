"""Pure installer-input and refusal contracts; no downloads, root or Installer."""

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def module(name, filename):
    source = Path(__file__).resolve().parents[1] / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, source)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


downloader = module("full_image_inputs", "download_full_image_installer_inputs.py")
probe = module("full_image_installer_probe", "mac_full_image_installer_probe.py")
PLAN = "5b6fbf102ab1e4133bce915f6af787301cb92a4d4b16efa55ebd1c47c7db9065"
COMPONENT_SOURCE = "213509c6bd9ff40131bd71dcb1a2967e96cd76a3"
ASSETS = {
    "base.pkg", "base-manifest.json", "base-source.tar.gz", "component.pkg",
    "component-review.json", "component-source.tar.gz", "full.pkg", "full-review.json",
    "full-scripts-inventory.json", "full-source.tar.gz",
}
CI = {
    "GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "fainir/account-access",
    "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40,
}


def contract():
    """Real fixed public pins, fictional unpublished metadata for pure validation only.

    Passing this fixture is not asset availability or Installer acceptance. No
    actual release/asset identifiers are required for the unpublished artifacts.
    """
    base = {"id": 418292574, "tag": "qa-fbd2a73-build76-component-base",
            "source": "fbd2a733b60acde68e82fe796cb7abd971d5d625"}
    component = {"id": 100, "tag": "qa-fictional-component", "source": COMPONENT_SOURCE}
    full = {"id": 101, "tag": "qa-fictional-full", "source": "b" * 40}

    def row(identifier, checksum, size, release):
        return {"id": identifier, "sha256": checksum, "bytes": size,
                "release": copy.deepcopy(release)}

    return {
        "schema": 1, "status": "FROZEN_REVIEWED_ASSETS", "repository": "fainir/account-access",
        "component_source": COMPONENT_SOURCE,
        "target_source": "5ba276b1369edf29eab59d3670b122975b350cca", "plan_sha256": PLAN,
        "assets": {
            "base.pkg": row(659061910,
                "e525233e74ee942a53c389babac57eee6cad25b79ea178ff9a6384b0a5c5567c", 289451807, base),
            "base-manifest.json": row(659061912,
                "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8", 4989248, base),
            "base-source.tar.gz": row(659061965,
                "4b239336a11d702932c376fb7448f9dda6a1eda87c4fe678cadbf537ba137a37", 219113811, base),
            "component.pkg": row(10001,
                "674c5df7866477e48811d002128370aaec6385aeb0565137036880de4c626bef", 3457184, component),
            "component-review.json": row(10002, "c" * 64, 128, component),
            "component-source.tar.gz": row(10003, "d" * 64, 256, component),
            "full.pkg": row(10004, "e" * 64, 512, full),
            "full-review.json": row(10005, "f" * 64, 128, full),
            "full-scripts-inventory.json": row(10006, "1" * 64, 128, full),
            "full-source.tar.gz": row(10007, "2" * 64, 256, full),
        },
    }


@pytest.mark.parametrize("pending", ["status", "missing-asset-id"])
def test_pending_or_unpublished_candidate_cannot_validate(pending):
    value = contract()
    assert downloader.validate(value) == value
    if pending == "status":
        value["status"] = "PENDING_EXACT_BUILT_PACKAGE_AND_RELEASE_ASSETS"
    else:
        value["assets"]["full.pkg"]["id"] = None
    with pytest.raises(ValueError, match="^full_image_installer_input_contract_failed$"):
        downloader.validate(value)


@pytest.mark.parametrize("raw", [
    b'{"status":"first","status":"second"}',
    b'{"assets":{"full.pkg":{"id":1,"id":2}}}',
])
def test_duplicate_contract_identity_refused(raw):
    with pytest.raises(ValueError, match="^full_image_installer_input_contract_failed$"):
        downloader.decode(raw)


def test_exact_asset_names_accept_real_names_and_reject_escapes():
    assert probe.ASSET_FILES == downloader.FILES == ASSETS
    assert all(probe.asset_name(name) for name in ASSETS)
    for name in (r"base\.pkg", r"full-source.tar\.gz", "../base.pkg", "/base.pkg", "other.pkg",
                 "base.pkg/", "base.PKG", "base.pkg\n", "base/pkg", None, 5):
        assert not probe.asset_name(name)


@pytest.mark.parametrize("path,value", [
    (("plan_sha256",), "8eb5193656b08e105476e0524890e206db2c23d62bc805ed62d1c94623fc06fa"),
    (("schema",), True),
    (("repository",), "other/repository"),
    (("component_source",), "a" * 40),
    (("target_source",), "a" * 40),
    (("assets", "full-source.tar.gz"), None),
    (("assets", "full.pkg", "id"), 10005),
    (("assets", "full.pkg", "id"), True),
    (("assets", "full.pkg", "bytes"), True),
    (("assets", "full.pkg", "bytes"), 1024**3 + 1),
    (("assets", "full.pkg", "sha256"), "E" * 64),
    (("assets", "full.pkg", "release", "tag"), "../qa-other"),
    (("assets", "full.pkg", "release", "id"), 102),
    (("assets", "base.pkg", "sha256"), "a" * 64),
    (("assets", "base.pkg", "release", "id"), 102),
    (("assets", "component.pkg", "sha256"), "a" * 64),
    (("assets", "component.pkg", "bytes"), 3457185),
    (("assets", "component-review.json", "release", "source"), "a" * 40),
])
def test_genuine_plan_contract_accepts_then_refuses_single_identity_mutation(path, value):
    baseline = contract()
    original = copy.deepcopy(baseline)
    assert baseline["plan_sha256"] == probe.PLAN_SHA == PLAN
    assert downloader.validate(baseline) is baseline
    assert baseline == original
    wrong = copy.deepcopy(baseline)
    target = wrong
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    with pytest.raises(ValueError, match="^full_image_installer_input_contract_failed$"):
        downloader.validate(wrong)


def test_direct_helper_stage_excludes_temporary_path_aliases():
    assert probe.canonical_stage_name(Path("/private/tmp/account-access-full-image-acceptance-fixed_1"))
    for path in ("/tmp/account-access-full-image-acceptance-fixed_1",
                 "/var/tmp/account-access-full-image-acceptance-fixed_1", "/private/tmp/other",
                 "/private/tmp/account-access-full-image-acceptance-",
                 "/private/tmp/account-access-full-image-acceptance-x/child"):
        assert not probe.canonical_stage_name(Path(path))


@pytest.mark.parametrize("field,value", [
    ("uid", 501), ("euid", 501), ("platform", "linux"), ("machine", "x86_64"),
    ("GITHUB_ACTIONS", "false"), ("CI", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "X64"), ("GITHUB_REPOSITORY", "other/repo"),
    ("GITHUB_RUN_ID", "../1"), ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "0"),
    ("GITHUB_SHA", "A" * 40),
])
def test_root_and_host_context_refused_before_filesystem_or_process(monkeypatch, field, value):
    def forbidden(*_args, **_kwargs):
        pytest.fail("refused context touched filesystem, loaded source or launched a process")

    # These UID return values only exercise the pure predicate; no process becomes root.
    with monkeypatch.context() as guard:
        guard.setattr(probe.sys, "platform", "darwin")
        guard.setattr(probe.platform, "machine", lambda: "arm64")
        guard.setattr(probe.os, "getuid", lambda: 0)
        guard.setattr(probe.os, "geteuid", lambda: 0)
        for key, item in CI.items():
            guard.setenv(key, item)
        assert probe.guard() is None
        if field in ("uid", "euid"):
            guard.setattr(probe.os, "getuid" if field == "uid" else "geteuid", lambda: value)
        elif field == "platform":
            guard.setattr(probe.sys, "platform", value)
        elif field == "machine":
            guard.setattr(probe.platform, "machine", lambda: value)
        else:
            guard.setenv(field, value)
        for name in ("read_bytes", "open", "mkdir"):
            guard.setattr(Path, name, forbidden)
        for name in ("open", "stat", "lstat"):
            guard.setattr(probe.os, name, forbidden)
        guard.setattr(probe.runpy, "run_path", forbidden)
        for name in ("Popen", "run", "check_output"):
            guard.setattr(probe.subprocess, name, forbidden)
        with pytest.raises(ValueError, match="^full_image_installer_acceptance_failed$"):
            probe.run(SimpleNamespace())


def test_policy_expectation_changes_only_actual_two_fields_and_preserves_input(monkeypatch):
    peers = {"owner": {"hashes": ["b" * 40], "team": "WBULD6N4NQ",
                       "identifier": "com.fainir.accountaccess"},
             "broker": {"hashes": ["c" * 40]}, "bootstrap": {"hashes": ["d" * 40]}}
    before = {"install": {"payload_fingerprint": "old", "broker_uid": 470},
              "host": {"owner_hashes": ["a" * 40], "bootstrap_hashes": ["d" * 40], "owner_uid": 501},
              "owner": {"server_hashes": ["c" * 40], "owner_uid": 501}}
    original = copy.deepcopy(before)
    monkeypatch.setattr(probe, "h", SimpleNamespace(BASE=Path("/fixture/public"), LABEL="fixture.label"),
                        raising=False)
    expected = probe.expected_policies(before, peers)
    assert before == original
    assert expected["host"]["owner_hashes"] == peers["owner"]["hashes"]
    fingerprint = expected["install"]["payload_fingerprint"]
    assert len(fingerprint) == 64 and all(char in "0123456789abcdef" for char in fingerprint)
    expected["host"]["owner_hashes"] = original["host"]["owner_hashes"]
    expected["install"]["payload_fingerprint"] = original["install"]["payload_fingerprint"]
    assert expected == original
