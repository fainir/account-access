"""Review the public-input/root-controller boundary without network or privilege."""

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pytest
import yaml


PATH = Path(__file__).parents[1] / ".github/workflows/mac-component-update-review.yml"
WORKFLOW = yaml.safe_load(PATH.read_text())
JOBS = WORKFLOW["jobs"]


def script(job, name):
    return next(step["run"] for step in JOBS[job]["steps"] if step.get("name") == name)


DOWNLOAD = script("download-public-inputs", "Authenticate and hash-check only public package inputs")
PREFLIGHT = script("actual-installer-review", "Verify transferred public bytes and the checked-out controller")
INSTALL = script("actual-installer-review", "Run actual Installer, verify fresh-app closure and component reapply in this disposable VM")


def python_body(value):
    return re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", value, re.DOTALL)[1]


def functions(*names):
    tree = ast.parse(python_body(DOWNLOAD))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(selected) == len(names)
    context = {"re": re, "json": json}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(PATH), "exec"), context)
    return context


def request():
    return {"AC_COMPONENT_SOURCE": "a" * 40, "AC_CANDIDATE_SHA256": "b" * 64,
            "AC_REVIEW_SHA256": "c" * 64, "AC_CANDIDATE_RELEASE_ID": "12",
            "AC_CANDIDATE_ASSET_ID": "34", "AC_REVIEW_ASSET_ID": "56"}


def test_push_runs_only_ordinary_contracts_and_actions_are_pinned():
    triggers = WORKFLOW.get("on", WORKFLOW.get(True))
    assert "workflow_dispatch" in triggers and "push" in triggers
    assert JOBS["ordinary-contracts"]["if"] == "github.event_name == 'push'"
    for name in ("download-public-inputs", "actual-installer-review"):
        assert JOBS[name]["if"] == "github.event_name == 'workflow_dispatch' && github.repository == 'fainir/account-access'"
    for job in JOBS.values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w-]+/[\w-]+@[a-f0-9]{40}", step["uses"])
    ordinary = "\n".join(step.get("run", "") for step in JOBS["ordinary-contracts"]["steps"])
    assert "test_component_update_review_workflow.py" in ordinary and "sudo" not in ordinary


def test_exact_candidate_source_contracts_run_on_every_push():
    # Native-only fixes still need this ninth source gate. A paths/branches
    # filter would leave a genuine frozen candidate without its required run.
    triggers = WORKFLOW.get("on", WORKFLOW.get(True))
    assert triggers["push"] is None


def test_only_linux_download_has_draft_visibility_and_mac_has_no_token():
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert JOBS["download-public-inputs"]["permissions"] == {"contents": "write"}
    assert JOBS["actual-installer-review"]["permissions"] == {"contents": "read"}
    mac = json.dumps(JOBS["actual-installer-review"])
    assert "GH_TOKEN" not in mac and "github.token" not in mac
    for name in ("download-public-inputs", "actual-installer-review"):
        checkout = JOBS[name]["steps"][0]
        assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False, "ref": "${{ github.sha }}"}


def test_actual_installer_uses_fixed_controller_and_probe_owned_report():
    assert 'sudo -n /usr/bin/env -i' in INSTALL
    assert '"$AC_COMPONENT_PYTHON" -I -B "$GITHUB_WORKSPACE/scripts/mac_component_update_installer_probe.py"' in INSTALL
    assert '--repository "$GITHUB_WORKSPACE"' in INSTALL
    assert '--report "/Library/Logs/AccountAccessComponentInstallerQA-${GITHUB_RUN_ID}/report.json"' in INSTALL
    assert "mkdir" not in INSTALL and "HOME=" not in INSTALL and "GH_TOKEN" not in INSTALL
    assert "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null" in INSTALL
    assert 'test ! -e \'/Library/Application Support/Account Access\'' in INSTALL
    upload = JOBS["actual-installer-review"]["steps"][-1]
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "/Library/Logs/AccountAccessComponentInstallerQA-${{ github.run_id }}"


def test_inline_python_and_install_shell_syntax():
    for value in (DOWNLOAD, PREFLIGHT):
        compile(python_body(value), str(PATH), "exec")
    subprocess.run(["/bin/sh", "-n"], input=INSTALL, text=True, check=True, capture_output=True)


def test_authentication_uses_only_fixed_gets_and_immutable_base_pins():
    assert "--hostname', 'github.com'" in DOWNLOAD
    assert not any(value in DOWNLOAD for value in ("'-X'", "'POST'", "'DELETE'", "'PATCH'", "browser_download_url"))
    assert "BASE_RELEASE = 418292574" in DOWNLOAD
    assert "659061965, '4b239336a11d702932c376fb7448f9dda6a1eda87c4fe678cadbf537ba137a37', 219113811" in DOWNLOAD
    assert "659061910, 'e525233e74ee942a53c389babac57eee6cad25b79ea178ff9a6384b0a5c5567c', 289451807" in DOWNLOAD
    assert "659061912, '5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8', 4989248" in DOWNLOAD
    assert "asset(base, *BASE_CORRESPONDING_SOURCE[:2]" in DOWNLOAD
    assert "source + ':' + name" in DOWNLOAD
    assert "controller_revision + ':scripts/mac_component_update_installer_probe.py'" in DOWNLOAD


@pytest.mark.parametrize("field,value", [
    ("AC_COMPONENT_SOURCE", "main"), ("AC_COMPONENT_SOURCE", "A" * 40),
    ("AC_CANDIDATE_SHA256", "b" * 63), ("AC_REVIEW_SHA256", "$(command)"),
    ("AC_CANDIDATE_RELEASE_ID", "0"), ("AC_CANDIDATE_ASSET_ID", "1/../2"),
    ("AC_REVIEW_ASSET_ID", "56\n"), ("AC_REVIEW_ASSET_ID", "34"),
])
def test_dispatch_inputs_refuse_unbounded_or_ambiguous_values(field, value):
    environment = request()
    environment[field] = value
    with pytest.raises(ValueError, match="component_review_input_contract_failed"):
        functions("require", "request_values")["request_values"](environment)


def test_dispatch_and_asset_positive_then_server_digest_required():
    namespace = functions("require", "request_values", "asset")
    assert namespace["request_values"](request()) == "a" * 40
    item = {"id": 34, "state": "uploaded", "digest": "sha256:" + "b" * 64, "size": 123}
    assert namespace["asset"]({"assets": [item]}, 34, "b" * 64, 123, 123) is item
    for replacement in ({"digest": None}, {"state": "new"}, {"size": True}, {"size": 124}):
        changed = dict(item, **replacement)
        with pytest.raises(ValueError):
            namespace["asset"]({"assets": [changed]}, 34, "b" * 64, 123, 123)
    with pytest.raises(ValueError):
        namespace["asset"]({"assets": [item, item]}, 34, "b" * 64, 123)


def test_revalidation_dispatch_is_all_or_none_and_uses_distinct_bound_assets():
    validate = functions("require", "request_values")["request_values"]
    extra = {"AC_ROOT_REVALIDATION_ASSET_ID": "78", "AC_ROOT_REVALIDATION_SHA256": "d" * 64,
             "AC_ROOT_REVALIDATION_REVIEW_ASSET_ID": "90", "AC_ROOT_REVALIDATION_REVIEW_SHA256": "e" * 64}
    assert validate({**request(), **extra}) == "a" * 40
    for key in extra:
        with pytest.raises(ValueError):
            validate({**request(), **extra, key: ""})
    for key, value in (("AC_ROOT_REVALIDATION_ASSET_ID", "34"), ("AC_ROOT_REVALIDATION_REVIEW_ASSET_ID", "78"),
                       ("AC_ROOT_REVALIDATION_SHA256", "D" * 64), ("AC_ROOT_REVALIDATION_REVIEW_SHA256", "invalid")):
        with pytest.raises(ValueError):
            validate({**request(), **extra, key: value})
    triggers = WORKFLOW.get("on", WORKFLOW.get(True))
    assert len(triggers["workflow_dispatch"]["inputs"]) <= 10


def test_duplicate_public_review_keys_are_refused():
    read = functions("require", "unique", "read_json")["read_json"]
    with pytest.raises(ValueError):
        read(b'{"status": false, "sta\\u0074us": true}')


def preflight_fixture(tmp_path, monkeypatch):
    folder = tmp_path / "account-access-component-input"
    folder.mkdir()
    for name in ("base.pkg", "base-manifest.json", "candidate.pkg", "review.json"):
        (folder / name).write_bytes(name.encode())
    probe = b"# trusted controller fixture\n"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/mac_component_update_installer_probe.py").write_bytes(probe)
    value = {"schema": 1, "controller_revision": "d" * 40, "component_source_commit": "a" * 40,
             "probe_sha256": hashlib.sha256(probe).hexdigest(),
             "files": {item.name: hashlib.sha256(item.read_bytes()).hexdigest() for item in folder.iterdir()}}
    (folder / "controller.json").write_text(json.dumps(value))
    environment = dict(os.environ, RUNNER_TEMP=str(tmp_path), AC_COMPONENT_SOURCE="a" * 40, GITHUB_SHA="d" * 40,
                       AC_CANDIDATE_SHA256=value["files"]["candidate.pkg"], AC_REVIEW_SHA256=value["files"]["review.json"])
    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.chdir(tmp_path)

    def git(args, **kwargs):
        if args == ["git", "rev-parse", "HEAD"]:
            return "d" * 40 + "\n"
        assert args == ["git", "show", "d" * 40 + ":scripts/mac_component_update_installer_probe.py"]
        return probe

    monkeypatch.setattr(subprocess, "check_output", git)
    return folder, value


def test_preflight_accepts_distinct_bound_component_and_controller(tmp_path, monkeypatch):
    preflight_fixture(tmp_path, monkeypatch)
    exec(compile(python_body(PREFLIGHT), str(PATH), "exec"), {})


def test_preflight_binds_optional_revalidation_files_and_rejects_partial_or_changed_bytes(tmp_path, monkeypatch):
    folder, value = preflight_fixture(tmp_path, monkeypatch)
    for name in ("root-revalidation.pkg", "root-revalidation-review.json"):
        raw = name.encode()
        (folder / name).write_bytes(raw)
        value["files"][name] = hashlib.sha256(raw).hexdigest()
    (folder / "controller.json").write_text(json.dumps(value))
    monkeypatch.setenv("AC_ROOT_REVALIDATION_SHA256", value["files"]["root-revalidation.pkg"])
    monkeypatch.setenv("AC_ROOT_REVALIDATION_REVIEW_SHA256", value["files"]["root-revalidation-review.json"])
    exec(compile(python_body(PREFLIGHT), str(PATH), "exec"), {})
    monkeypatch.setenv("AC_ROOT_REVALIDATION_REVIEW_SHA256", "")
    with pytest.raises(AssertionError):
        exec(compile(python_body(PREFLIGHT), str(PATH), "exec"), {})
    monkeypatch.setenv("AC_ROOT_REVALIDATION_REVIEW_SHA256", value["files"]["root-revalidation-review.json"])
    (folder / "root-revalidation.pkg").write_bytes(b"replacement")
    with pytest.raises(AssertionError):
        exec(compile(python_body(PREFLIGHT), str(PATH), "exec"), {})


@pytest.mark.parametrize("mutation", ["missing_file", "extra_mapping", "bad_hash", "wrong_controller", "link", "duplicate_key"])
def test_preflight_refuses_ambiguous_transferred_input(tmp_path, monkeypatch, mutation):
    folder, value = preflight_fixture(tmp_path, monkeypatch)
    value = copy.deepcopy(value)
    if mutation == "missing_file":
        (folder / "base.pkg").unlink()
    elif mutation == "extra_mapping":
        value["files"]["../outside"] = "b" * 64
    elif mutation == "bad_hash":
        (folder / "candidate.pkg").write_bytes(b"replacement")
    elif mutation == "wrong_controller":
        value["controller_revision"] = "a" * 40
    elif mutation == "link":
        target = tmp_path / "outside"
        target.write_bytes((folder / "review.json").read_bytes())
        (folder / "review.json").unlink()
        (folder / "review.json").symlink_to(target)
    raw = json.dumps(value)
    if mutation == "duplicate_key":
        raw = '{"schema": 2, ' + raw[1:]
    (folder / "controller.json").write_text(raw)
    with pytest.raises(AssertionError):
        exec(compile(python_body(PREFLIGHT), str(PATH), "exec"), {})
