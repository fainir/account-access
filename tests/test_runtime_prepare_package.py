import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from macos import runtime_prepare
from macos import system_package as package
from test_payload_audit import thin


@pytest.fixture
def package_inputs(tmp_path, monkeypatch):
    paths = {name: tmp_path / name for name in ["app", "native", "python", "browsers", "wheels"]}
    for path in paths.values():
        path.mkdir()
    (paths["python"] / "bin").mkdir()
    (paths["python"] / "bin/python3.12").write_bytes(thin())
    (paths["python"] / "lib/python3.12").mkdir(parents=True)
    (paths["python"] / "lib/python3.12/os.py").write_text("# fixture")
    (paths["browsers"] / "browser").write_bytes(thin())
    for name in ["broker", "bootstrap"]:
        (paths["native"] / ("AccountAccess-" + name)).write_bytes(thin())
    project = paths["app"] / "project.whl"
    for path in [project, paths["wheels"] / "dependency.whl"]:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("fixture.py", "# fixture")
    monkeypatch.setattr(package.sys, "platform", "darwin")
    monkeypatch.setattr(package.os, "getuid", lambda: 501)
    monkeypatch.setattr(
        package, "inspect_app", lambda *a, **k: ("0.8.0", "ABCDEFGHIJ", project, b"fixture==1")
    )
    monkeypatch.setattr(package, "signature", lambda *a, **k: {"team": "ABCDEFGHIJ"})
    calls = []

    def command(arguments):
        calls.append(arguments)
        assert arguments[0] == "/bin/chmod", (
            "Inspection must not run supplied code or a signing tool"
        )
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(package, "command", command)
    args = SimpleNamespace(
        **paths,
        output=tmp_path / "output",
        architecture="arm64",
        development=True,
        installer_identity="fixture",
        inspect_runtime=False,
        runtime_identity=None,
        runtime_plan=None,
    )
    return args, calls


@pytest.mark.parametrize("development", [False, True])
def test_inspection_writes_a_reviewable_plan_without_running_or_signing_runtime(
    package_inputs, monkeypatch, development
):
    args, calls = package_inputs
    args.development = development
    args.installer_identity = None
    args.inspect_runtime = True
    plan = {"schema": 1, "python_sha256": "a" * 64, "browsers_sha256": "b" * 64, "executables": {}}

    def inspect(payload, requirements, name, checksum):
        assert not str(payload).startswith(str(args.output.parent))
        assert requirements == b"fixture==1" and name.startswith("account_access-")
        assert len(checksum) == 64
        return plan

    monkeypatch.setattr(runtime_prepare, "preparation_plan", inspect)
    result = package.assemble(args)
    assert result["status"] == "INSPECTED"
    assert json.loads(Path(result["plan_file"]).read_bytes()) == plan
    assert result["production_ready"] is result["notarized"] is result["installed"] is False
    assert len(calls) == 1 and not list(args.output.glob("*.pkg"))


@pytest.mark.parametrize("identity,plan", [("fixture", None), (None, "plan.json")])
def test_signing_identity_and_plan_must_be_supplied_together_before_any_runtime_code(
    package_inputs, identity, plan
):
    args, calls = package_inputs
    args.runtime_identity, args.runtime_plan = identity, plan
    with pytest.raises(ValueError, match="runtime_signing_identity_and_plan_required"):
        package.assemble(args)
    assert len(calls) == 1 and not list(args.output.iterdir())


def test_inspection_cannot_silently_use_a_signing_identity(package_inputs):
    args, calls = package_inputs
    args.inspect_runtime = True
    args.runtime_identity = "-"
    with pytest.raises(ValueError, match="runtime_inspection_cannot_sign"):
        package.assemble(args)
    assert len(calls) == 1 and not list(args.output.iterdir())
