"""Ordinary temporary code fixtures only; no installed or privileged repair run."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from macos import runtime_cache_repair as repair
from macos import startup_check


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    if sys.platform != "darwin":
        pytest.skip("Darwin atomic rename/ACL fixture")
    runtime = tmp_path / "runtime"
    reports = tmp_path / "reports"
    runtime.mkdir()
    reports.mkdir()
    monkeypatch.setattr(repair, "RUNTIME", runtime)

    def check_fd(fd, *, directory=False):
        return startup_check.check_fd(fd, directory=directory, owner=os.getuid())

    def directory(path):
        # Fixture-only root substitute. Production uses pinned root-owned ancestry.
        assert Path(path).is_relative_to(runtime)
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    plan = {"sources": {}, "baseline": [], "extra_directories": []}
    baselines = {}
    for name, source in (("baseline", b"VALUE = frozenset({'a', 'b'})\n"), ("extra", b"")):
        text = runtime / (name + ".py")
        text.write_bytes(source)
        text.chmod(0o644)
        plan["sources"][text.name] = {"sha256": repair.digest(source), "size": len(source), "mode": 0o644}
        folder = runtime / name
        folder.mkdir(mode=0o700)
        cache = folder / (name + ".cpython-312.pyc")
        cache.write_bytes(repair.expected_generated_cache(source, text.stat(), str(text)))
        cache.chmod(0o600)
        observed_path = cache if name == "baseline" else folder
        info = observed_path.stat()
        observed = {"uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino,
                    "mode": f"{stat.S_IMODE(info.st_mode):04o}", "size": info.st_size}
        if name == "baseline":
            data = b"FIXTURE-ORIGINAL-BASELINE-CODE"
            baselines[str(cache.relative_to(runtime))] = data
            plan["baseline"].append({"path": str(cache.relative_to(runtime)), "source": text.name,
                                     "observed": observed, "sha256": repair.digest(data), "size": len(data)})
        else:
            plan["extra_directories"].append({"path": name, "observed": observed,
                                               "allowed_children": {cache.name: text.name}})
    reports_fd = os.open(reports, os.O_RDONLY | os.O_DIRECTORY)
    transaction = repair.Repair(SimpleNamespace(check_fd=check_fd, directory=directory), plan, baselines, reports_fd)
    result = SimpleNamespace(runtime=runtime, reports=reports, plan=plan, transaction=transaction)
    try:
        yield result
    finally:
        transaction.close()
        os.close(reports_fd)


def test_success_restores_exact_baseline_and_moves_only_extra_code_with_durable_evidence(fixture):
    work = fixture.transaction
    work.preflight()
    original = work.operations[0]["before"]
    status, success = work.apply()
    assert (status, success) == ("restored_build76_cache", True)
    baseline = fixture.runtime / fixture.plan["baseline"][0]["path"]
    assert baseline.read_bytes() == b"FIXTURE-ORIGINAL-BASELINE-CODE"
    assert stat.S_IMODE(baseline.stat().st_mode) == 0o644
    assert not (fixture.runtime / "extra").exists()
    assert work.file_identity(work.backup, "prior-00", mode=0o600) == (original["stamp"][1], original["sha256"])
    assert work.state(work.operations[1]) == "applied"
    backup = next(fixture.reports.iterdir())
    journals = [json.loads(path.read_bytes()) for path in sorted(backup.glob("journal-*.json"))]
    staged = next(row for row in journals if row["event"] == "replacements_staged")
    assert staged["state"][0]["inode"] == baseline.stat().st_ino
    assert staged["state"][0]["sha256"] == repair.digest(baseline.read_bytes())
    assert journals.index(staged) < next(i for i, row in enumerate(journals) if row["event"] == "intent")
    assert journals[-1]["event"] == "repair_completed"


@pytest.mark.parametrize("change", ["unknown", "symlink", "hardlink", "wrongcode", "sourcechanged", "wrongmode"])
def test_every_target_is_validated_before_any_backup_or_move(fixture, change):
    extra = fixture.runtime / "extra"
    cache = next(extra.iterdir())
    if change == "unknown":
        (extra / "unexpected.txt").write_text("unrelated")
    elif change == "symlink":
        cache.unlink()
        cache.symlink_to(fixture.runtime / "extra.py")
    elif change == "hardlink":
        os.link(cache, fixture.runtime / "second-link")
    elif change == "wrongcode":
        cache.write_bytes(b"not code")
    elif change == "sourcechanged":
        (fixture.runtime / "extra.py").write_bytes(b"CHANGED = True\n")
    else:
        cache.chmod(0o644)
    with pytest.raises((repair.Refused, startup_check.Refused, OSError)):
        fixture.transaction.preflight()
    assert list(fixture.reports.iterdir()) == []
    assert stat.S_IMODE((fixture.runtime / fixture.plan["baseline"][0]["path"]).stat().st_mode) == 0o600


@pytest.mark.parametrize("timing", ["before_rename", "after_rename", "completed_journal"])
def test_partial_failure_rolls_back_by_real_inode_and_hash_not_just_journal_state(fixture, timing):
    work = fixture.transaction
    work.preflight()
    calls = 0
    native = work.rename

    def renamer(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2 and timing == "before_rename":
            raise RuntimeError("fixture-private-detail")
        native(*args, **kwargs)
        if calls == 2 and timing == "after_rename":
            raise RuntimeError("fixture-private-detail")

    work.rename = renamer
    journal = work.journal

    def journal_failure(event, index, state=None):
        if timing == "completed_journal" and event == "completed" and index == 1:
            raise RuntimeError("fixture-private-detail")
        return journal(event, index, state)

    work.journal = journal_failure
    assert work.apply() == ("repair_failed_rollback_confirmed", False)
    assert work.failure_reason == "cache_repair_preconditions_unavailable"
    for operation in work.operations:
        current = operation["parent"]
        if operation["kind"] == "file":
            assert work.file_identity(current, operation["name"], mode=0o600) == (
                operation["before"]["stamp"][1], operation["before"]["sha256"])
        else:
            assert (fixture.runtime / "extra").is_dir()
            assert work.tree(current, operation["name"], operation["row"])["children"] == operation["before"]["children"]
    assert any(fixture.reports.iterdir())  # Evidence and staged replacements survive rollback.


def test_concurrent_replacement_is_preserved_and_reported_as_rollback_conflict(fixture):
    work = fixture.transaction
    work.preflight()
    native = work.rename
    calls = 0

    def renamer(*args, **kwargs):
        nonlocal calls
        calls += 1
        native(*args, **kwargs)
        if calls == 2:
            baseline = fixture.runtime / fixture.plan["baseline"][0]["path"]
            replacement = baseline.with_name("concurrent")
            replacement.write_bytes(b"PRESERVE-CONCURRENT-REPLACEMENT")
            replacement.chmod(0o644)
            replacement.replace(baseline)
            raise RuntimeError("concurrent fixture update")

    work.rename = renamer
    assert work.apply() == ("repair_failed_rollback_conflict", False)
    assert (fixture.runtime / fixture.plan["baseline"][0]["path"]).read_bytes() == b"PRESERVE-CONCURRENT-REPLACEMENT"
    assert (fixture.runtime / "extra").is_dir()  # Unconflicted move was safely reversed.
    assert work.file_identity(work.backup, "prior-00", mode=0o600)[1] == work.operations[0]["before"]["sha256"]


def test_mutation_of_moved_tree_is_refused_and_preserved_in_private_backup(fixture):
    work = fixture.transaction
    work.preflight()
    native = work.rename
    calls = 0

    def renamer(*args, **kwargs):
        nonlocal calls
        calls += 1
        native(*args, **kwargs)
        if calls == 2:
            folder = os.open("prior-01", os.O_RDONLY | os.O_DIRECTORY, dir_fd=work.backup)
            try:
                fd = os.open("unknown", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=folder)
                os.close(fd)
            finally:
                os.close(folder)

    work.rename = renamer
    assert work.apply() == ("repair_failed_rollback_conflict", False)
    assert work.failure_reason == "cache_changed_during_move"
    assert not (fixture.runtime / "extra").exists()
    assert any((next(fixture.reports.iterdir()) / "prior-01").iterdir())


def test_ordinary_entrypoint_refuses_before_unsafe_imports_or_reads(tmp_path):
    result = subprocess.run([sys.executable, "-I", "-B", "-S", str(Path(repair.__file__))],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                            env={"PATH": "/usr/bin:/bin"}, cwd=tmp_path)
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"status": "REFUSED", "reason": "trusted_repair_context_required"}
    assert result.stderr == b""


def test_public_reasons_are_closed():
    assert repair.closed_reason(repair.Refused("unknown_cache_child")) == "unknown_cache_child"
    assert repair.closed_reason(RuntimeError("password-or-private-path")) == "cache_repair_preconditions_unavailable"
    assert repair.closed_reason(OSError(13, "private-path")) == "cache_repair_preconditions_unavailable"


def builder():
    path = Path(repair.__file__).with_name("build-runtime-cache-repair.py")
    spec = importlib.util.spec_from_file_location("runtime_cache_builder_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_static_inputs_match_baseline_manifest_and_generated_postinstall_is_narrow(tmp_path):
    build = builder()
    # The exact signed binary is separately reviewed local evidence, not a
    # checkout/CI dependency. Shell assertions need only bounded static fixtures.
    inputs = {"runtime_cache_repair.py": (Path(repair.__file__).read_bytes(), 0o644),
              "runtime-public-plan-check": (b"FIXTURE-NATIVE-CHECKER", 0o755)}
    plan = json.loads((build.INPUTS / "plan.json").read_bytes())
    assert repair.digest((build.INPUTS / "plan.json").read_bytes()) == repair.PLAN_SHA256
    assert repair.digest(build.base.HELPER.read_bytes()) == plan["common_sha256"]
    assert len(plan["baseline"]) == 3 and len(plan["extra_directories"]) == 8
    for row in plan["baseline"]:
        data = (build.INPUTS / row["package_file"]).read_bytes()
        assert len(data) == row["size"] and repair.digest(data) == row["sha256"]
    post = build.postinstall(inputs)
    path = tmp_path / "postinstall"
    path.write_bytes(post)
    subprocess.run(["/bin/sh", "-n", str(path)], check=True, timeout=5)
    assert b' -I -B -S -X "pycache_prefix=$AC_REPAIR_PREFIX" ' in post
    assert post.index(b'[ -z "$(/bin/ls -A "$AC_REPAIR_PREFIX")" ]') < post.index(b" -I -B -S -X ")
    assert post.index(b"runtime_cache_repair.py\" || exit 1") < post.index(b"# This fixed signed checker")
    assert all(token not in post for token in (b"launchctl", b"kill ", b"--inspect-retained", b"HOME="))
    assert b"--nopayload" in Path(build.__file__).read_bytes()


def test_local_signed_inputs_when_retained_public_artifact_is_available():
    build = builder()
    if sys.platform != "darwin" or not build.CHECKER.exists():
        pytest.skip("Local retained signed public artifact is not a checkout dependency")
    inputs = build.reviewed_inputs()  # Public code only; no helper execution.
    assert len(inputs) == 8
