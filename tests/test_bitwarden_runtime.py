"""Ordinary synthetic packaging inputs; no executable is run or account opened."""

import base64
import hashlib
import io
import json
import stat
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

from macos import bitwarden_runtime as runtime
from macos import bitwarden_derivation as derivation
from macos import system_package


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def npm_archive(files, *, alias=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, raw in files.items():
            entry = tarfile.TarInfo("package/" + name)
            entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
        if alias:
            entry = tarfile.TarInfo("package/redirected")
            entry.type, entry.linkname = tarfile.SYMTYPE, "/unrelated"
            archive.addfile(entry)
    return output.getvalue()


def fixture(tmp_path, monkeypatch, *, source_fault=None, zip_fault=None, cli_fault=None):
    binary = derivation.IMPORT + b'\nconst metadata = {"node-forge":"1.4.0","demo":"1.0.0"};\n'
    if cli_fault == "forge-call":
        binary += b"external_node_forge_namespaceObject.pki.publicKeyFromPem(input).verify(input, signature);\n"
    elif cli_fault == "alias-consumer":
        binary += b"const another = require('node-forge'); another.pki.publicKeyFromPem(input);\n"
    dependency = npm_archive({"index.js": b"fictional dependency not executed"})
    archive = tmp_path / "official.tgz"
    cli_files = {"package.json": json.dumps({"name": "@bitwarden/cli", "version": "2026.10.0",
                 "dependencies": {"demo": "1.0.0", "node-forge": "1.4.0"}, "bin": {"bw": "build/bw.js"}}).encode(),
                 "build/bw.js": binary,
                 "build/344.js": b"// Fictional first adjacent asset; never executed.\n",
                 "build/685.js": b"// Fictional second adjacent asset; never executed.\n"}
    if cli_fault == "chunk-consumer":
        cli_files["build/chunk.js"] = b'require("node-forge").pki.publicKeyFromPem(input);'
    if zip_fault == "extra":
        cli_files["../unexpected"] = b"not allowed"
    archive.write_bytes(npm_archive(cli_files, alias=zip_fault == "symlink"))
    package = json.dumps({"packages": {
        "node_modules/" + name: {"resolved": "https://registry.npmjs.org/" + name + "/-/" + name + "-1.0.0.tgz",
            "version": "1.0.0", "integrity": "sha512-" + base64.b64encode(hashlib.sha512(dependency).digest()).decode()}
        for name in ["demo", "buffer", "debug", "proxy-agent-negotiate", "node-forge"]}}).encode()
    package_rows = json.loads(package)
    package_rows["packages"]["node_modules/node-forge"]["version"] = "1.4.0"
    package = json.dumps(package_rows).encode()
    crate = b"fictional cargo source"
    cargo = ("[[package]]\nname='demo'\nversion='1.0.0'\n"
             "source='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='" + sha(crate) + "'\n").encode()
    node = b"fictional node source"
    lock = dict(runtime.locked(), archive_sha256=sha(archive.read_bytes()), archive_bytes=archive.stat().st_size,
                npm_integrity="sha512-" + base64.b64encode(hashlib.sha512(archive.read_bytes()).digest()).decode(),
                entrypoint_sha256=sha(binary), npm_dependencies={"demo": "1.0.0", "node-forge": "1.4.0"}, package_lock_sha256=sha(package),
                cargo_lock_sha256=sha(cargo), node_source_sha256=sha(node))
    modified_binary = binary.replace(derivation.IMPORT, derivation.NOTICE, 1).replace(derivation.EMBEDDED_DEPENDENCY, b"", 1)
    modified_metadata = json.loads(cli_files["package.json"])
    modified_metadata["dependencies"].pop("node-forge")
    modified_metadata["accountAccessModification"] = "Unused external dependency removed on 2026-10-20; upstream version unchanged."
    lock["runtime_entrypoint_sha256"] = sha(modified_binary)
    monkeypatch.setattr(runtime, "locked", lambda: lock)
    ledger = json.loads(runtime.OVERRIDES.read_bytes())
    ledger.update(official_cli_version=lock["version"], official_archive_sha256=lock["archive_sha256"],
                  upstream_package_lock_sha256=lock["package_lock_sha256"], overrides={})
    review = ledger["residual_advisories"][0]["applicability"]
    review.update(official_entrypoint_sha256=sha(binary),
                  worker_source_sha256=runtime.digest(runtime.PROVIDER_WORKER),
                  javascript_assets_sha256={name: sha(raw) for name, raw in cli_files.items()
                                            if name.endswith((".js", ".cjs", ".mjs"))})
    ledger["cli_derivation"].update(official_entrypoint_sha256=sha(binary), derived_entrypoint_sha256=sha(modified_binary),
                                    official_metadata_sha256=sha(cli_files["package.json"]),
                                    derived_metadata_sha256=sha((json.dumps(modified_metadata, indent=2, sort_keys=True) + "\n").encode()),
                                    source_sha256=runtime.digest(runtime.DERIVATION_SOURCE))
    ledger_path = tmp_path / "dependency-overrides.json"
    ledger_path.write_text(json.dumps(ledger))
    monkeypatch.setattr(runtime, "OVERRIDES", ledger_path)
    materials = runtime.source_materials(json.loads(package), __import__("tomllib").loads(cargo.decode()), lock)
    bodies = {name: node if name == "node-source.tar.xz" else dependency if name.startswith("npm/")
              else crate if name.startswith("cargo/") else b"fictional preferred source " + name.encode()
              for name in materials}
    index = {"schema": 1, "managed_by": "account-access-bitwarden-source-v1",
             "binary_archive_sha256": lock["archive_sha256"], "clients_commit": lock["clients_commit"],
             "sdk_commit": lock["sdk_commit"], "cli_derivation": derivation.DERIVATION_ID, "notice_files_missing": [],
             "materials": {name: {"url": row["url"], "sha256": sha(bodies[name]), "bytes": len(bodies[name])}
                           for name, row in materials.items()}}
    files = {"source-index.json": None, "package-lock.json": package, "Cargo.lock": cargo,
             "dependency-overrides.json": runtime.OVERRIDES.read_bytes(),
             "account-access-cli-derivation.py": runtime.DERIVATION_SOURCE.read_bytes(),
             "account-access-cli.lock.json": runtime.LOCK.read_bytes(),
             "BUILD.md": (runtime.NOTICES / "BUILD.md").read_bytes(),
             "GPL-3.0.txt": (runtime.NOTICES / "GPL-3.0.txt").read_bytes(),
             "THIRD_PARTY_NOTICES.txt": b"Fictional copyright/license notices", **bodies}
    if source_fault == "missing":
        files.pop("node-source.tar.xz")
    elif source_fault == "modified":
        name = next(name for name in files if name.startswith("npm/"))
        files[name] += b"changed"
    elif source_fault == "notices":
        index["notice_files_missing"] = ["npm/component.tgz"]
    elif source_fault == "lock":
        files["package-lock.json"] += b" "
    elif source_fault == "foreign-origin":
        index["materials"]["node-source.tar.xz"]["url"] = "https://attacker.example/source"
    elif source_fault == "overrides":
        files["dependency-overrides.json"] += b" "
    elif source_fault == "derivation":
        files["account-access-cli-derivation.py"] += b"\n# unreviewed transform\n"
    elif source_fault == "cli-lock":
        files["account-access-cli.lock.json"] += b" "
    files["source-index.json"] = json.dumps(index).encode()
    source = tmp_path / "source.tar.gz"
    with tarfile.open(source, "w:gz") as output:
        for name, raw in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            output.addfile(entry, io.BytesIO(raw))
        if source_fault == "duplicate":
            entry = tarfile.TarInfo("node-source.tar.xz")
            entry.size = len(node)
            output.addfile(entry, io.BytesIO(node))
        if source_fault == "alias":
            entry = tarfile.TarInfo("alias")
            entry.type, entry.linkname = tarfile.SYMTYPE, "/unrelated"
            output.addfile(entry)
    payload = tmp_path / "payload"
    (payload / "python").mkdir(parents=True)
    (payload / "wheels").mkdir()
    wheel = payload / "wheels" / lock["node_wheel_filename"]
    node = b"fictional fixed interpreter never executed"
    with zipfile.ZipFile(wheel, "w") as output:
        output.writestr("playwright/driver/node", node)
    lock.update(node_wheel_sha256=runtime.digest(wheel), node_upstream_sha256=sha(node))
    return archive, source, sha(source.read_bytes()), payload, binary


def test_pinned_cli_and_complete_source_are_staged_without_mutating_inputs(tmp_path, monkeypatch):
    archive, source, pin, payload, binary = fixture(tmp_path, monkeypatch)
    before = [path.read_bytes() for path in [archive, source]]
    report = runtime.stage(payload, archive, source, pin)
    target = payload / "python/libexec/bitwarden"
    assert (target / "build/bw.js").read_bytes() == binary.replace(
        derivation.IMPORT, derivation.NOTICE, 1).replace(derivation.EMBEDDED_DEPENDENCY, b"", 1)
    assert b"node-forge" not in (target / "build/bw.js").read_bytes()
    assert "node-forge" not in json.loads((target / "package.json").read_bytes())["dependencies"]
    assert not (target / "node_modules/node-forge").exists()
    assert stat.S_IMODE((target / "build/bw.js").stat().st_mode) == 0o644
    assert (target / "GPL-3.0.txt").read_bytes() == (runtime.NOTICES / "GPL-3.0.txt").read_bytes()
    assert report["source_bundle_sha256"] == pin and report["source_distribution_required"] is True
    assert report["native_addons"] is False and report["node_version"] == "24.21.0"
    assert report["official_entrypoint_sha256"] == sha(binary)
    assert report["entrypoint_sha256"] == runtime.locked()["runtime_entrypoint_sha256"]
    assert report["cli_derivation"] == derivation.DERIVATION_ID
    assert report["omitted_runtime_dependencies"] == {"node-forge": "1.4.0"}
    assert not (target / "bw").exists()
    assert all(not path.stat().st_mode & 0o111 for path in target.rglob("*") if path.is_file())
    assert json.loads((target / "runtime-manifest.json").read_bytes()) == report
    assert [path.read_bytes() for path in [archive, source]] == before
    # The full source archive is a separate release asset, not another runtime copy.
    assert not list(target.glob("*.tar.gz"))


@pytest.mark.parametrize("fault,reason", [
    ("missing", "bitwarden_corresponding_source_incomplete"),
    ("modified", "bitwarden_source_bundle_invalid"),
    ("notices", "bitwarden_dependency_notices_need_review"),
    ("lock", "bitwarden_source_lock_changed"),
    ("foreign-origin", "bitwarden_source_bundle_invalid"),
    ("overrides", "bitwarden_dependency_overrides_changed"),
    ("derivation", "bitwarden_cli_derivation_changed"),
    ("cli-lock", "bitwarden_cli_derivation_changed"),
    ("duplicate", "bitwarden_source_bundle_invalid"),
    ("alias", "bitwarden_source_bundle_invalid"),
])
def test_source_refusal_happens_before_runtime_publication(tmp_path, monkeypatch, fault, reason):
    archive, source, pin, payload, _ = fixture(tmp_path, monkeypatch, source_fault=fault)
    with pytest.raises(ValueError, match="^" + reason + "$"):
        runtime.stage(payload, archive, source, pin)
    assert list((payload / "python").iterdir()) == []


@pytest.mark.parametrize("fault", ["extra", "symlink"])
def test_cli_zip_must_have_one_regular_pinned_executable(tmp_path, monkeypatch, fault):
    archive, source, pin, payload, _ = fixture(tmp_path, monkeypatch, zip_fault=fault)
    with pytest.raises(ValueError, match="^bitwarden_cli_archive_invalid$"):
        runtime.stage(payload, archive, source, pin)
    assert list((payload / "python").iterdir()) == []


def test_existing_or_redirected_libexec_is_never_adopted(tmp_path, monkeypatch):
    archive, source, pin, payload, _ = fixture(tmp_path, monkeypatch)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (payload / "python/libexec").symlink_to(unrelated)
    with pytest.raises(ValueError, match="^bitwarden_runtime_destination_must_be_new$"):
        runtime.stage(payload, archive, source, pin)
    assert list(unrelated.iterdir()) == []


def test_source_header_limits_are_checked_before_advancing_archive(tmp_path, monkeypatch):
    source = tmp_path / "source.tar.gz"
    source.write_bytes(b"Fictional archive never decompressed")
    oversized = tarfile.TarInfo("oversized")
    oversized.size = runtime.MAX_MATERIAL_BYTES + 1

    class Headers:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def __iter__(self):
            yield oversized
            pytest.fail("Refuse the header before decompressing its oversized body")

    monkeypatch.setattr(runtime.tarfile, "open", lambda *a, **k: Headers())
    with pytest.raises(ValueError, match="^bitwarden_source_bundle_invalid$"):
        runtime.source_bundle(source, runtime.digest(source))


def test_consumer_assembly_requires_cli_and_corresponding_source_together(tmp_path):
    for values in [{}, {"bitwarden_archive": "only-binary"}, {"bitwarden_sources": "only-source"}]:
        with pytest.raises(ValueError, match="^bitwarden_runtime_and_corresponding_source_required$"):
            system_package.stage_bitwarden(SimpleNamespace(development=False, **values), tmp_path)
    assert system_package.stage_bitwarden(SimpleNamespace(development=True), tmp_path) is None


def test_fixed_node_input_drift_is_refused_before_staging(tmp_path, monkeypatch):
    archive, source, pin, payload, _ = fixture(tmp_path, monkeypatch)
    wheel = payload / "wheels" / runtime.locked()["node_wheel_filename"]
    wheel.write_bytes(b"Unreviewed interpreter cannot enter this runtime")
    with pytest.raises(ValueError, match="^bitwarden_node_runtime_changed$"):
        runtime.stage(payload, archive, source, pin)
    assert not (payload / "python/libexec").exists()


def test_npm_tar_refuses_addons_and_aliases():
    for files in [{"native.node": b"unreviewed native addon"}, {"data": b"\xcf\xfa\xed\xfeunreviewed Mach-O"}]:
        with pytest.raises(ValueError, match="^bitwarden_cli_native_addon_not_permitted$"):
            runtime._npm_files(npm_archive(files))
    with pytest.raises(ValueError, match="^bitwarden_cli_archive_invalid$"):
        runtime._npm_files(npm_archive({"safe": b"data"}, alias=True))


@pytest.mark.parametrize("second", [b"identical", b"conflicting"])
def test_upstream_duplicate_files_are_allowed_only_when_identical(second):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for body in [b"identical", second]:
            member = tarfile.TarInfo("package/index.js")
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    if second == b"identical":
        assert runtime._npm_files(output.getvalue()) == {"index.js": b"identical"}
    else:
        with pytest.raises(ValueError, match="^bitwarden_cli_archive_invalid$"):
            runtime._npm_files(output.getvalue())


def test_dependency_resolution_uses_nearest_lock_path_and_required_peers(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    rows = {"node_modules/" + name: {"version": "1.0.0"}
            for name in ["demo", "buffer", "debug", "proxy-agent-negotiate", "nearest", "peer", "node-forge"]}
    rows["node_modules/node-forge"]["version"] = "1.4.0"
    rows["node_modules/demo"].update(dependencies={"nearest": "2.0.0"}, peerDependencies={"peer": "1.0.0", "optional-peer": "1"},
                                     peerDependenciesMeta={"optional-peer": {"optional": True}}, optionalDependencies={"unavailable": "1"})
    rows["node_modules/demo/node_modules/nearest"] = {"version": "2.0.0"}
    resolved = runtime.runtime_dependencies({"packages": rows})
    assert "node_modules/demo/node_modules/nearest" in resolved
    assert "node_modules/nearest" not in resolved and "node_modules/peer" in resolved
    assert "node_modules/node-forge" not in resolved
    assert runtime.runtime_dependencies({"packages": rows}, include_removed=True)["node_modules/node-forge"]["version"] == "1.4.0"
    rows["node_modules/demo"]["dependencies"]["missing-required"] = "1"
    with pytest.raises(ValueError, match="^bitwarden_runtime_dependency_missing$"):
        runtime.runtime_dependencies({"packages": rows})


def test_dependency_override_replaces_graph_and_requires_the_original_version(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    rows = {"node_modules/" + name: {"version": "1.0.0"}
            for name in ["demo", "buffer", "debug", "proxy-agent-negotiate", "old-child", "patched-child", "node-forge"]}
    rows["node_modules/node-forge"]["version"] = "1.4.0"
    rows["node_modules/demo"]["dependencies"] = {"old-child": "1.0.0"}
    change = {"node_modules/demo": {"from_version": "1.0.0", "package": {
        "version": "1.0.1", "dependencies": {"patched-child": "1.0.0"}}}}
    monkeypatch.setattr(runtime, "reviewed_overrides", lambda _: change)
    resolved = runtime.runtime_dependencies({"packages": rows})
    assert resolved["node_modules/demo"]["version"] == "1.0.1"
    assert "node_modules/patched-child" in resolved and "node_modules/old-child" not in resolved
    change["node_modules/demo"]["from_version"] = "2.0.0"
    with pytest.raises(ValueError, match="^bitwarden_dependency_overrides_changed$"):
        runtime.runtime_dependencies({"packages": rows})


def test_override_ledger_cannot_be_used_with_another_official_cli_input():
    lock = runtime.locked()
    assert len(runtime.reviewed_overrides(lock)) == 5
    for key in ["version", "archive_sha256", "package_lock_sha256"]:
        with pytest.raises(ValueError, match="^bitwarden_dependency_overrides_changed$"):
            runtime.reviewed_overrides(dict(lock, **{key: "changed"}))


def test_source_plan_rejects_new_registry_or_git_authority(tmp_path, monkeypatch):
    fixture(tmp_path, monkeypatch)
    minimal = {"packages": {"node_modules/" + name: {"version": "1.0.0", "resolved": "https://attacker.example/package", "integrity": "sha512-eA=="}
                            for name in ["demo", "buffer", "debug", "proxy-agent-negotiate", "node-forge"]}}
    minimal["packages"]["node_modules/node-forge"]["version"] = "1.4.0"
    with pytest.raises(ValueError, match="^bitwarden_source_dependency_needs_review$"):
        runtime.source_materials(minimal, {"package": []})
    minimal["packages"]["node_modules/demo"]["resolved"] = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    for row in minimal["packages"].values():
        row["resolved"] = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    with pytest.raises(ValueError, match="^bitwarden_source_dependency_needs_review$"):
        runtime.source_materials(minimal, {"package": [{"source": "git+https://attacker.example/code"}]})


@pytest.mark.parametrize("fault", ["forge-call", "alias-consumer", "chunk-consumer"])
def test_current_review_cannot_accept_new_forge_consumers_even_after_repinning_inputs(tmp_path, monkeypatch, fault):
    # The synthetic archive, entrypoint and asset hashes all agree. The release
    # must still reject a used namespace or a second import before publication.
    archive, source, pin, payload, _ = fixture(tmp_path, monkeypatch, cli_fault=fault)
    with pytest.raises(ValueError, match="^bitwarden_residual_advisory_review_changed$"):
        runtime.stage(payload, archive, source, pin)
    assert not (payload / "python/libexec").exists()


@pytest.mark.parametrize("fault", ["worker", "entrypoint-review", "removed-advisory", "cleared-advisory",
                                  "command-review", "boolean-count"])
def test_stale_or_silently_cleared_review_is_refused_before_runtime_publication(tmp_path, monkeypatch, fault):
    archive, source, pin, payload, _ = fixture(tmp_path, monkeypatch)
    ledger = json.loads(runtime.OVERRIDES.read_bytes())
    if fault == "worker":
        changed_worker = tmp_path / "changed-worker.py"
        changed_worker.write_bytes(runtime.PROVIDER_WORKER.read_bytes() + b"\n# unreviewed command-path change\n")
        monkeypatch.setattr(runtime, "PROVIDER_WORKER", changed_worker)
    elif fault == "entrypoint-review":
        ledger["residual_advisories"][0]["applicability"]["official_entrypoint_sha256"] = "0" * 64
    elif fault == "removed-advisory":
        ledger["residual_advisories"] = []
    elif fault == "cleared-advisory":
        ledger["residual_advisories"][0]["analysis_state"] = "not_affected"
    elif fault == "command-review":
        ledger["residual_advisories"][0]["applicability"]["allowed_commands"].append("serve")
    elif fault == "boolean-count":
        ledger["residual_advisories"][0]["applicability"]["bound_namespace_occurrences"] = True
    runtime.OVERRIDES.write_text(json.dumps(ledger))
    with pytest.raises(ValueError, match="^bitwarden_residual_advisory_review_changed$"):
        runtime.stage(payload, archive, source, pin)
    assert not (payload / "python/libexec").exists()


@pytest.mark.parametrize("kind", ["dependencies", "optionalDependencies", "peerDependencies"])
def test_new_transitive_forge_consumers_fail_the_real_dependency_resolver(tmp_path, monkeypatch, kind):
    fixture(tmp_path, monkeypatch)
    rows = {"node_modules/" + name: {"version": "1.0.0"}
            for name in ["demo", "buffer", "debug", "proxy-agent-negotiate", "node-forge"]}
    rows["node_modules/node-forge"]["version"] = "1.4.0"
    rows["node_modules/demo"][kind] = {"node-forge": "1.4.0"}
    with pytest.raises(ValueError, match="^bitwarden_residual_advisory_review_changed$"):
        runtime.runtime_dependencies({"packages": rows})


def test_review_is_bound_to_every_official_javascript_asset(tmp_path, monkeypatch):
    archive, _, _, _, _ = fixture(tmp_path, monkeypatch)
    cli = runtime._npm_files(archive.read_bytes())
    runtime.review_residual_advisories(runtime.locked(), cli=cli)
    cli["build/unreviewed.mjs"] = b"export const unused = 1;"
    with pytest.raises(ValueError, match="^bitwarden_residual_advisory_review_changed$"):
        runtime.review_residual_advisories(runtime.locked(), cli=cli)


def test_derivation_is_reproducible_and_preserves_original_version_and_other_assets(tmp_path, monkeypatch):
    archive, _, _, _, _ = fixture(tmp_path, monkeypatch)
    original = runtime._npm_files(archive.read_bytes())
    before = dict(original)
    ledger = json.loads(runtime.OVERRIDES.read_bytes())
    first = derivation.derive_cli(original, ledger)
    assert derivation.derive_cli(original, ledger) == first
    assert original == before
    assert {name for name in first if first[name] != original[name]} == {"package.json", "build/bw.js"}
    metadata = json.loads(first["package.json"])
    assert metadata["version"] == json.loads(original["package.json"])["version"] == "2026.10.0"
    assert metadata["dependencies"] == {"demo": "1.0.0"}
    assert "upstream version unchanged" in metadata["accountAccessModification"]
    assert b"Account Access modification (2026-10-20)" in first["build/bw.js"]
    assert b"require(" not in first["build/bw.js"]


@pytest.mark.parametrize("fault", ["output-pin", "metadata-pin", "original-metadata-pin", "source-pin",
                                  "patched-claim", "omission-path", "modified-asset", "metadata-consumer"])
def test_derivation_refuses_changed_output_provenance_or_original_shape(tmp_path, monkeypatch, fault):
    archive, _, _, payload, _ = fixture(tmp_path, monkeypatch)
    files = runtime._npm_files(archive.read_bytes())
    ledger = json.loads(runtime.OVERRIDES.read_bytes())
    spec = ledger["cli_derivation"]
    if fault == "output-pin":
        spec["derived_entrypoint_sha256"] = "0" * 64
    elif fault == "metadata-pin":
        spec["derived_metadata_sha256"] = "0" * 64
    elif fault == "original-metadata-pin":
        spec["official_metadata_sha256"] = "0" * 64
    elif fault == "source-pin":
        spec["source_sha256"] = "0" * 64
    elif fault == "patched-claim":
        spec["upstream_patched"] = True
    elif fault == "omission-path":
        spec["omitted_runtime_paths"].append("node_modules/demo")
    elif fault == "modified-asset":
        files["build/344.js"] += b"// changed\n"
    else:
        metadata = json.loads(files["package.json"])
        metadata["optionalDependencies"] = {"node-forge": "1.4.0"}
        files["package.json"] = json.dumps(metadata).encode()
        spec["official_metadata_sha256"] = sha(files["package.json"])
    with pytest.raises(ValueError, match="^bitwarden_cli_derivation_changed$"):
        derivation.derive_cli(files, ledger)
    assert not (payload / "python/libexec").exists()


def test_data_only_reproduction_tool_writes_only_reviewed_overlay_and_refuses_reuse(tmp_path, monkeypatch, capsys):
    archive, _, _, _, _ = fixture(tmp_path, monkeypatch)
    original = runtime._npm_files(archive.read_bytes())
    directory = tmp_path / "official"
    runtime._write_npm(original, directory)
    output = tmp_path / "derived-overlay"
    args = ["--cli-directory", str(directory), "--output", str(output), "--ledger", str(runtime.OVERRIDES)]
    assert derivation.main(args) == 0
    assert json.loads(capsys.readouterr().out)["upstream_patched"] is False
    assert sorted(str(path.relative_to(output)) for path in output.rglob("*") if path.is_file()) == ["build/bw.js", "package.json"]
    assert {name: (directory / name).read_bytes() for name in original} == original
    before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    assert derivation.main(args) == 1
    assert {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()} == before


def test_data_only_reproduction_refuses_unreviewed_adjacent_code_before_output(tmp_path, monkeypatch):
    archive, _, _, _, _ = fixture(tmp_path, monkeypatch)
    directory = tmp_path / "official"
    runtime._write_npm(runtime._npm_files(archive.read_bytes()), directory)
    (directory / "build/new.js").write_text("require('node-forge')")
    output = tmp_path / "derived-overlay"
    assert derivation.main(["--cli-directory", str(directory), "--output", str(output),
                            "--ledger", str(runtime.OVERRIDES)]) == 1
    assert not output.exists()


@pytest.mark.parametrize("fault", ["oversize", "symlink"])
def test_data_only_reproduction_requires_a_bounded_regular_ledger(tmp_path, monkeypatch, fault):
    archive, _, _, _, _ = fixture(tmp_path, monkeypatch)
    directory = tmp_path / "official"
    runtime._write_npm(runtime._npm_files(archive.read_bytes()), directory)
    ledger = tmp_path / "unreviewed-ledger.json"
    if fault == "oversize":
        ledger.write_bytes(b"x" * (128 * 1024 + 1))
    else:
        ledger.symlink_to(runtime.OVERRIDES)
    output = tmp_path / "derived-overlay"
    assert derivation.main(["--cli-directory", str(directory), "--output", str(output), "--ledger", str(ledger)]) == 1
    assert not output.exists()


def test_worker_and_packaging_agree_on_original_and_derived_entrypoints():
    from account_access import bitwarden_source

    lock = runtime.locked()
    assert lock["entrypoint_sha256"] == bitwarden_source.OFFICIAL_ENTRYPOINT_SHA256
    assert lock["runtime_entrypoint_sha256"] == bitwarden_source.ENTRYPOINT_SHA256
    assert bitwarden_source.CLI_DERIVATION == derivation.DERIVATION_ID


def test_static_runtime_copies_fixed_libexec_and_notices_without_executing_them(tmp_path, monkeypatch):
    from macos import runtime_image
    from test_runtime_image import lock, wheel

    payload = tmp_path / "private-runtime"
    (payload / "python/bin").mkdir(parents=True)
    executable = payload / "python/bin/python3.12"
    executable.write_bytes(b"This fictional interpreter must never execute")
    executable.chmod(0o755)
    cli = payload / "python/libexec/bitwarden"
    cli.mkdir(parents=True)
    (cli / "bw").write_bytes(b"This fictional CLI must never execute")
    (cli / "bw").chmod(0o755)
    (cli / "NOTICE.md").write_text("Fictional source/license notice")
    wheels = payload / "wheels"
    wheels.mkdir()
    dependency = wheel(wheels, "fixture")
    project = wheel(wheels, "account-access", "0.8.0", requires=["fixture>=1"])
    monkeypatch.setattr(runtime_image, "build_stage", lambda value: value.resolve(strict=True))
    original = {path.name: path.read_bytes() for path in cli.iterdir()}
    runtime_image.assemble(payload, lock(dependency), project.name, runtime_image.digest(project), "arm64", "3.12.15")
    installed = payload / "runtime/libexec/bitwarden"
    assert {path.name: path.read_bytes() for path in installed.iterdir()} == original
    assert {path.name: path.read_bytes() for path in cli.iterdir()} == original
    assert stat.S_IMODE((installed / "bw").stat().st_mode) == 0o755
