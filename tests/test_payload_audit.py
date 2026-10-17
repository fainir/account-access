from io import BytesIO
from pathlib import Path
import platform
import stat
import struct
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

from macos import payload_audit as audit


def thin(kind=2, endian="<", bits=64):
    magic = {
        ("<", 64): b"\xcf\xfa\xed\xfe",
        ("<", 32): b"\xce\xfa\xed\xfe",
        (">", 64): b"\xfe\xed\xfa\xcf",
        (">", 32): b"\xfe\xed\xfa\xce",
    }[endian, bits]
    return (
        magic
        + struct.pack(endian + "6I", 0x100000C, 0, kind, 0, 0, 0)
        + (b"\0" * 4 if bits == 64 else b"")
    )


def fat(endian=">", bits=32, kinds=(2, 2)):
    magic = {
        (">", 32): b"\xca\xfe\xba\xbe",
        ("<", 32): b"\xbe\xba\xfe\xca",
        (">", 64): b"\xca\xfe\xba\xbf",
        ("<", 64): b"\xbf\xba\xfe\xca",
    }[endian, bits]
    size = 20 if bits == 32 else 32
    offset = 8 + len(kinds) * size
    entries = []
    for kind in kinds:
        if bits == 32:
            entries.append(struct.pack(endian + "5I", 0x100000C, 0, offset, 32, 0))
        else:
            entries.append(struct.pack(endian + "IIQQII", 0x100000C, 0, offset, 32, 0, 0))
        offset += 32
    return (
        magic
        + struct.pack(endian + "I", len(kinds))
        + b"".join(entries)
        + b"".join(thin(k) for k in kinds)
    )


@pytest.mark.parametrize("endian,bits", [("<", 32), ("<", 64), (">", 32), (">", 64)])
@pytest.mark.parametrize("kind", [2, 6, 8])
def test_runtime_macho_types_include_both_endiannesses_and_word_sizes(tmp_path, endian, bits, kind):
    path = tmp_path / "binary"
    path.write_bytes(thin(kind, endian, bits))
    assert audit.binary_type(path) == kind
    path.write_bytes(fat(endian, bits, (kind, kind)))
    assert audit.binary_type(path) == kind


@pytest.mark.parametrize(
    "payload",
    [
        b"\xcf\xfa\xed\xfe",
        fat()[:25],
        fat()[:-1],
        b"\xca\xfe\xba\xbe" + struct.pack(">I", 9),
        fat(kinds=(2, 6)),
        thin(11),
    ],
)
def test_truncated_mixed_or_unsupported_native_code_is_refused(tmp_path, payload):
    path = tmp_path / "invalid"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        audit.binary_type(path)


@pytest.mark.parametrize("payload", [b"plain data", thin(1), thin(10)])
def test_data_objects_and_debug_symbols_are_not_runtime_code(tmp_path, payload):
    path = tmp_path / "data"
    path.write_bytes(payload)
    assert audit.binary_type(path) is None


def signature_command(
    *,
    architectures=("arm64",),
    timestamp="Oct 17, 2026",
    team="ABCDEFGHIJ",
    flags="0x10000",
    authority="Developer ID Application: Fixture",
):
    calls = []

    def command(args):
        calls.append(args)
        if args[0] == "/usr/bin/lipo":
            return SimpleNamespace(stdout=" ".join(architectures).encode())
        text = f"TeamIdentifier={team}\nAuthority={authority}\nTimestamp={timestamp}\nCDHash={'a' * 40}\nCodeDirectory v=20500 flags={flags}(runtime)\n"
        return SimpleNamespace(stdout=b"", stderr=text.encode())

    return command, calls


@pytest.mark.parametrize(
    "options",
    [
        {"architectures": ("x86_64",)},
        {"architectures": ("arm64", "arm64")},
        {"architectures": ("arm64", "i386")},
        {"timestamp": ""},
        {"timestamp": "none"},
        {"team": "not set"},
        {"flags": "0x0"},
        {"authority": "Apple Development: Fixture"},
    ],
)
def test_every_executable_requires_target_architecture_developer_id_runtime_and_timestamp(options):
    command, _ = signature_command(**options)
    with pytest.raises(ValueError):
        audit.verify_code(Path("fixture"), 2, "arm64", command)


def test_libraries_need_valid_publisher_and_timestamp_but_do_not_require_executable_runtime_flag():
    command, calls = signature_command(flags="0x0", architectures=("arm64", "x86_64"))
    audit.verify_code(Path("library"), 6, "arm64", command)
    requirement = next(arg for call in calls for arg in call if arg.startswith("-R="))
    assert "100.6.1.13" in requirement and "get-task-allow" in requirement
    assert len([call for call in calls if "--arch" in call]) == 2


def test_every_native_file_inside_wheels_and_frameworks_is_inspected(tmp_path):
    tree = tmp_path / "Runtime.app"
    tree.mkdir()
    (tree / "program").write_bytes(thin())
    wheel = tmp_path / "dependency.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("package/module.so", thin(8))
        archive.writestr("package/script.py", "# ordinary resource")
    command, calls = signature_command()
    result = audit.audit_payload([tree], [wheel], "arm64", command, development=False)
    assert result == dict(
        native_files=2,
        executables=1,
        bundles=1,
        wheels=1,
        publisher_signatures_verified=True,
        notarization_verified=False,
    )
    assert sum("--arch" in call for call in calls) == 2
    assert any("--deep" in call and call[-1] == str(tree) for call in calls)
    # A development inventory never claims the mock publisher check ran.
    result = audit.audit_payload(
        [tree], [wheel], "arm64", lambda _: pytest.fail("Inventory only"), development=True
    )
    assert result["native_files"] == 2 and result["publisher_signatures_verified"] is False


def test_aliases_cannot_leave_the_copied_runtime_or_add_external_bundle_seals(tmp_path):
    tree = tmp_path / "runtime"
    tree.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(thin())
    (tree / "alias").symlink_to(outside)
    with pytest.raises(ValueError, match="unsafe_native_payload_symlink"):
        audit.audit_payload([tree], [], "arm64", None, development=True)
    (tree / "alias").unlink()
    binary = tree / "binary"
    binary.write_bytes(thin())
    (tree / "alias").symlink_to("binary")
    report = audit.audit_payload([tree], [], "arm64", None, development=True)
    assert report["native_files"] == 1


def test_os_ancestor_aliases_are_canonicalized_without_accepting_a_symlink_root(tmp_path):
    real = tmp_path / "real" / "Runtime.app"
    real.mkdir(parents=True)
    (real / "program").write_bytes(thin())
    (real / "program-alias").symlink_to("program")
    ancestor = tmp_path / "alias"
    ancestor.symlink_to(real.parent, target_is_directory=True)
    command, calls = signature_command()
    result = audit.audit_payload([ancestor / real.name], [], "arm64", command, development=False)
    assert result["native_files"] == result["bundles"] == 1
    assert any("--deep" in call and call[-1] == str(real.resolve()) for call in calls)
    direct = tmp_path / "direct.app"
    direct.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe_native_payload_path"):
        audit.audit_payload([direct], [], "arm64", command, development=False)


@pytest.mark.parametrize(
    "names",
    [["../outside"], ["/absolute"], ["a\\b"], ["a/./b"], ["a//b"], ["A", "a"], ["evil.app/code"]],
)
def test_wheel_paths_collisions_and_unprepared_bundles_are_refused(names):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, thin())
    with zipfile.ZipFile(buffer) as archive, pytest.raises(ValueError):
        list(audit.wheel_entries(archive))


def test_wheel_symlinks_are_refused_without_extracting_them():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("alias")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "/outside")
    with (
        zipfile.ZipFile(buffer) as archive,
        pytest.raises(ValueError, match="unsafe_native_wheel_entry"),
    ):
        list(audit.wheel_entries(archive))


@pytest.mark.skipif(sys.platform != "darwin", reason="Uses Apple's native signature verifier")
def test_real_ad_hoc_runtime_is_not_accepted_as_developer_id(tmp_path):
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }\n")
    binary = tmp_path / "fixture"
    subprocess.run(
        ["/usr/bin/xcrun", "clang", str(source), "-o", str(binary)], check=True, capture_output=True
    )
    subprocess.run(
        ["/usr/bin/codesign", "--force", "--options", "runtime", "--sign", "-", str(binary)],
        check=True,
        capture_output=True,
    )

    def command(args):
        return subprocess.run(args, check=True, capture_output=True)

    with pytest.raises(subprocess.CalledProcessError):
        audit.verify_code(
            binary, 2, "arm64" if platform.machine() == "arm64" else "x86_64", command
        )
