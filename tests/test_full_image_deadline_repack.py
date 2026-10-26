import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deadline_repack", ROOT / "scripts/repack_full_image84_timeout.py")
repack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repack)
INFO = (b'<pkg-info identifier="com.fainir.accountaccess.fullimageupdate84" version="0.1.0" auth="root">'
        b'<scripts><postinstall file="./postinstall" timeout="600"/></scripts></pkg-info>')


def test_deadline_is_the_only_changed_byte_sequence():
    changed = repack.extend_deadline(INFO)
    assert changed.replace(b'timeout="1800"', b'timeout="600"') == INFO
    assert len(changed) == len(INFO) + 1


@pytest.mark.parametrize("before,after", [
    (b'fullimageupdate84', b'fullimageupdate83'),
    (b'timeout="600"', b'timeout="1800"'),
    (b'timeout="600"', b''),
    (b'file="./postinstall"', b'file="/other"'),
    (b'auth="root"', b'auth="none"'),
    (b'</scripts>', b'<postinstall file="./extra"/></scripts>'),
    (b'<scripts>', b'<payload numberOfFiles="1" installKBytes="1"/><scripts>'),
])
def test_other_packages_or_changes_are_refused(before, after):
    with pytest.raises(ValueError):
        repack.extend_deadline(INFO.replace(before, after))


def test_root_cannot_execute_repack(monkeypatch):
    monkeypatch.setattr(repack.os, "getuid", lambda: 0)
    monkeypatch.setattr(repack.os, "geteuid", lambda: 0)
    monkeypatch.setattr(Path, "lstat", lambda *_: pytest.fail("path access before root refusal"))
    with pytest.raises(ValueError):
        repack.run(Path("/unread"), Path("/unwritten"))
