import json
from pathlib import Path
import shutil

import pytest

from account_access.browser_setup import CHROME, FILES, RELATIVE, prepare
from account_access.errors import AccessError
from account_access.google_messages_host import HOST, RESOURCES, extension_id


@pytest.fixture
def browser_files(tmp_path):
    home = tmp_path / "owner"
    home.mkdir(mode=0o700)
    app = tmp_path / "signed-app/Contents/MacOS/AccountAccess"
    app.parent.mkdir(parents=True)
    app.write_text("fixture-only")
    resources = tmp_path / "signed-app/Contents/Resources/GoogleMessagesExtension"
    shutil.copytree(RESOURCES, resources)
    checked = []
    def stage():
        return prepare(home, app=app, resources=resources, protected=lambda p: checked.append(p))
    return home, app, resources, checked, stage


def test_browser_registration_uses_native_app_and_immutable_resources_without_a_vault(browser_files, monkeypatch):
    home, app, resources, checked, stage = browser_files
    monkeypatch.setattr("account_access.google_messages_host.load_key", lambda *a: pytest.fail("No vault access"))
    result = stage()
    assert result == {"status": "PREPARED", "extension_path": str(resources), "extension_id": extension_id()}
    assert set(checked) == {app, *(resources / name for name in FILES)}
    launcher = home / RELATIVE / "native-host"
    assert "--browser-native-host" in launcher.read_text() and "--root" not in launcher.read_text()
    manifest = json.loads((home / CHROME / (HOST + ".json")).read_bytes())
    assert manifest["allowed_origins"] == ["chrome-extension://" + extension_id() + "/"]
    assert manifest["path"] == str(launcher) and launcher.stat().st_mode & 0o777 == 0o700
    assert not list(home.rglob("state.db")) and not list(home.rglob("config.json"))
    assert not list(home.rglob("reader.js"))
    assert stage() == result


@pytest.mark.parametrize("change", ["origin", "path", "launcher", "symlink", "permissions", "extension-key", "extension-script"])
def test_browser_setup_refuses_unrecognized_or_unsafe_existing_registration(browser_files, change):
    home, _, resources, _, stage = browser_files
    stage()
    registration = home / CHROME / (HOST + ".json")
    launcher = home / RELATIVE / "native-host"
    if change in {"origin", "path"}:
        value = json.loads(registration.read_bytes())
        value["allowed_origins" if change == "origin" else "path"] = ["chrome-extension://other/"] if change == "origin" else "/tmp/other"
        registration.write_text(json.dumps(value))
    elif change == "launcher":
        launcher.write_text("do not overwrite")
    elif change == "symlink":
        registration.rename(registration.with_suffix(".saved"))
        registration.symlink_to(registration.with_suffix(".saved"))
    elif change == "permissions":
        registration.chmod(0o666)
    elif change == "extension-key":
        file = resources / "manifest.json"
        value = json.loads(file.read_bytes())
        value["key"] = "changed"
        file.write_text(json.dumps(value))
    else:
        (resources / "reader.js").write_text("changed")
    before = registration.read_bytes(), launcher.read_bytes()
    with pytest.raises((AccessError, OSError)):
        stage()
    assert (registration.read_bytes(), launcher.read_bytes()) == before


def test_native_host_pins_the_public_extension_identity():
    swift = (Path(__file__).parents[1] / "macos/BrowserNativeHost.swift").read_text()
    assert 'static let origin = "chrome-extension://' + extension_id() + '/"' in swift


def test_untrusted_runtime_refused_before_browser_registration_changes(browser_files):
    home, app, resources, _, _ = browser_files
    def reject(_):
        raise AccessError("DENIED", "untrusted_runtime")
    with pytest.raises(AccessError, match="untrusted_runtime"):
        prepare(home, app=app, resources=resources, protected=reject)
    assert not list(home.iterdir())


def test_recognized_legacy_host_can_migrate_without_reading_its_store(browser_files):
    home, _, resources, _, stage = browser_files
    stage()
    registration = home / CHROME / (HOST + ".json")
    value = json.loads(registration.read_bytes())
    value["path"] = str(home / "Library/Application Support/Account Access/google-messages-native-host")
    registration.write_text(json.dumps(value))
    assert stage()["extension_path"] == str(resources)
    assert json.loads(registration.read_bytes())["path"] == str(home / RELATIVE / "native-host")
