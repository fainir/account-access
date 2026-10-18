"""Source preparation remains data-only and excludes upstream commercial code."""

import io
import tarfile
from types import SimpleNamespace

import pytest

from macos import bitwarden_sources as sources


def source_archive(path, files, *, alias=None):
    with tarfile.open(path, "w:gz") as output:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            output.addfile(member, io.BytesIO(raw))
        if alias:
            member = tarfile.TarInfo("repository/docs/license-link")
            member.type, member.linkname = tarfile.SYMTYPE, alias
            output.addfile(member)


def test_source_filter_preserves_oss_bytes_and_confined_links_without_extraction(tmp_path):
    path = tmp_path / "upstream.tar.gz"
    source_archive(path, {"repository/LICENSE": b"Fictional OSS license",
                          "repository/apps/cli/build.sh": b"Do not execute this source file",
                          "repository/bitwarden_license/secret.ts": b"Commercial source must not be redistributed",
                          "repository/crates/nested/bitwarden_license/lib.rs": b"Commercial nested source"},
                   alias="../LICENSE")
    sources.filtered_source(path)
    with tarfile.open(path, "r:gz") as archive:
        assert archive.getnames() == ["repository/LICENSE", "repository/apps/cli/build.sh", "repository/docs/license-link"]
        assert archive.extractfile("repository/apps/cli/build.sh").read() == b"Do not execute this source file"
        assert archive.getmember("repository/docs/license-link").linkname == "../LICENSE"
    assert sorted(value.name for value in tmp_path.iterdir()) == ["upstream.tar.gz"]


@pytest.mark.parametrize("target", ["/outside", "../../outside"])
def test_source_filter_refuses_links_leaving_repository(tmp_path, target):
    path = tmp_path / "upstream.tar.gz"
    source_archive(path, {"repository/LICENSE": b"Fictional OSS license"}, alias=target)
    original = path.read_bytes()
    with pytest.raises(ValueError, match="^bitwarden_upstream_source_link_changed$"):
        sources.filtered_source(path)
    assert path.read_bytes() == original


def test_license_collection_keeps_exact_upstream_notice_text(tmp_path):
    path = tmp_path / "source.tar.gz"
    source_archive(path, {"package/LICENSE": b"Copyright Fictional Author\nFictional permission text\n",
                          "package/NOTICE.txt": b"Fictional dependency notice",
                          "package/build.js": b"This file must not execute"})
    result = sources.notice_text(path, "fictional-package")
    assert "Copyright Fictional Author\nFictional permission text\n" in result
    assert "Fictional dependency notice" in result and "must not execute" not in result


def test_source_preparation_refuses_low_space_before_directory_or_network(tmp_path, monkeypatch):
    output = tmp_path / "new-source-output"
    monkeypatch.setattr(sources.shutil, "disk_usage", lambda _: SimpleNamespace(free=100))
    monkeypatch.setattr(sources.urllib.request, "urlopen", lambda *a, **k: pytest.fail("No download on full disk"))
    with pytest.raises(ValueError, match="^insufficient_corresponding_source_scratch_space$"):
        sources.prepare(output)
    assert not output.exists()


def test_source_download_refuses_new_authority_without_opening_network(tmp_path, monkeypatch):
    monkeypatch.setattr(sources.urllib.request, "urlopen", lambda *a, **k: pytest.fail("No unreviewed download"))
    for url in ["http://registry.npmjs.org/package", "https://attacker.example/package", "https://registry.npmjs.org@attacker.example/package"]:
        with pytest.raises(ValueError, match="^bitwarden_source_url_not_reviewed$"):
            sources.download(url, tmp_path / "source")
    assert not list(tmp_path.iterdir())


def test_redirect_policy_checks_each_hop_before_following():
    handler = sources.ReviewedRedirect()
    request = sources.urllib.request.Request("https://registry.npmjs.org/source")
    for target in ["http://registry.npmjs.org/source", "https://attacker.example/source",
                   "https://registry.npmjs.org@attacker.example/source"]:
        with pytest.raises(ValueError, match="^bitwarden_source_redirect_not_reviewed$"):
            handler.redirect_request(request, None, 302, "Found", {}, target)
    redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://codeload.github.com/source")
    assert redirected.full_url == "https://codeload.github.com/source"


def test_final_response_cannot_downgrade_https(tmp_path, monkeypatch):
    class Response:
        url = "http://registry.npmjs.org/source"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(sources.urllib.request, "build_opener", lambda *a: SimpleNamespace(open=lambda *a, **k: Response()))
    with pytest.raises(ValueError, match="^bitwarden_source_redirect_not_reviewed$"):
        sources.download("https://registry.npmjs.org/source", tmp_path / "source")
    assert not list(tmp_path.iterdir())
