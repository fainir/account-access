"""Exact-version supplements for upstream packages without named notice files.

This maintainer-only inventory retains upstream license files, README sections,
copyright headers, and explicit published SPDX declarations. It does not infer
copyright from author names or grant a license to an unreviewed dependency.
"""

from functools import cache
import hashlib
import json
from pathlib import Path


CATALOG = Path(__file__).with_name("notices") / "bitwarden" / "SUPPLEMENTAL-NOTICES.json"
CATALOG_SHA256 = "e519d57dacd6832a9ecba4f654d49be137ee9aef3fe6f57369dd3f4e7c6bbc9d"


@cache
def _catalog():
    raw = CATALOG.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOG_SHA256:
        raise ValueError("bitwarden_supplemental_notices_changed")
    result = json.loads(raw)
    if result["schema"] != 1:
        raise ValueError("bitwarden_supplemental_notices_changed")
    for document in result["documents"].values():
        if hashlib.sha256(document["text"].encode()).hexdigest() != document["sha256"]:
            raise ValueError("bitwarden_supplemental_notices_changed")
    return result


def supplemental_notice(name, origin, archive_path):
    """Return reviewed notice text only for the identical public source archive.

    Unknown materials still return no notice and remain subject to the caller's
    missing-notice gate. A known name with changed origin or bytes fails closed.
    No download, extraction, upstream execution, or account access is performed.
    """
    catalog = _catalog()
    component = catalog["components"].get(name)
    if component is None:
        return ""
    if not isinstance(origin, dict) or origin.get("url") != component["source_url"]:
        raise ValueError("bitwarden_supplemental_notice_source_changed")
    with Path(archive_path).open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != component["archive_sha256"]:
        raise ValueError("bitwarden_supplemental_notice_source_changed")
    lines = [
        f"\n--- {name} :: reviewed upstream notice supplement ---",
        f"Component: {component['name']} {component['version']}",
        f"Source: {component['source_url']}",
        f"Source SHA-256: {actual}",
        f"Evidence method: {component['method']}",
        f"Published metadata ({component['metadata_path']}):",
        json.dumps(component["metadata"], sort_keys=True, ensure_ascii=False),
        f"Selected license: {component['selected_license']}",
        "Author metadata is not an inferred copyright notice. Original source notices are retained.",
    ]
    for evidence in component["evidence"]:
        lines.extend([
            f"\nVerbatim archive notice: {evidence['archive_path']}",
            f"Notice excerpt SHA-256: {evidence['sha256']}",
            evidence["text"],
        ])
    for identifier in component["documents"]:
        document = catalog["documents"][identifier]
        text = document["text"]
        lines.extend([
            f"\n{document['role']}: {document['source_url']}",
            f"Document SHA-256: {document['sha256']}",
        ])
        if document["role"] == "declared-license-standard-text":
            lines.append("Standard terms for the published declaration; no additional copyright attribution is asserted.")
            # SPDX's template line is an example, not an upstream attribution.
            # Retain the unmodified reference in the checked catalog and emit
            # only its actual permission/condition/disclaimer text here.
            text = text.replace("Copyright (c) <year> <copyright holders>\n\n", "")
        lines.append(text)
    return "\n".join(lines) + "\n"
