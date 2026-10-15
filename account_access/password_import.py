"""Owner-only, bounded CSV import. Preview responses never include passwords or seeds."""

import csv
import io
import secrets
import time
from contextlib import ExitStack
from urllib.parse import urlsplit

from .errors import AccessError
from .models import BrowserAccount, Configuration, origin

MAX_BYTES = 4_000_000
MAX_ROWS = 10_000


def available(store):
    from .catalog import entries
    return {**entries(), **{k: v for k, v in store.config().accounts.items()
                           if isinstance(v, BrowserAccount)}}


def parse(contents):
    if not isinstance(contents, str) or len(contents.encode()) > MAX_BYTES:
        raise AccessError("DENIED", "password_file_too_large")
    reader = csv.DictReader(io.StringIO(contents.lstrip("\ufeff")))
    if not reader.fieldnames or len(reader.fieldnames) > 40:
        raise AccessError("DENIED", "unsupported_password_export")
    normalized = [x.strip().lower() for x in reader.fieldnames]
    if len(set(normalized)) != len(normalized):
        raise AccessError("DENIED", "duplicate_csv_headers")
    fields = dict(zip(normalized, reader.fieldnames))
    keys = next((group for group in [("url", "username", "password"),
                                     ("login_uri", "login_username", "login_password")]
                 if set(group) <= fields.keys()), None)
    if not keys:
        raise AccessError("DENIED", "unsupported_password_export")
    rows = []
    try:
        for index, row in enumerate(reader):
            if index >= MAX_ROWS or None in row:
                raise AccessError("DENIED", "invalid_password_export")
            url, username, password = [row.get(fields[x], "") or "" for x in keys]
            if not username or not password:
                continue
            if any(len(x) > 4096 for x in [url, username, password]):
                raise AccessError("DENIED", "invalid_password_export")
            parts = urlsplit(url)
            if (parts.scheme not in {"https", "http"} or not parts.hostname
                    or parts.username or parts.password):
                continue
            rows.append({"id": str(index), "url": url, "username": username,
                         "password": password})
            for field in ["otpauth", "login_totp", "totp"]:
                value = row.get(fields.get(field, ""))
                if value:
                    from .factors import totp_seed
                    try:
                        rows[-1]["totp"] = totp_seed(value)
                    except AccessError:
                        rows[-1]["unsupported_authenticator"] = True
                    break
    except (csv.Error, ValueError):
        raise AccessError("DENIED", "invalid_password_export") from None
    return rows


def preview(store, contents):
    specs = available(store)
    config = store.config()
    config.accounts.update(specs)
    config = Configuration.model_validate(config.model_dump())
    rows = parse(contents)
    public = []
    for row in rows:
        candidates = {k: spec for k, spec in specs.items() if origin(spec.login_url) == origin(row["url"])}
        target = urlsplit(row["url"])
        exact = {k: spec for k, spec in candidates.items()
                 if (urlsplit(spec.login_url).path.rstrip("/"), urlsplit(spec.login_url).query)
                 == (target.path.rstrip("/"), target.query)}
        paths = {k: spec for k, spec in candidates.items()
                 if urlsplit(spec.login_url).path.rstrip("/") == target.path.rstrip("/")}
        matches = [{"id": k, "label": spec.label,
                    "authenticator_supported": bool(spec.login and spec.login.authenticator_source(config)),
                    "operations": [{"name": n, "description": op.description}
                                   for n, op in spec.operations.items()]}
                   for k, spec in (exact or paths or candidates).items()]
        public.append({"id": row["id"], "website": origin(row["url"]),
                       "username": row["username"], "matches": matches,
                       "has_authenticator": bool(row.get("totp")),
                       "unsupported_authenticator": bool(row.get("unsupported_authenticator"))})
    ident = secrets.token_hex(24)
    matched = {x["id"] for x in public if x["matches"]}
    # Do not retain passwords for websites this service cannot use.
    with store.lock("password-import-staging"):
        with store.db() as db:
            staged = db.execute("SELECT id, value FROM records WHERE id LIKE 'password-import:%'").fetchall()
            live = []
            for item in staged:
                value = store.unseal(item["id"], item["value"])
                if not value or value["expires"] < time.time():
                    db.execute("DELETE FROM records WHERE id=?", (item["id"],))
                else:
                    live.append(item["id"])
            if len(live) >= 8:
                raise AccessError("DENIED", "too_many_import_previews")
            store.put("password-import:" + ident, {"expires": time.time() + 600,
                      "rows": [r for r in rows if r["id"] in matched],
                      "fingerprints": {k: config.fingerprint(k) for k in specs}}, db=db)
    return {"status": "PREVIEW", "id": ident, "rows": public,
            "expires_in": 600, "unsupported": sum(not x["matches"] for x in public)}


def apply(broker, ident, selections, principals):
    store = broker.store
    if (not isinstance(ident, str) or len(ident) != 48 or not isinstance(selections, list)
            or not 1 <= len(selections) <= 32 or not principals):
        raise AccessError("DENIED", "invalid_import_selection")
    with store.lock("password-import:" + ident):
        staged = store.get("password-import:" + ident)
        if not staged or staged["expires"] < time.time():
            store.put("password-import:" + ident, None)
            raise AccessError("DENIED", "password_import_expired")
        specs, config = available(store), store.config()
        rows = {r["id"]: r for r in staged["rows"]}
        chosen = []
        accounts = set()
        seeds = {}
        for selection in selections:
            if not isinstance(selection, dict) or set(selection) not in [{"row", "account", "operations"}, {"row", "account", "operations", "include_authenticator"}]:
                raise AccessError("DENIED", "invalid_import_selection")
            row, account, ops = selection["row"], selection["account"], selection["operations"]
            if (not isinstance(row, str) or row not in rows or not isinstance(account, str)
                    or account not in specs or account in accounts or not isinstance(ops, list)
                    or not ops or any(not isinstance(x, str) or x not in specs[account].operations for x in ops)):
                raise AccessError("DENIED", "invalid_import_selection")
            if origin(rows[row]["url"]) != origin(specs[account].login_url):
                raise AccessError("DENIED", "password_origin_mismatch")
            spec = specs[account]
            check = config.model_copy(deep=True)
            check.accounts[account] = spec
            fingerprint = check.fingerprint(account)
            if staged["fingerprints"].get(account) != fingerprint:
                raise AccessError("DENIED", "import_connector_changed")
            include = selection.get("include_authenticator", False)
            if not isinstance(include, bool):
                raise AccessError("DENIED", "invalid_import_selection")
            if include:
                source_id = spec.login.authenticator_source(config) if spec.login else None
                seed = rows[row].get("totp")
                if not seed or not source_id or config.code_sources[source_id].kind != "totp":
                    raise AccessError("DENIED", "authenticator_import_not_supported")
                if source_id in seeds and seeds[source_id] != seed:
                    raise AccessError("DENIED", "conflicting_authenticator_keys")
                seeds[source_id] = seed
            accounts.add(account)
            chosen.append((account, rows[row], ops))
            config.accounts[account] = spec
        config = Configuration.model_validate(config.model_dump())
        with ExitStack() as held:
            for account in sorted(accounts):
                held.enter_context(store.lock("account:" + account))
            held.enter_context(store.lock("catalog"))
            # All input/connector validation precedes any persistent change.
            current = store.config()
            for account, _, _ in chosen:
                current.accounts[account] = config.accounts[account]
            store.configure(Configuration.model_validate(current.model_dump()))
            with store.db() as db:
                for account, row, ops in chosen:
                    store.put("credential:" + account,
                              {"username": row["username"], "password": row["password"]}, db=db)
                    store.put("connection:" + account, None, db=db)
                    # A new explicit import replaces an older manager link; it
                    # must not later overwrite the owner's selected password.
                    store.put("password-link:" + account, None, db=db)
                    for principal in principals:
                        db.execute("DELETE FROM grants WHERE principal=? AND account=?", (principal, account))
                        for op in set(ops):
                            db.execute("INSERT INTO grants VALUES (?,?,?,?,NULL)",
                                       (principal, account, op, current.fingerprint(account)))
                store.put("password-import:" + ident, None, db=db)
                for source_id, seed in seeds.items():
                    store.put("source:" + source_id, {"seed": seed}, db=db)
        for account, _, _ in chosen:
            store.audit("owner", account, "", "password_imported")
        return {"status": "IMPORTED", "accounts": [x[0] for x in chosen]}
