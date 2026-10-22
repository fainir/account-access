"""Owner-only, bounded export import. Previews never include passwords or seeds."""

import csv
import io
import json
import re
import secrets
import time
from contextlib import ExitStack
from urllib.parse import urlsplit

from .errors import AccessError
from .factors import replace_source, source_mutation
from .models import BrowserAccount, Configuration, origin
from .account_context import describe

MAX_BYTES = 4_000_000
MAX_ROWS = 10_000
MAX_ITEM_URIS = 64
SYNC_HINT = "password-sync-hint:"
ITEM_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def available(store):
    from .catalog import entries
    return {**entries(), **{k: v for k, v in store.config().accounts.items()
                           if isinstance(v, BrowserAccount)}}


def matching_origin(spec, url):
    return (not (spec.login and spec.login.identity_contact)
            and origin(url) in {origin(spec.login_url), *spec.password_import_origins})


def _login_row(ident, url, username, password, authenticator=None):
    if any(value is not None and not isinstance(value, str)
           for value in [url, username, password]):
        raise ValueError()
    if not username or not password or not url:
        return None
    if any(len(value) > 4096 for value in [url, username, password]):
        raise ValueError()
    for value in [url, username, password]:
        value.encode("utf-8")
    parts = urlsplit(url)
    # Validate a supplied port before preview's origin matching. The export is
    # data only: its URL is never visited, broadened or used as a login target.
    if parts.port == 0:
        raise ValueError()
    if (parts.scheme not in {"https", "http"} or not parts.hostname
            or parts.username or parts.password):
        return None
    row = {"id": ident, "url": url, "username": username, "password": password}
    if authenticator:
        from .factors import totp_seed
        try:
            row["totp"] = totp_seed(authenticator)
        except AccessError:
            row["unsupported_authenticator"] = True
    return row


def _parse_csv(contents):
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
    for index, row in enumerate(reader):
        if index >= MAX_ROWS or None in row:
            raise AccessError("DENIED", "invalid_password_export")
        authenticator = next((row.get(fields[field]) for field in ["otpauth", "login_totp", "totp"]
                              if fields.get(field) and row.get(fields[field])), None)
        login = _login_row(str(index), *(row.get(fields[x], "") for x in keys), authenticator)
        if login is not None:
            rows.append(login)
    return rows


def _unique_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError()
        value[key] = item
    return value


def _json_constant(_value):
    raise ValueError()


def _parse_bitwarden(contents):
    value = json.loads(contents, object_pairs_hook=_unique_json, parse_constant=_json_constant)
    if not isinstance(value, dict):
        raise AccessError("DENIED", "unsupported_password_export")
    if value.get("encrypted") is True:
        raise AccessError("DENIED", "password_export_encrypted")
    if value.get("encrypted") is not False or not isinstance(value.get("items"), list):
        raise AccessError("DENIED", "unsupported_password_export")
    if len(value["items"]) > MAX_ROWS:
        raise ValueError()
    rows = []
    for index, item in enumerate(value["items"]):
        if not isinstance(item, dict) or type(item.get("type")) is not int:
            raise ValueError()
        # Notes, cards, identities, SSH keys, passkeys, history and metadata are
        # never copied into a preview or staging record. Deleted logins stay out.
        if item["type"] != 1 or item.get("deletedDate") is not None:
            continue
        login = item.get("login")
        if not isinstance(login, dict):
            raise ValueError()
        uris = login.get("uris")
        # The official TypeScript exporter omits uris for a login with no
        # destinations; older consumers also permit null. Neither supplies a
        # website, so skip the item without rejecting other valid logins.
        if uris is None:
            continue
        if not isinstance(uris, list) or len(uris) > MAX_ITEM_URIS:
            raise ValueError()
        seen = set()
        for uri_index, entry in enumerate(uris):
            if not isinstance(entry, dict):
                raise ValueError()
            match = entry.get("match")
            if match is not None and (type(match) is not int or not 0 <= match <= 5):
                raise ValueError()
            # Never and regex are not literal website destinations. Default,
            # domain, host, prefix and exact entries still use our own reviewed
            # connector/origin binding, never Bitwarden's matching authority.
            if match in {4, 5}:
                continue
            row = _login_row(f"{index}:{uri_index}", entry.get("uri"), login.get("username"),
                             login.get("password"), login.get("totp"))
            if row is not None and row["url"] not in seen:
                if len(rows) >= MAX_ROWS:
                    raise ValueError()
                seen.add(row["url"])
                # This is a suggestion for a later explicit source connection,
                # never a grant or an enrolled sync link. Older exports without
                # a canonical item ID remain ordinary password snapshots.
                item_id = item.get("id")
                if (isinstance(item_id, str) and ITEM_UUID.fullmatch(item_id)
                        and type(item.get("reprompt", 0)) is int and item.get("reprompt", 0) == 0
                        and item.get("archivedDate") is None):
                    row["sync_item"] = item_id
                rows.append(row)
    return rows


def parse(contents):
    if not isinstance(contents, str):
        raise AccessError("DENIED", "password_file_too_large")
    try:
        if len(contents.encode()) > MAX_BYTES:
            raise AccessError("DENIED", "password_file_too_large")
        candidate = contents.lstrip("\ufeff \t\r\n")
        if candidate.startswith(("{", "[")):
            return _parse_bitwarden(candidate)
        return _parse_csv(contents)
    except (csv.Error, ValueError, UnicodeError, RecursionError):
        raise AccessError("DENIED", "invalid_password_export") from None


def preview(store, contents):
    from .catalog import include_sources
    rows = parse(contents)
    # A catalog entry's companion source is needed only when that entry can
    # match this export. Unrelated fixed-source conflicts cannot block import
    # into other reviewed accounts, and preview never publishes definitions.
    specs = {key: spec for key, spec in available(store).items()
             if any(matching_origin(spec, row["url"]) for row in rows)}
    config = store.config()
    include_sources(config, specs)
    config.accounts.update(specs)
    config = Configuration.model_validate(config.model_dump())
    authenticator_sources = {source_id for spec in specs.values() if spec.login
                             for source_id in spec.login.sources()
                             if config.code_sources[source_id].kind == "totp"}
    public = []
    for row in rows:
        candidates = {k: spec for k, spec in specs.items() if matching_origin(spec, row["url"])}
        target = urlsplit(row["url"])
        exact = {k: spec for k, spec in candidates.items()
                 if (urlsplit(spec.login_url).path.rstrip("/"), urlsplit(spec.login_url).query)
                 == (target.path.rstrip("/"), target.query)}
        paths = {k: spec for k, spec in candidates.items()
                 if urlsplit(spec.login_url).path.rstrip("/") == target.path.rstrip("/")}
        matches = [{"id": k, **describe(spec, test_mode=config.test_mode),
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
        generations = {source_id: store.get("source-generation:" + source_id)
                       for source_id in sorted(authenticator_sources)}
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
                      "fingerprints": {k: config.fingerprint(k) for k in specs},
                      "source_generations": generations}, db=db)
    return {"status": "PREVIEW", "id": ident, "rows": public,
            "expires_in": 600, "unsupported": sum(not x["matches"] for x in public)}


def apply(broker, ident, selections, principals):
    from .catalog import entries, include_sources
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
            if not matching_origin(specs[account], rows[row]["url"]):
                raise AccessError("DENIED", "password_origin_mismatch")
            spec = specs[account]
            check = config.model_copy(deep=True)
            include_sources(check, {account: spec})
            check.accounts[account] = spec
            fingerprint = check.fingerprint(account)
            if staged["fingerprints"].get(account) != fingerprint:
                raise AccessError("DENIED", "import_connector_changed")
            include = selection.get("include_authenticator", False)
            if not isinstance(include, bool):
                raise AccessError("DENIED", "invalid_import_selection")
            if include:
                source_id = spec.login.authenticator_source(check) if spec.login else None
                seed = rows[row].get("totp")
                if not seed or not source_id or check.code_sources[source_id].kind != "totp":
                    raise AccessError("DENIED", "authenticator_import_not_supported")
                if source_id in seeds and seeds[source_id] != seed:
                    raise AccessError("DENIED", "conflicting_authenticator_keys")
                seeds[source_id] = seed
            accounts.add(account)
            chosen.append((account, rows[row], ops))
            config = check
        config = Configuration.model_validate(config.model_dump())
        with ExitStack() as held:
            for account in sorted(accounts):
                held.enter_context(store.lock("account:" + account))
            held.enter_context(store.lock("catalog"))
            for source_id in sorted(seeds):
                held.enter_context(source_mutation(store, source_id))
            # All input/connector validation precedes any persistent change.
            current = store.config()
            current_specs = {**entries(), **{key: spec for key, spec in current.accounts.items()
                                            if isinstance(spec, BrowserAccount)}}
            selected = {account: current_specs[account] for account, _, _ in chosen
                        if account in current_specs}
            if len(selected) != len(chosen):
                raise AccessError("DENIED", "import_connector_changed")
            include_sources(current, selected)
            current.accounts.update(selected)
            current = Configuration.model_validate(current.model_dump())
            # Waiting for a busy account must not adopt an intervening owner
            # edit or extend the preview's authority past its lifetime.
            if staged["expires"] < time.time():
                store.put("password-import:" + ident, None)
                raise AccessError("DENIED", "password_import_expired")
            if any(current.fingerprint(account) != staged["fingerprints"].get(account)
                   for account in selected):
                raise AccessError("DENIED", "import_connector_changed")
            generations = staged.get("source_generations")
            if seeds and (not isinstance(generations, dict) or any(
                    source_id not in generations or generations[source_id] != store.get("source-generation:" + source_id)
                    for source_id in seeds)):
                raise AccessError("DENIED", "import_authenticator_changed")
            store.configure(current)
            with store.db() as db:
                for account, row, ops in chosen:
                    store.put("credential:" + account,
                              {"username": row["username"], "password": row["password"]}, db=db)
                    store.put("connection:" + account, None, db=db)
                    # A new explicit import replaces an older manager link; it
                    # must not later overwrite the owner's selected password.
                    store.put("password-link:" + account, None, db=db)
                    hint = None
                    if row.get("sync_item"):
                        hint = {"provider": "bitwarden", "item": row["sync_item"],
                                "username": row["username"],
                                "origin": origin(current.accounts[account].login_url),
                                "fingerprint": current.fingerprint(account)}
                    store.put(SYNC_HINT + account, hint, db=db)
                    for principal in principals:
                        db.execute("DELETE FROM grants WHERE principal=? AND account=?", (principal, account))
                        for op in set(ops):
                            db.execute("INSERT INTO grants VALUES (?,?,?,?,NULL)",
                                       (principal, account, op, current.fingerprint(account)))
                store.put("password-import:" + ident, None, db=db)
                for source_id, seed in seeds.items():
                    replace_source(store, source_id, {"seed": seed}, db=db)
        for account, _, _ in chosen:
            store.audit("owner", account, "", "password_imported")
        return {"status": "IMPORTED", "accounts": [x[0] for x in chosen]}


def sync_suggestion(store, account, *, config=None, credential=None, hint=None):
    """Owner-only exact-item hint; enrollment still checks the live item.

    An export never establishes authority to a password manager. The suggestion
    disappears after an identity, connector, or explicit credential replacement.
    """
    config = config or store.config()
    spec = config.accounts.get(account)
    hint = store.get(SYNC_HINT + account) if hint is None else hint
    if (not isinstance(spec, BrowserAccount) or not spec.login
            or not isinstance(hint, dict)
            or set(hint) != {"provider", "item", "username", "origin", "fingerprint"}
            or hint.get("provider") != "bitwarden"
            or not isinstance(hint.get("item"), str) or not ITEM_UUID.fullmatch(hint["item"])
            or hint.get("origin") != origin(spec.login_url)
            or hint.get("fingerprint") != config.fingerprint(account)):
        return None
    credential = store.get("credential:" + account) if credential is None else credential
    if (not isinstance(credential, dict) or not credential.get("username")
            or hint.get("username") != credential["username"]):
        return None
    return {"provider": "bitwarden", "item": hint["item"]}
