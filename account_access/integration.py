"""Small managed instructions loaded by existing agents in every new session."""

import json
import os
import stat
import tempfile
from pathlib import Path

from .errors import AccessError

START = "<!-- account-access:automatic:start -->"
END = "<!-- account-access:automatic:end -->"


def session_guidance(skill):
    return (START + "\n## Connected accounts\n\n"
            "For work involving connected accounts, information behind a login, or supported "
            "sign-in recovery, use the [Account Access skill](<" + str(skill / "SKILL.md") + ">) "
            "automatically. The user can ask in ordinary language; do not require a skill name "
            "or slash command. Discover its permitted accounts and operations when needed, "
            "then perform the requested work through its installed launcher. Respect standing "
            "permissions and owner-presence challenges. Do not request passwords or login "
            "codes in chat, or use unrelated account data in ordinary coding tasks.\n" + END)


def update_guidance(path, block, *, start_marker=START, end_marker=END, owned_only=False):
    """Replace only our block; preserve unrelated UTF-8 instructions and file mode."""
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise AccessError("DENIED", "session_instructions_symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = b""
    mode = 0o600
    previous = None
    if path.exists():
        previous = path.stat()
        if (not stat.S_ISREG(previous.st_mode) or previous.st_uid != os.getuid()
                or previous.st_nlink != 1 or previous.st_size > 524288):
            raise AccessError("DENIED", "session_instructions_need_review")
        old = path.read_bytes()
        mode = stat.S_IMODE(previous.st_mode)
    try:
        content = old.decode("utf-8")
    except UnicodeError:
        raise AccessError("DENIED", "session_instructions_need_review") from None
    if ("\x00" in content or content.count(start_marker) != content.count(end_marker)
            or content.count(start_marker) > 1):
        raise AccessError("DENIED", "session_instructions_need_review")
    if owned_only and previous is not None and start_marker not in content:
        raise AccessError("DENIED", "existing_execution_rule_needs_review")
    if start_marker in content:
        start, end = content.index(start_marker), content.index(end_marker)
        if end < start:
            raise AccessError("DENIED", "session_instructions_need_review")
        updated = content[:start] + block + content[end + len(end_marker):]
    else:
        updated = content + ("\n\n" if content else "") + block + "\n"
    if updated.encode() == old:
        return
    descriptor, name = tempfile.mkstemp(prefix=".account-access-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(updated.encode())
            output.flush()
            os.fsync(output.fileno())
        if (path.is_symlink() or path.exists() != (previous is not None)
                or (path.exists() and path.read_bytes() != old)):
            raise AccessError("RETRYABLE", "session_instructions_changed")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def codex_rule_block(skill):
    start, end = "# account-access:automatic:start", "# account-access:automatic:end"
    launcher = json.dumps(str(skill / "scripts/access"))
    commands = json.dumps(["accounts", "status", "run", "task", "audit", "doctor"])
    return (start + "\n" + "prefix_rule(\n"
            + "    pattern = [" + launcher + ", " + commands + "],\n"
            + '    decision = "allow",\n'
            + '    justification = "Use the installed Account Access client for owner-approved operations",\n'
            + ")\n" + end)


def install_codex_rule(directory, skill):
    """Allow only the installed, client-only launcher; retain every other host policy."""
    start, end = "# account-access:automatic:start", "# account-access:automatic:end"
    path = directory / "rules/account-access.rules"
    update_guidance(path, codex_rule_block(skill), start_marker=start, end_marker=end, owned_only=True)
    return str(path)


def install_session_guidance(home, detected, codex_home=None):
    installed = {}
    for host in detected:
        directory = (codex_home or home / ".codex") if host == "codex" else home / ".claude"
        paths = [directory / ("AGENTS.md" if host == "codex" else "CLAUDE.md")]
        if host == "codex" and (directory / "AGENTS.override.md").exists():
            paths.append(directory / "AGENTS.override.md")
        skill = home / (".claude/skills/account-access" if host == "claude" else ".agents/skills/account-access")
        for path in paths:
            update_guidance(path, session_guidance(skill))
        installed[host] = {"enabled": True, "instruction_files": [str(path) for path in paths]}
        if host == "codex":
            installed[host]["execution_rules"] = install_codex_rule(directory, skill)
    return installed
