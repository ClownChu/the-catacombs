#!/usr/bin/env python3
"""Catacombs security guard — profile-driven policy enforcement for Cursor hooks."""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from guard_secrets import (
    _var_name_sensitive,
    detect_secret_values_path,
    detect_secret_values_shell,
)

DEFAULT_PROFILE = "medium"
AUDIT_LOG = Path.home() / ".cursor" / "catacombs-security-audit.log"
VALID_ACTIONS = frozenset({"allow", "ask", "block"})
BLOCK_MESSAGE = (
    "Blocked by Catacombs security guard. "
    "Operation: {operation}. Target: {target}. Intention: {intention}."
)
ASK_MESSAGE = (
    "Catacombs security guard requires approval. "
    "Operation: {operation}. Target: {target}. Intention: {intention}."
)

META_KEYS = frozenset({"match_order", "ask_unsupported_hooks", "ask_unsupported_fallback"})

OBSERVATIONAL_HOOKS = frozenset(
    {
        "postToolUse",
        "afterFileEdit",
        "afterShellExecution",
        "afterMCPExecution",
        "afterAgentResponse",
        "stop",
    }
)
ASK_DEFERRAL_TARGET_HOOKS = frozenset({"beforeShellExecution", "beforeMCPExecution"})

WRITE_SHELL_CMDS = re.compile(
    r"(?:^|[;&|]\s*)(?:rm|mv|cp|chmod|chown|tee|touch|mkdir|truncate|install|sed\s+-i)\b",
    re.IGNORECASE,
)
READ_SHELL_CMDS = re.compile(
    r"(?:^|[;&|]\s*)(?:cat|head|tail|less|more|grep|awk|sed|python3?|node|php)\b",
    re.IGNORECASE,
)
REDIRECT_TO_SSH = re.compile(
    r"(?:>>?|tee\s+(?:-a\s+)?)\s*['\"]?[^'\"\s]*\.ssh",
    re.IGNORECASE,
)
SHELL_REDIRECT_PATH = re.compile(
    r"(?:>>?|tee\s+(?:-[a-zA-Z]+\s+)*(?:-a\s+)?)\s*"
    r"(?:\"([^\"]+)\"|'([^']+)'|(\S+))",
    re.IGNORECASE,
)
SHELL_WRITE_CMD = re.compile(
    r"(?:^|[;&|]\s*)"
    r"(?:rm|rmdir|unlink|mv|cp|chmod|chown|tee|touch|mkdir|truncate|install|sed\s+-i)\b",
    re.IGNORECASE,
)
# ponytail: argv-visible absolute paths only; obfuscated -c/-e without /tmp in string is a ceiling
_INTERPRETER_WRITE_API = re.compile(
    r"(?:"
    r"open\s*\([^)]*['\"][wax+]['\"]"
    r"|\.write_text\s*\("
    r"|\.write_bytes\s*\("
    r"|os\.remove\b"
    r"|os\.unlink\b"
    r"|shutil\.rmtree\b"
    r"|Path\s*\([^)]*\)\.unlink\s*\("
    r"|writeFileSync\b"
    r"|writeFile\s*\("
    r"|appendFile\b"
    r"|createWriteStream\b"
    r"|unlinkSync\b"
    r"|fs\.unlink\b"
    r"|file_put_contents\b"
    r"|fopen\s*\([^)]*['\"][wax+]['\"]"
    r"|unlink\s*\("
    r")",
    re.IGNORECASE,
)
_ABSOLUTE_PATH_IN_CMD = re.compile(
    r"""['"](/[^'"]+)['"]|(?<![\w./~])(/(?:tmp|var/tmp|home|etc|usr|dev|root|opt)(?:/[\w./~%-]+)?)"""
)
_INTERPRETER_UNLINK_API = re.compile(
    r"(?:os\.remove\b|os\.unlink\b|unlinkSync\b|fs\.unlink\b|Path\s*\([^)]*\)\.unlink\s*\(|\bunlink\s*\()",
    re.IGNORECASE,
)
_TEMPFILE_WRITE_API = re.compile(
    r"\b(?:tempfile\.(?:mkstemp|NamedTemporaryFile|TemporaryDirectory)|mkstemp\s*\()",
    re.IGNORECASE,
)
_CHR_LITERAL = re.compile(
    r"(?:chr|String\.fromCharCode)\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
    re.IGNORECASE,
)
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_STRING_CONCAT = re.compile(
    r"""(['"])([^'"]*)\1\s*(?:\+|\.)\s*(['"])([^'"]*)\3"""
)
_HEX_DECODE_CALL = re.compile(
    r"(?:bytes\.fromhex|binascii\.unhexlify|hex2bin)\s*\(\s*"
    r"(['\"])([0-9a-fA-F]*)\1\s*\)",
    re.IGNORECASE,
)
_BUFFER_HEX_CALL = re.compile(
    r"Buffer\.from\s*\(\s*(['\"])([0-9a-fA-F]*)\1\s*,\s*['\"]hex['\"]\s*\)",
    re.IGNORECASE,
)
_B64_DECODE_CALL = re.compile(
    r"(?:base64\.b64decode|base64_decode|atob)\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]*)\1\s*\)",
    re.IGNORECASE,
)
_BUFFER_B64_CALL = re.compile(
    r"Buffer\.from\s*\(\s*(['\"])([A-Za-z0-9+/=]*)\1\s*,\s*['\"]base64['\"]\s*\)",
    re.IGNORECASE,
)
_DEV_SINKS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr"})
SSH_PATH_RE = re.compile(r"(?:^|[/\s'\"~])\.ssh(?:/|\b)")

PERMISSION_RANK = {"deny": 3, "ask": 2, "allow": 1}


@dataclass
class GuardResult:
    permission: str = "allow"
    category: Optional[str] = None
    subtype: Optional[str] = None
    user_message: Optional[str] = None
    agent_message: Optional[str] = None
    notify: bool = False
    matched_detail: Optional[str] = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"permission": self.permission}
        if self.user_message:
            out["user_message"] = self.user_message
        if self.agent_message:
            out["agent_message"] = self.agent_message
        return out


@dataclass
class AuditResult:
    additional_context: Optional[str] = None
    user_message: Optional[str] = None
    audit_log_path: Path = AUDIT_LOG

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.additional_context:
            out["additional_context"] = self.additional_context
        if self.user_message:
            out["user_message"] = self.user_message
        return out


def config_root_default() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def load_security_config(config_root: Path) -> dict[str, Any]:
    path = config_root / "catacombs-security.json"
    if not path.is_file():
        return {"version": 1, "active_profile": DEFAULT_PROFILE, "overrides": {}}
    return _load_json(path)


def load_categories(config_root: Path) -> dict[str, Any]:
    return _load_json(config_root / "catacombs-security" / "categories.json")


def category_definitions(categories_data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in categories_data.items() if k not in META_KEYS}


def load_profile(profile_id: str, config_root: Path) -> dict[str, Any]:
    path = config_root / "catacombs-security" / "profiles" / f"{profile_id}.json"
    if not path.is_file():
        raise KeyError(f"Unknown security profile: {profile_id!r}")

    data = _load_json(path)
    categories_data = load_categories(config_root)
    match_order = categories_data.get("match_order", [])
    cats = data.get("categories", {})

    missing = [key for key in match_order if key not in cats]
    if missing:
        raise ValueError(
            f"Profile {profile_id!r} missing categories: {', '.join(missing)}"
        )
    extra = [key for key in cats if key not in match_order]
    if extra:
        raise ValueError(
            f"Profile {profile_id!r} has unknown categories: {', '.join(extra)}"
        )

    for cat, settings in cats.items():
        action = settings.get("action")
        if action not in VALID_ACTIONS:
            raise ValueError(
                f"Profile {profile_id!r} category {cat!r}: invalid action {action!r}"
            )
        if action == "block" and not settings.get("notify"):
            raise ValueError(
                f"Profile {profile_id!r} category {cat!r}: block requires notify: true"
            )

    return {
        "id": data.get("id", profile_id),
        "label": data.get("label", profile_id),
        "description": data.get("description", ""),
        "categories": cats,
    }


def merge_category_settings(
    profile: dict[str, Any], overrides: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for cat, settings in profile.get("categories", {}).items():
        merged[cat] = dict(settings)
    for cat, override in overrides.items():
        base = merged.get(cat, {"enabled": False, "action": "allow"})
        base.update(override)
        merged[cat] = base
    return merged


def _glob_match(path: str, pattern: str) -> bool:
    normalized = path.replace("\\", "/")
    pat = pattern.replace("\\", "/")

    if pat.startswith("~/"):
        home = str(Path.home()).replace("\\", "/")
        expanded = home + pat[1:]
        if fnmatch.fnmatch(normalized, expanded) or expanded.rstrip("/") in normalized:
            return True
        pat = pat[2:]

    if pat == "**/.ssh/*.pub":
        return "/.ssh/" in normalized and normalized.endswith(".pub")

    segment_match = re.match(r"^\*\*/(.+)/\*\*$", pat)
    if segment_match:
        segment = segment_match.group(1)
        return (
            f"/{segment}/" in normalized
            or normalized.endswith(f"/{segment}")
            or normalized.startswith(f"{segment}/")
            or normalized == segment
        )

    if pat.startswith("**/"):
        tail = pat[3:]
        if tail.endswith("/**"):
            segment = tail[:-3]
            return (
                f"/{segment}/" in normalized
                or normalized.endswith(f"/{segment}")
                or normalized.startswith(f"{segment}/")
                or normalized == segment
            )
        return fnmatch.fnmatch(normalized, tail) or fnmatch.fnmatch(
            os.path.basename(normalized), tail
        )

    return fnmatch.fnmatch(normalized, pat)


def path_matches_any(path: str, patterns: list[str]) -> bool:
    return any(_glob_match(path, p) for p in patterns)


def path_excluded(path: str, patterns: list[str]) -> bool:
    return path_matches_any(path, patterns)


def normalize_path(path: str) -> str:
    n = path.replace("\\", "/").rstrip("/")
    if n.startswith("~/"):
        n = str(Path.home()).replace("\\", "/") + n[1:]
    return n


def policy_path_fragments(cat_def: dict[str, Any]) -> list[str]:
    fragments: list[str] = []
    for pattern in cat_def.get("path_patterns", []):
        frag = pattern.replace("\\", "/")
        if frag.startswith("**/"):
            frag = frag[3:]
        if frag.startswith("~/"):
            frag = str(Path.home()).replace("\\", "/") + frag[1:]
        if frag.endswith("/**"):
            frag = frag[:-3]
        fragments.append(frag.rstrip("/"))
    return fragments


def command_references_policy_path(command: str, cat_def: dict[str, Any]) -> bool:
    n = command.replace("\\", "/")
    return any(fragment in n for fragment in policy_path_fragments(cat_def))


def command_writes_policy_path(command: str, cat_def: dict[str, Any]) -> bool:
    if not command_references_policy_path(command, cat_def):
        return False
    n = command.replace("\\", "/")
    fragments = policy_path_fragments(cat_def)
    redirect = re.compile(
        r"(?:>>?|tee\s+(?:-a\s+)?)\s*['\"]?[^'\"\s]*"
        + "|".join(re.escape(f) for f in fragments),
        re.IGNORECASE,
    )
    return bool(redirect.search(n) or WRITE_SHELL_CMDS.search(n))


def command_reads_policy_path(command: str, cat_def: dict[str, Any]) -> bool:
    if not command_references_policy_path(command, cat_def):
        return False
    if command_writes_policy_path(command, cat_def):
        return False
    n = command.replace("\\", "/")
    if READ_SHELL_CMDS.search(n):
        return True
    if re.search(r"\bunittest\b", n, re.IGNORECASE) and re.search(
        r"\.cursor/hooks|catacombs-security", n
    ):
        return True
    return False


def is_ssh_pub_path(path: str, suffixes: list[str]) -> bool:
    n = normalize_path(path)
    return path_matches_any(n, ["**/.ssh/**"]) and any(n.endswith(s) for s in suffixes)


def command_accesses_ssh(command: str) -> bool:
    return bool(SSH_PATH_RE.search(command.replace("\\", "/")))


def command_ssh_pub_read_only(command: str) -> bool:
    n = command.replace("\\", "/")
    if not command_accesses_ssh(n):
        return False
    if WRITE_SHELL_CMDS.search(n) or REDIRECT_TO_SSH.search(n):
        return False
    stripped = re.sub(r"[^\s;'\"|]*\.ssh[^\s;'\"|]*\.pub", "", n)
    return not command_accesses_ssh(stripped)


def _tool_input(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("tool_input")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    return {}


def _tool_name(event: dict[str, Any]) -> str:
    return str(event.get("tool_name") or event.get("tool") or "")


def _arguments(event: dict[str, Any]) -> dict[str, Any]:
    raw = event.get("arguments")
    return raw if isinstance(raw, dict) else {}


def _strip_file_uri(path: str) -> str:
    if path.startswith("file://"):
        return path[7:]
    return path


def _file_path(event: dict[str, Any]) -> str:
    ti = _tool_input(event)
    args = _arguments(event)
    raw = str(
        event.get("file_path")
        or event.get("path")
        or ti.get("path")
        or ti.get("file_path")
        or ti.get("target_file")
        or ti.get("target_notebook")
        or ti.get("target_directory")
        or args.get("path")
        or args.get("target_file")
        or ""
    )
    return _strip_file_uri(raw)


def _tool_name_folded(event: dict[str, Any]) -> str:
    return _tool_name(event).lower()


def _tokenize_shell_args(args: str) -> list[str]:
    tokens: list[str] = []
    for match in re.finditer(r'"([^"]*)"|\'([^\']*)\'|(\S+)', args):
        tokens.append(next(group for group in match.groups() if group is not None))
    return tokens


def _paths_after_write_cmd(segment: str) -> list[str]:
    match = re.search(
        r"(?:^|[;&|]\s*)"
        r"(?:rm|rmdir|unlink|mv|cp|chmod|chown|tee|touch|mkdir|truncate|install|sed\s+-i)\s+(.*)",
        segment,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return []
    paths: list[str] = []
    tokens = _tokenize_shell_args(match.group(1))
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token == "-i" and idx + 1 < len(tokens):
            paths.append(tokens[idx + 1])
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        paths.append(token)
        idx += 1
    return paths


def _quoted_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    return repr(value)


def _decode_hex_literal(hex_digits: str) -> Optional[str]:
    if len(hex_digits) % 2:
        return None
    try:
        return binascii.unhexlify(hex_digits).decode("latin-1")
    except (ValueError, binascii.Error):
        return None


def _decode_b64_literal(payload: str) -> Optional[str]:
    try:
        return base64.b64decode(payload, validate=True).decode("latin-1")
    except (ValueError, binascii.Error):
        return None


def _replace_encoded_literals(command: str) -> str:
    def hex_repl(match: re.Match[str]) -> str:
        decoded = _decode_hex_literal(match.group(2))
        if decoded is None:
            return match.group(0)
        return _quoted_literal(decoded)

    def b64_repl(match: re.Match[str]) -> str:
        decoded = _decode_b64_literal(match.group(2))
        if decoded is None:
            return match.group(0)
        return _quoted_literal(decoded)

    result = command
    while True:
        updated = _HEX_DECODE_CALL.sub(hex_repl, result)
        updated = _BUFFER_HEX_CALL.sub(hex_repl, updated)
        updated = _B64_DECODE_CALL.sub(b64_repl, updated)
        updated = _BUFFER_B64_CALL.sub(b64_repl, updated)
        if updated == result:
            break
        result = updated
    return result


def _rewrite_env_access_obfuscation(command: str) -> str:
    result = re.sub(
        r"getattr\s*\(\s*os\s*,\s*['\"]environ['\"]\s*\)",
        "os.environ",
        command,
        flags=re.IGNORECASE,
    )
    return re.sub(
        r"process\s*\[\s*['\"]env['\"]\s*\]",
        "process.env",
        result,
        flags=re.IGNORECASE,
    )


def normalize_command_obfuscation(command: str) -> str:
    """Fold concat strings and chr()/fromCharCode()/\\xNN so matchers see real paths."""
    result = _replace_encoded_literals(command)
    while True:
        updated = _CHR_LITERAL.sub(
            lambda m: _quoted_literal(chr(int(m.group(1), 0))), result
        )
        if updated == result:
            break
        result = updated
    result = _HEX_ESCAPE.sub(lambda m: _quoted_literal(chr(int(m.group(1), 16))), result)

    def fold_quoted_concat(match: re.Match[str]) -> str:
        q1, s1, q2, s2 = match.group(1), match.group(2), match.group(3), match.group(4)
        if q1 == q2:
            return f"{q1}{s1}{s2}{q1}"
        return match.group(0)

    raw_slash_plus_quoted = re.compile(
        r"""(?<![\w'"])/\s*(?:\+|\.)\s*(['"])([^'"]*)\1"""
    )

    while True:
        updated = _STRING_CONCAT.sub(fold_quoted_concat, result)
        updated = raw_slash_plus_quoted.sub(
            lambda m: f"{m.group(1)}/{m.group(2)}{m.group(1)}", updated
        )
        if updated == result:
            break
        result = updated
    return _rewrite_env_access_obfuscation(result)


def _is_excluded_write_target(path: str) -> bool:
    normalized = normalize_path(path)
    if "://" in normalized:
        return True
    if normalized in _DEV_SINKS:
        return True
    if normalized.startswith("/dev/fd/"):
        return True
    return False


def _path_inside_url(command: str, start: int) -> bool:
    if start > 0 and command[start - 1] == ":":
        return True
    return start >= 3 and command[start - 3 : start] == "://"


def _interpreter_write_paths(command: str) -> list[str]:
    """Paths targeted by python/node/php write or unlink APIs visible in argv."""
    if not _INTERPRETER_WRITE_API.search(command):
        return []
    paths: list[str] = []
    for match in _ABSOLUTE_PATH_IN_CMD.finditer(command):
        path = match.group(1) or match.group(2)
        if not path:
            continue
        start = match.start(1) if match.group(1) else match.start(2)
        if _path_inside_url(command, start):
            continue
        paths.append(path)
    return paths


def _shell_write_destinations(command: str) -> list[str]:
    normalized = normalize_command_obfuscation(command.replace("\\", "/"))
    paths: list[str] = []
    for match in SHELL_REDIRECT_PATH.finditer(normalized):
        for group in match.groups():
            if group and not _is_excluded_write_target(group):
                paths.append(group)
    for segment in re.split(r"[;&|]", normalized):
        segment = segment.strip()
        if not SHELL_WRITE_CMD.search(segment):
            continue
        for path in _paths_after_write_cmd(segment):
            if not _is_excluded_write_target(path):
                paths.append(path)
    for path in _interpreter_write_paths(normalized):
        if not _is_excluded_write_target(path):
            paths.append(path)
    return paths


def normalize_hook_name(event: dict[str, Any]) -> str:
    for key in ("hook_event_name", "hook", "event"):
        val = event.get(key)
        if val:
            return str(val)
    if event.get("command") and not _tool_name(event):
        return "beforeShellExecution"
    if event.get("file_path") or event.get("path"):
        return "beforeReadFile"
    if event.get("mcp_server_name"):
        return "beforeMCPExecution"
    tool = _tool_name(event)
    if tool.startswith("MCP:") or tool in ("CallDynamicTool", "CallMcpTool"):
        return "beforeMCPExecution"
    if tool:
        return "preToolUse"
    return ""


def dispatch_pretooluse(event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Map preToolUse payloads onto the hook classifiers already know."""
    tool = _tool_name(event)
    ti = _tool_input(event)
    shaped: dict[str, Any] = dict(event)

    if tool == "Shell":
        shaped["command"] = str(ti.get("command") or "")
        return "beforeShellExecution", shaped

    if _tool_name_folded(event) in ("read", "grep", "glob"):
        path = _file_path(event)
        if path:
            shaped["file_path"] = path
            shaped["path"] = path
        return "beforeReadFile", shaped

    if tool in ("Write", "StrReplace", "Delete", "EditNotebook"):
        path = _file_path(event)
        if path:
            shaped["file_path"] = path
            shaped["path"] = path
        return "preToolUse", shaped

    if tool in ("CallDynamicTool", "CallMcpTool") or tool.startswith("MCP:"):
        shaped["mcp_server_name"] = str(
            event.get("mcp_server_name")
            or ti.get("namespace")
            or ti.get("server")
            or ""
        )
        return "beforeMCPExecution", shaped

    return "preToolUse", shaped


def log_resolved_hook(hook: str, event: dict[str, Any]) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tool = _tool_name(event)
    line = f"{ts} hook_resolved={hook} tool={tool}\n"
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line)


def _regex_any(text: str, patterns: list[str], flags: int = re.IGNORECASE) -> bool:
    return any(re.search(p, text, flags) for p in patterns)


def _path_allowed_suffix(path: str, suffixes: list[str]) -> bool:
    n = normalize_path(path)
    return any(n.endswith(s) for s in suffixes)


def _operation_label(hook: str, tool: str) -> str:
    if hook == "beforeShellExecution":
        return "Shell"
    if hook == "beforeReadFile":
        return "Read"
    if hook == "beforeMCPExecution":
        return f"MCP ({tool or 'tool'})"
    if hook == "preToolUse":
        return tool or "tool"
    return hook


def _intention(
    category: str,
    subtype: Optional[str],
    cat_def: dict[str, Any],
) -> str:
    overrides = cat_def.get("intention_overrides", {})
    if subtype and subtype in overrides:
        return overrides[subtype]
    if subtype and subtype in cat_def.get("message_templates", {}):
        # ponytail: subtype keys in message_templates are legacy; intention_overrides preferred
        pass
    return str(cat_def.get("intention", f"perform {category.replace('_', ' ')}"))


def _shell_command(event: dict[str, Any]) -> str:
    return normalize_command_obfuscation(str(event.get("command") or ""))


def match_shell_regex(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    if hook != "beforeShellExecution" or "command" not in event:
        return None
    patterns = cat_def.get("shell_patterns", [])
    command = _shell_command(event)
    if category == "network_egress" and ".ssh/" in command.replace("\\", "/"):
        return None
    if _regex_any(command, patterns):
        return (category, command[:80])
    return None


def match_destructive_fs(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    if hook == "beforeShellExecution" and "command" in event:
        command = _shell_command(event)
        patterns = cat_def.get("shell_patterns", [])
        if _regex_any(command, patterns):
            return (category, command[:80])
        prefix = cat_def.get("workspace_prefix", "/repos/")
        if _INTERPRETER_UNLINK_API.search(command):
            for path in _interpreter_write_paths(command):
                if normalize_path(path).startswith(prefix):
                    return ("delete", path)
            if not _interpreter_write_paths(command):
                return (category, command[:80])
        return None
    if hook != "preToolUse":
        return None
    tool = _tool_name(event)
    if tool not in cat_def.get("delete_tools", ["Delete"]):
        return None
    path = normalize_path(_file_path(event))
    prefix = cat_def.get("workspace_prefix", "/repos/")
    if path and path.startswith(prefix):
        return ("delete", path)
    return None


def match_tool_name(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    allowed_hooks = {"preToolUse", "beforeMCPExecution"}
    if hook not in allowed_hooks:
        return None
    tool = _tool_name(event)
    if tool in cat_def.get("tools", []):
        subtype = "http_tool" if category == "http_tools" else "subagent"
        return (subtype if category == "subagent_spawn" else category, tool)
    return None


def _path_is_write_outside(
    path: str,
    *,
    prefix: str,
    allow_patterns: list[str],
) -> bool:
    if not path:
        return False
    normalized = normalize_path(path)
    if allow_patterns and path_matches_any(normalized, allow_patterns):
        return False
    return not normalized.replace("\\", "/").startswith(prefix)


def match_write_prefix(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    prefix = cat_def.get("write_path_exclude_prefix", "/repos/")
    allow_patterns = cat_def.get("write_path_allow_patterns", [])

    if hook == "beforeShellExecution" and "command" in event:
        command = _shell_command(event)
        if _TEMPFILE_WRITE_API.search(command):
            return ("write_outside", "tempfile default /tmp")
        outside = [
            path
            for path in _shell_write_destinations(command)
            if _path_is_write_outside(path, prefix=prefix, allow_patterns=allow_patterns)
        ]
        if outside:
            return ("write_outside", outside[0])
        return None

    if hook != "preToolUse":
        return None
    tool = _tool_name(event)
    write_tools = cat_def.get("write_tools", ["Write", "StrReplace", "Delete"])
    if tool not in write_tools:
        return None
    path = _file_path(event)
    if path and _path_is_write_outside(
        path, prefix=prefix, allow_patterns=allow_patterns
    ):
        return ("write_outside", path)
    return None


def match_read_prefix(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    prefix = cat_def.get("read_path_include_prefix", "/repos/")
    read_tools = cat_def.get("read_tools", ["Read", "Grep"])

    if hook == "beforeReadFile":
        path = normalize_path(_file_path(event))
        if path and not path.startswith(prefix):
            return ("read_outside", path)
        return None

    if hook != "preToolUse":
        return None
    tool = _tool_name(event)
    if tool not in read_tools:
        return None
    path = normalize_path(_file_path(event))
    if path and not path.startswith(prefix):
        return ("read_outside", path)
    return None


def match_path(
    cat_def: dict[str, Any],
    event: dict[str, Any],
    hook: str,
    category: str,
) -> Optional[tuple[str, str]]:
    path = normalize_path(_file_path(event))
    tool = _tool_name(event)
    patterns = cat_def.get("path_patterns", [])
    exclude = cat_def.get("path_exclude", [])
    write_tools = cat_def.get("write_tools", ["Write", "StrReplace", "Delete", "EditNotebook"])
    read_tools = cat_def.get("read_tools", ["Read", "Grep"])
    pub_suffixes = cat_def.get("read_allow_suffixes", [])
    shell_allow_pub = cat_def.get("shell_allow_pub_read", False)

    def path_hit(p: str) -> bool:
        return bool(p) and path_matches_any(p, patterns) and not path_excluded(p, exclude)

    if hook == "beforeReadFile" and path and path_hit(path):
        if pub_suffixes and _path_allowed_suffix(path, pub_suffixes):
            return None
        if category == "agent_config":
            return None
        subtype = (
            "policy"
            if category == "guard_policy"
            else "ssh"
            if category == "ssh_dir"
            else "credential"
        )
        return (subtype, path)

    if hook == "preToolUse" and path and path_hit(path):
        if category == "guard_policy":
            return ("policy", path)
        if category == "agent_config":
            if tool in write_tools:
                return ("agent_config", path)
            return None
        if tool in write_tools:
            return ("ssh" if category == "ssh_dir" else "credential", path)
        if not tool or tool in read_tools:
            if pub_suffixes and _path_allowed_suffix(path, pub_suffixes):
                return None
            subtype = "ssh" if category == "ssh_dir" else "credential"
            return (subtype, path)
        if tool in cat_def.get("tools", []):
            return ("credential", path)
        return None

    if hook == "beforeShellExecution" and "command" in event:
        cmd = _shell_command(event)
        if category == "guard_policy":
            if command_writes_policy_path(cmd, cat_def):
                return ("policy", "shell write to guard policy")
            if command_reads_policy_path(cmd, cat_def):
                return ("policy", "shell read of guard policy")
            return None
        if category == "agent_config":
            if command_writes_policy_path(cmd, cat_def):
                return ("agent_config", "shell write to agent config")
            if command_reads_policy_path(cmd, cat_def):
                return ("agent_config", "shell read of agent config")
            return None
        if category == "ssh_dir":
            if re.search(r"\bln\s+-[a-zA-Z]*s\b", cmd):
                return None
            if command_accesses_ssh(cmd) and not (
                shell_allow_pub and command_ssh_pub_read_only(cmd)
            ):
                return ("ssh", "shell .ssh access")
            return None
        if category == "credential_access":
            if command_ssh_pub_read_only(cmd):
                return None
            if _regex_any(cmd, cat_def.get("shell_patterns", [])):
                return ("credential", "shell credential access")
    return None


def match_secrets(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, _category: str
) -> Optional[tuple[str, str]]:
    allowed_tools = {t.lower() for t in cat_def.get("tools", ["Read", "Grep"])}
    if hook == "beforeReadFile":
        path = _file_path(event)
        if path:
            hit = detect_secret_values_path(path, cat_def, path_matches_any)
            if hit:
                return hit
    elif hook == "preToolUse":
        path = _file_path(event)
        tool = _tool_name_folded(event)
        if tool and tool not in allowed_tools:
            return None
        if path:
            hit = detect_secret_values_path(path, cat_def, path_matches_any)
            if hit:
                return hit
    if hook == "beforeShellExecution" and "command" in event:
        hit = detect_secret_values_shell(_shell_command(event), cat_def)
        if hit:
            return hit
    return None


MATCHERS = {
    "shell_regex": match_shell_regex,
    "destructive_fs": match_destructive_fs,
    "tool_name": match_tool_name,
    "path": match_path,
    "write_prefix": match_write_prefix,
    "read_prefix": match_read_prefix,
    "secrets": match_secrets,
}


def match_category(
    category: str,
    cat_def: dict[str, Any],
    event: dict[str, Any],
    hook: str,
) -> Optional[tuple[str, str]]:
    kind = cat_def.get("matcher")
    fn = MATCHERS.get(kind)
    if fn is None:
        return None
    return fn(cat_def, event, hook, category)


def _action_to_permission(
    action: str,
    hook: str,
    ask_unsupported_hooks: frozenset[str],
    *,
    defer_ask: bool = False,
    original_hook: str = "",
) -> str:
    if action == "allow":
        return "allow"
    if action == "ask":
        if (
            defer_ask
            and original_hook == "preToolUse"
            and hook in ASK_DEFERRAL_TARGET_HOOKS
        ):
            return "allow"
        if hook in ask_unsupported_hooks:
            return "deny"
        return "ask"
    return "deny"


def _build_message(
    *,
    action: str,
    hook: str,
    tool: str,
    detail: Optional[str],
    category: str,
    subtype: Optional[str],
    cat_def: dict[str, Any],
    profile_id: str,
    ask_unsupported_hooks: frozenset[str],
) -> str:
    operation = _operation_label(hook, tool)
    target = detail or category
    intention = _intention(category, subtype, cat_def)

    if action == "block" or (action == "ask" and hook in ask_unsupported_hooks):
        return BLOCK_MESSAGE.format(
            operation=operation, target=target, intention=intention
        )
    if action == "ask":
        return ASK_MESSAGE.format(
            operation=operation, target=target, intention=intention
        )
    return (
        f"Agent attempted `{category}` ({target}) — requires attention "
        f"(profile: {profile_id})."
    )


def write_audit(
    category: str,
    subtype: Optional[str],
    detail: Optional[str],
    action: str,
    audit_path: Path = AUDIT_LOG,
) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sub = f":{subtype}" if subtype else ""
    detail_part = f" detail={detail}" if detail else ""
    line = f"{ts} category={category}{sub} action={action}{detail_part}\n"
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(line)


def evaluate(
    event: dict[str, Any],
    *,
    profile_id: Optional[str] = None,
    overrides: Optional[dict[str, Any]] = None,
    config_root: Optional[Path] = None,
    original_hook: Optional[str] = None,
    defer_ask: bool = False,
) -> GuardResult:
    root = config_root or config_root_default()
    security = load_security_config(root)
    active = profile_id or security.get("active_profile", DEFAULT_PROFILE)
    user_overrides = overrides if overrides is not None else security.get("overrides", {})

    try:
        profile = load_profile(active, root)
        categories_data = load_categories(root)
        categories_def = category_definitions(categories_data)
        match_order = categories_data.get("match_order", list(categories_def.keys()))
        ask_unsupported = frozenset(categories_data.get("ask_unsupported_hooks", []))
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
        return GuardResult(
            permission="deny",
            user_message="Catacombs security guard failed to load configuration — denying (fail closed).",
            agent_message="Catacombs security guard failed to load configuration — denying (fail closed).",
        )

    hook = str(event.get("hook") or original_hook or "")
    orig = original_hook or hook
    if not hook:
        return GuardResult(permission="allow")

    if event.get("command"):
        event = {**event, "command": normalize_command_obfuscation(str(event["command"]))}

    merged = merge_category_settings(profile, user_overrides)
    tool = _tool_name(event)

    hits: list[tuple[int, str, str, str, str, bool, dict[str, Any]]] = []
    for order_idx, category in enumerate(match_order):
        settings = merged.get(category)
        if not settings or not settings.get("enabled", False):
            continue
        cat_def = categories_def.get(category, {})
        hit = match_category(category, cat_def, event, hook)
        if not hit:
            continue

        subtype, detail = hit
        action = settings.get("action", "block")
        notify = bool(settings.get("notify", False))
        if action == "block":
            notify = True

        permission = _action_to_permission(
            action,
            hook,
            ask_unsupported,
            defer_ask=defer_ask,
            original_hook=orig,
        )
        hits.append(
            (order_idx, category, subtype, detail, permission, notify, cat_def)
        )

    if not hits:
        return GuardResult(permission="allow")

    best_rank = max(PERMISSION_RANK.get(row[4], 0) for row in hits)
    tier = [row for row in hits if PERMISSION_RANK.get(row[4], 0) == best_rank]
    if any(row[1] == "destructive_fs" for row in tier):
        write_outside = [row for row in tier if row[1] == "file_write_outside_repos"]
        if write_outside:
            _, category, subtype, detail, permission, notify, cat_def = min(
                write_outside, key=lambda row: row[0]
            )
        else:
            _, category, subtype, detail, permission, notify, cat_def = min(
                tier, key=lambda row: row[0]
            )
    else:
        _, category, subtype, detail, permission, notify, cat_def = min(
            tier, key=lambda row: row[0]
        )
    action = merged[category].get("action", "block")

    user_message = None
    agent_message = None
    if permission != "allow" or notify:
        user_message = _build_message(
            action=action,
            hook=orig if orig == "preToolUse" else hook,
            tool=tool,
            detail=detail,
            category=category,
            subtype=subtype,
            cat_def=cat_def,
            profile_id=active,
            ask_unsupported_hooks=ask_unsupported,
        )
        if permission != "allow":
            agent_message = user_message

    if permission != "allow" or notify:
        write_audit(category, subtype, detail, action)

    return GuardResult(
        permission=permission,
        category=category,
        subtype=subtype,
        user_message=user_message,
        agent_message=agent_message,
        notify=notify,
        matched_detail=detail,
    )


def _scan_output_for_secrets(text: str, keywords: list[str]) -> Optional[str]:
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", line.strip())
        if m and _var_name_sensitive(m.group(1), keywords):
            return m.group(1)
    return None


def evaluate_audit(
    event: dict[str, Any], *, config_root: Optional[Path] = None
) -> AuditResult:
    root = config_root or config_root_default()
    try:
        categories = load_categories(root)
    except (OSError, json.JSONDecodeError):
        return AuditResult()

    secret_def = categories.get("secret_values", {})
    keywords = secret_def.get("env_var_name_keywords", [])

    path = str(event.get("file_path") or event.get("path") or "")
    output = str(event.get("output") or event.get("result") or event.get("content") or "")

    detail: Optional[str] = None
    subtype: Optional[str] = None

    if path:
        hit = detect_secret_values_path(path, secret_def, path_matches_any)
        if hit:
            subtype, detail = hit

    if not detail and output:
        var = _scan_output_for_secrets(output, keywords)
        if var:
            subtype, detail = "env_var", var
        elif re.search(r"\.env", output) and re.search(r"=", output):
            subtype, detail = "env_file", ".env content in output"

    if not detail:
        return AuditResult(audit_log_path=AUDIT_LOG)

    write_audit("secret_values", subtype, detail, "audit_warn")
    msg = (
        f"Catacombs security audit: possible secret exposure detected "
        f"({subtype}: {detail}). Review the agent output — values are not logged."
    )
    return AuditResult(
        additional_context=msg,
        user_message=msg,
        audit_log_path=AUDIT_LOG,
    )


def guard_main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"permission": "deny", "user_message": "Invalid hook input JSON."}
        print(json.dumps(payload))
        return 1

    hook = normalize_hook_name(event)
    env_hook = os.environ.get("CATACOMBS_HOOK")
    if env_hook and not hook:
        hook = env_hook
    if hook:
        event["hook"] = hook
        log_resolved_hook(hook, event)

    if hook in OBSERVATIONAL_HOOKS:
        print(json.dumps({"permission": "allow"}))
        return 0

    original_hook = hook or "preToolUse"
    eval_event = event
    effective_hook = original_hook
    defer_ask = False

    if original_hook == "preToolUse":
        effective_hook, eval_event = dispatch_pretooluse(event)
        eval_event["hook"] = effective_hook
        defer_ask = True
    else:
        eval_event["hook"] = original_hook

    if effective_hook == "beforeShellExecution" and eval_event.get("command"):
        eval_event["command"] = normalize_command_obfuscation(eval_event["command"])

    result = evaluate(
        eval_event,
        original_hook=original_hook,
        defer_ask=defer_ask,
    )
    print(json.dumps(result.to_json()))
    return 0


def audit_main() -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        print("{}")
        return 0

    result = evaluate_audit(event)
    print(json.dumps(result.to_json()))
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "guard"
    if mode == "audit":
        return audit_main()
    return guard_main()


if __name__ == "__main__":
    raise SystemExit(main())
