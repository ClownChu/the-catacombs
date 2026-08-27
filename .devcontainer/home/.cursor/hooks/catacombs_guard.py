#!/usr/bin/env python3
"""Catacombs security guard — profile-driven policy enforcement for Cursor hooks."""

from __future__ import annotations

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
SSH_PATH_RE = re.compile(r"(?:^|[/\s'\"~])\.ssh(?:/|\b)")


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


def _tool_name(event: dict[str, Any]) -> str:
    return str(event.get("tool_name") or event.get("tool") or "")


def _file_path(event: dict[str, Any]) -> str:
    return str(
        event.get("file_path")
        or event.get("path")
        or event.get("arguments", {}).get("path")
        or event.get("arguments", {}).get("target_file")
        or ""
    )


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


def match_shell_regex(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    if hook != "beforeShellExecution" or "command" not in event:
        return None
    patterns = cat_def.get("shell_patterns", [])
    command = event["command"]
    if category == "network_egress" and ".ssh/" in command.replace("\\", "/"):
        return None
    if _regex_any(command, patterns):
        return (category, command[:80])
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


def match_write_prefix(
    cat_def: dict[str, Any], event: dict[str, Any], hook: str, category: str
) -> Optional[tuple[str, str]]:
    if hook != "preToolUse":
        return None
    tool = _tool_name(event)
    write_tools = cat_def.get("write_tools", ["Write", "StrReplace", "Delete"])
    if tool not in write_tools:
        return None
    path = _file_path(event)
    prefix = cat_def.get("write_path_exclude_prefix", "/repos/")
    allow_patterns = cat_def.get("write_path_allow_patterns", [])
    if path:
        normalized = normalize_path(path)
        if allow_patterns and path_matches_any(normalized, allow_patterns):
            return None
        if not normalized.replace("\\", "/").startswith(prefix):
            return ("write_outside", path)
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
        cmd = event["command"]
        if category == "guard_policy":
            if command_writes_policy_path(cmd, cat_def):
                return ("policy", "shell write to guard policy")
            if command_reads_policy_path(cmd, cat_def):
                return ("policy", "shell read of guard policy")
            return None
        if category == "ssh_dir":
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
    if hook in ("beforeReadFile", "preToolUse"):
        path = _file_path(event)
        tool = _tool_name(event)
        if tool and tool not in cat_def.get("tools", ["Read", "Grep"]):
            return None
        if path:
            hit = detect_secret_values_path(path, cat_def, path_matches_any)
            if hit:
                return hit
    if hook == "beforeShellExecution" and "command" in event:
        hit = detect_secret_values_shell(event["command"], cat_def)
        if hit:
            return hit
    return None


MATCHERS = {
    "shell_regex": match_shell_regex,
    "tool_name": match_tool_name,
    "path": match_path,
    "write_prefix": match_write_prefix,
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
    action: str, hook: str, ask_unsupported_hooks: frozenset[str]
) -> str:
    if action == "allow":
        return "allow"
    if action == "ask":
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

    hook = event.get("hook")
    if not hook:
        return GuardResult(
            permission="deny",
            user_message="Catacombs security guard: missing hook in event.",
            agent_message="Catacombs security guard: missing hook in event.",
        )

    merged = merge_category_settings(profile, user_overrides)
    tool = _tool_name(event)

    for category in match_order:
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

        permission = _action_to_permission(action, hook, ask_unsupported)

        user_message = None
        agent_message = None
        if permission != "allow" or notify:
            user_message = _build_message(
                action=action,
                hook=hook,
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

    return GuardResult(permission="allow")


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

    hook = os.environ.get("CATACOMBS_HOOK")
    if hook:
        event["hook"] = hook

    result = evaluate(event)
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
