#!/usr/bin/env python3
"""Secret-value heuristics for the Catacombs security guard (not stdlib secrets)."""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

from guard_shell import READ_SHELL_CMDS

_ENV_VAR_RE = re.compile(r"\$[{]?([A-Za-z_][A-Za-z0-9_]*)[}]?")
_READ_INTERPRETER = re.compile(
    r"open\s*\(|readFileSync|readFile\s*\(|file_get_contents|Path\s*\(",
    re.IGNORECASE,
)
_READ_SHELL_VERBS = re.compile(
    r"\b(?:cat|head|tail|less|more|grep|awk|sed)\b",
    re.IGNORECASE,
)
_QUOTED_STRING = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_PATH_TOKEN = re.compile(r"(?<![\w.])(\.env(?:\.\w+)?)|(?<![\w./~])(/[\w./~%-]+)")
_PATH_IN_TEXT = re.compile(
    r"(~(?:/[\w./~%-]+)?|/(?:[\w./~%-]+)|(?<![\w])\.env(?:[\w./-]*)?)"
)


def _looks_like_path_literal(text: str) -> bool:
    return bool(
        text.startswith(("/", "~", "./", "../")) or text.startswith(".env")
    )


def _extract_shell_path_candidates(command: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        if path and path not in seen:
            seen.add(path)
            paths.append(path)

    for match in _QUOTED_STRING.finditer(command):
        text = match.group(1) or match.group(2)
        if not text:
            continue
        if _looks_like_path_literal(text):
            add(text)
            continue
        for sub in _PATH_IN_TEXT.finditer(text):
            add(sub.group(0))
    for match in _PATH_TOKEN.finditer(command):
        add(match.group(1) or match.group(2) or "")
    return paths


def _var_name_sensitive(name: str, keywords: list[str]) -> bool:
    upper = name.upper()
    return any(kw in upper for kw in keywords)


def detect_secret_values_path(
    path: str,
    cat_def: dict[str, Any],
    path_matches_any: Callable[[str, list[str]], bool],
) -> Optional[tuple[str, str]]:
    normalized = path.replace("\\", "/")
    file_paths = cat_def.get("env_file_paths", [])
    excludes = cat_def.get("env_file_path_exclude", [])
    if path_matches_any(normalized, file_paths) and not path_matches_any(
        normalized, excludes
    ):
        return ("env_file", path)
    return None


def _extract_sensitive_var(command: str, keywords: list[str]) -> Optional[str]:
    for match in _ENV_VAR_RE.finditer(command):
        name = match.group(1)
        if _var_name_sensitive(name, keywords):
            return name

    for pattern in (
        r"process\.env\.(\w+)",
        r"process\.env\[['\"](\w+)['\"]\]",
        r"os\.environ\[['\"](\w+)['\"]\]",
        r"os\.getenv\s*\(\s*['\"](\w+)['\"]",
        r"os\.environ\.get\s*\(\s*['\"](\w+)['\"]",
        r"getenv\s*\(\s*['\"](\w+)['\"]",
        r"\$_ENV\[['\"](\w+)['\"]\]",
        r"\$_SERVER\[['\"](\w+)['\"]\]",
    ):
        for match in re.finditer(pattern, command):
            name = match.group(1)
            if _var_name_sensitive(name, keywords):
                return name
    return None


def _command_is_keyed_env_access(command: str) -> bool:
    keyed_patterns = (
        r"os\.getenv\s*\(\s*['\"][^'\"]+['\"]",
        r"os\.environ\.get\s*\(\s*['\"][^'\"]+['\"]",
        r"os\.environ\[['\"][^'\"]+['\"]\]",
        r"getenv\s*\(\s*['\"][^'\"]+['\"]",
        r"process\.env\.[A-Za-z_]",
        r"process\.env\[['\"][^'\"]+['\"]\]",
        r"\$_ENV\[['\"][^'\"]+['\"]\]",
        r"\$_SERVER\[['\"][^'\"]+['\"]\]",
    )
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in keyed_patterns)


def _command_is_read_ish(command: str) -> bool:
    return bool(
        READ_SHELL_CMDS.search(command)
        or _READ_SHELL_VERBS.search(command)
        or _READ_INTERPRETER.search(command)
    )


def detect_secret_values_shell(
    command: str,
    cat_def: dict[str, Any],
    path_matches_any: Callable[[str, list[str]], bool],
) -> Optional[tuple[str, str]]:
    keywords = cat_def.get("env_var_name_keywords", [])

    for pattern in cat_def.get("env_dump_shell_patterns", []):
        if re.search(pattern, command, re.IGNORECASE):
            return ("env_dump", "environment dump")

    if _command_is_read_ish(command):
        for candidate in _extract_shell_path_candidates(command):
            hit = detect_secret_values_path(candidate, cat_def, path_matches_any)
            if hit:
                return hit

    var = _extract_sensitive_var(command, keywords)
    if var:
        return ("env_var", var)

    if _command_is_keyed_env_access(command):
        return None

    for pattern in cat_def.get("env_access_code_patterns", []):
        if re.search(pattern, command, re.IGNORECASE):
            var = _extract_sensitive_var(command, keywords)
            if var:
                return ("env_var", var)
            return ("env_dump", "environment dump")

    return None
