#!/usr/bin/env python3
"""Secret-value heuristics for the Catacombs security guard (not stdlib secrets)."""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

_ENV_VAR_RE = re.compile(r"\$[{]?([A-Za-z_][A-Za-z0-9_]*)[}]?")
_READ_SHELL_CMDS = re.compile(
    r"(?:^|[;&|]\s*)(?:cat|head|tail|less|more|grep|awk|sed|python3?|node|php)\b",
    re.IGNORECASE,
)


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
        r"getenv\s*\(\s*['\"](\w+)['\"]",
        r"\$_ENV\[['\"](\w+)['\"]\]",
        r"\$_SERVER\[['\"](\w+)['\"]\]",
    ):
        for match in re.finditer(pattern, command):
            name = match.group(1)
            if _var_name_sensitive(name, keywords):
                return name
    return None


def detect_secret_values_shell(
    command: str, cat_def: dict[str, Any]
) -> Optional[tuple[str, str]]:
    keywords = cat_def.get("env_var_name_keywords", [])

    for pattern in cat_def.get("env_dump_shell_patterns", []):
        if re.search(pattern, command, re.IGNORECASE):
            return ("env_dump", "environment dump")

    for pattern in cat_def.get("env_file_shell_patterns", []):
        if re.search(pattern, command, re.IGNORECASE):
            return ("env_file", ".env file via shell")

    var = _extract_sensitive_var(command, keywords)
    if var:
        return ("env_var", var)

    for pattern in cat_def.get("env_access_code_patterns", []):
        if re.search(pattern, command, re.IGNORECASE):
            var = _extract_sensitive_var(command, keywords)
            if var:
                return ("env_var", var)
            return ("env_var", "sensitive environment access")

    return None
