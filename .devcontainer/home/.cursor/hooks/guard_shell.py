#!/usr/bin/env python3
"""Shell command parsing: write destinations, redirects, interpreter write APIs."""

from __future__ import annotations

import re
from typing import Optional

from guard_obfuscation import normalize_command_obfuscation

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
READ_SHELL_CMDS = re.compile(
    r"(?:^|[;&|]\s*)(?:cat|head|tail|less|more|grep|awk|sed|python3?|node|php)\b",
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
_TEMPFILE_WRITE_API = re.compile(
    r"\b(?:tempfile\.(?:mkstemp|NamedTemporaryFile|TemporaryDirectory)|mkstemp\s*\()",
    re.IGNORECASE,
)
_DEV_SINKS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr"})
SSH_PATH_RE = re.compile(r"(?:^|[/\s'\"~])\.ssh(?:/|\b)")


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


def _is_excluded_write_target(path: str) -> bool:
    normalized = path.replace("\\", "/").rstrip("/")
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


def interpreter_write_paths(command: str) -> list[str]:
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


def shell_write_destinations(command: str) -> list[str]:
    """Collect write targets from redirects, shell write cmds, and interpreter APIs."""
    normalized = command.replace("\\", "/")
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
    for path in interpreter_write_paths(normalized):
        if not _is_excluded_write_target(path):
            paths.append(path)
    return paths


def command_accesses_ssh(command: str) -> bool:
    return bool(SSH_PATH_RE.search(command.replace("\\", "/")))


def command_ssh_pub_read_only(command: str) -> bool:
    n = command.replace("\\", "/")
    if not command_accesses_ssh(n):
        return False
    if SHELL_WRITE_CMD.search(n) or REDIRECT_TO_SSH.search(n):
        return False
    stripped = re.sub(r"[^\s;'\"|]*\.ssh[^\s;'\"|]*\.pub", "", n)
    return not command_accesses_ssh(stripped)


def fold_command(command: str) -> str:
    return normalize_command_obfuscation(command)
