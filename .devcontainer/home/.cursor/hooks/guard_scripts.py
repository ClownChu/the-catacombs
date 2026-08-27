#!/usr/bin/env python3
"""Inline executed script bodies into shell commands for guard classification."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Optional

from guard_obfuscation import normalize_command_obfuscation

_MAX_BODY_BYTES = 65536
_SOURCE_SUFFIXES = frozenset(
    {".py", ".js", ".mjs", ".cjs", ".php", ".sh", ".bash", ".zsh"}
)
_INLINE_FLAGS = frozenset({"-c", "-e", "-r", "-m"})
_INTERPRETER_CMD = re.compile(
    r"(?:^|[;&|]\s*)"
    r"(python3?(?:\.\d+)?|node(?:js)?|php(?:\d+\.\d+)?|bash|sh|dash|zsh)"
    r"(?:\s+|$)",
    re.IGNORECASE,
)
_EXEC_OPEN = re.compile(
    r"exec\s*\(\s*open\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_READ_FILE_SYNC = re.compile(
    r"readFileSync\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def _looks_like_source(path: Path) -> bool:
    return path.suffix.lower() in _SOURCE_SUFFIXES


def _read_text_body(path: Path) -> Optional[str]:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(_MAX_BODY_BYTES + 1)
    except OSError:
        return None
    if b"\x00" in chunk[:4096]:
        return None
    if len(chunk) > _MAX_BODY_BYTES:
        chunk = chunk[:_MAX_BODY_BYTES]
    try:
        return chunk.decode("utf-8")
    except UnicodeDecodeError:
        return chunk.decode("latin-1", errors="replace")


def _resolve_script_path(raw: str, cwd: Optional[Path]) -> Optional[Path]:
    candidate = Path(raw)
    if not candidate.is_absolute() and cwd is not None:
        candidate = cwd / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return None
    if not resolved.is_file():
        return None
    return resolved


def _interpreter_script_path(segment: str, cwd: Optional[Path]) -> Optional[Path]:
    match = _INTERPRETER_CMD.search(segment)
    if not match:
        return None
    rest = segment[match.end():].strip()
    if not rest:
        return None
    tokens = re.finditer(r'"([^"]*)"|\'([^\']*)\'|(\S+)', rest)
    args = [match.group(match.lastindex) for match in tokens]
    idx = 0
    while idx < len(args):
        token = args[idx]
        if token in _INLINE_FLAGS:
            return None
        if token.startswith("-") and token not in _INLINE_FLAGS:
            idx += 1
            continue
        candidate = Path(token)
        if not candidate.is_absolute() and cwd is not None:
            candidate = cwd / candidate
        if not _looks_like_source(candidate):
            return None
        return _resolve_script_path(token, cwd)
    return None


def _one_hop_script_paths(command: str, cwd: Optional[Path]) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for pattern in (_EXEC_OPEN, _READ_FILE_SYNC):
        for match in pattern.finditer(command):
            raw = match.group(1)
            candidate = Path(raw)
            if not _looks_like_source(candidate):
                continue
            resolved = _resolve_script_path(raw, cwd)
            if resolved is None or resolved in seen:
                continue
            seen.add(resolved)
            paths.append(resolved)
    return paths


def _collect_script_paths(command: str, cwd: Optional[Path]) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()

    def add(path: Optional[Path]) -> None:
        if path is None or path in seen:
            return
        seen.add(path)
        paths.append(path)

    for segment in re.split(r"[;&|]", command):
        add(_interpreter_script_path(segment.strip(), cwd))
    for path in _one_hop_script_paths(command, cwd):
        add(path)
    return paths


def enrich_shell_command(
    command: str,
    *,
    cwd: Optional[str] = None,
    skip_body_for_path: Optional[Callable[[str], bool]] = None,
) -> str:
    """Append resolved script paths and folded bodies for interpreter+file invocations."""
    cwd_path = Path(cwd).resolve() if cwd else None
    fragments: list[str] = [command]

    for script_path in _collect_script_paths(command, cwd_path):
        resolved_text = str(script_path)
        fragments.append(resolved_text)
        if skip_body_for_path and skip_body_for_path(resolved_text):
            continue
        body = _read_text_body(script_path)
        if body:
            fragments.append(normalize_command_obfuscation(body))

    if len(fragments) == 1:
        return command
    return " ".join(fragments)
