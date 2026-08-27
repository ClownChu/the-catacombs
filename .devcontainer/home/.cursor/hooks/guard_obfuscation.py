#!/usr/bin/env python3
"""Fold obfuscated shell strings so guard matchers see real paths and env access."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

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
_CODECS_HEX_DECODE = re.compile(
    r"codecs\.decode\s*\(\s*(['\"])([0-9a-fA-F]*)\1\s*,\s*['\"]hex['\"]\s*\)",
    re.IGNORECASE,
)
_MULTI_CHAR_CODE = re.compile(
    r"(?:String\.fromCharCode|String\.fromCodePoint)\s*\(\s*"
    r"((?:0x[0-9a-fA-F]+|\d+)\s*,\s*)+(0x[0-9a-fA-F]+|\d+)\s*\)",
    re.IGNORECASE,
)
_BYTES_INT_LIST = re.compile(
    r"bytes\s*\(\s*\[([^\]]+)\]\s*\)(?:\s*\.\s*decode\s*\([^)]*\))?",
    re.IGNORECASE,
)
_JOIN_CHR_LIST = re.compile(
    r"""(['"])\1\s*\.\s*join\s*\(\s*chr\s*\(\s*c\s*\)\s+for\s+c\s+in\s+\[([^\]]+)\]\s*\)""",
    re.IGNORECASE,
)
_REVERSE_SLICE = re.compile(
    r"""(['"])([^'"]+)\1\s*\[\s*::-1\s*\]"""
)
_PATH_LIKE_INT_LIST = re.compile(r"\[(\d+(?:\s*,\s*\d+)+)\]")
_PATH_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./_%-~"
)


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


def _is_path_like_text(text: str) -> bool:
    return text and all(c in _PATH_CHARS for c in text)


def _decode_int_codepoints(list_content: str) -> Optional[str]:
    nums = re.findall(r"(0x[0-9a-fA-F]+|\d+)", list_content)
    if not nums:
        return None
    try:
        chars = "".join(chr(int(n, 0)) for n in nums)
    except (ValueError, OverflowError):
        return None
    if not _is_path_like_text(chars):
        return None
    return chars


def _replace_multi_char_codes(command: str) -> str:
    def repl(match: re.Match[str]) -> str:
        nums = re.findall(r"(0x[0-9a-fA-F]+|\d+)", match.group(0))
        try:
            chars = "".join(chr(int(n, 0)) for n in nums)
        except (ValueError, OverflowError):
            return match.group(0)
        return _quoted_literal(chars)

    return _MULTI_CHAR_CODE.sub(repl, command)


def _replace_bytes_int_lists(command: str) -> str:
    def repl(match: re.Match[str]) -> str:
        decoded = _decode_int_codepoints(match.group(1))
        if decoded is None:
            return match.group(0)
        return _quoted_literal(decoded)

    return _BYTES_INT_LIST.sub(repl, command)


def _replace_join_chr_lists(command: str) -> str:
    def repl(match: re.Match[str]) -> str:
        decoded = _decode_int_codepoints(match.group(2))
        if decoded is None:
            return match.group(0)
        return _quoted_literal(decoded)

    return _JOIN_CHR_LIST.sub(repl, command)


def _replace_reverse_slices(command: str) -> str:
    def repl(match: re.Match[str]) -> str:
        quote, text = match.group(1), match.group(2)
        return f"{quote}{text[::-1]}{quote}"

    return _REVERSE_SLICE.sub(repl, command)


def _replace_path_like_int_lists(command: str) -> str:
    def repl(match: re.Match[str]) -> str:
        decoded = _decode_int_codepoints(match.group(1))
        if decoded is None:
            return match.group(0)
        return _quoted_literal(decoded)

    return _PATH_LIKE_INT_LIST.sub(repl, command)


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
        updated = _CODECS_HEX_DECODE.sub(hex_repl, updated)
        updated = _B64_DECODE_CALL.sub(b64_repl, updated)
        updated = _BUFFER_B64_CALL.sub(b64_repl, updated)
        if updated == result:
            break
        result = updated
    return result


def _rewrite_env_access_obfuscation(command: str) -> str:
    result = command
    replacements = [
        (
            r"getattr\s*\(\s*os\s*,\s*['\"]environ['\"]\s*\)",
            "os.environ",
        ),
        (
            r"(?:object\.)?__getattribute__\s*\(\s*['\"]environ['\"]\s*\)",
            "os.environ",
        ),
        (
            r"object\.__getattribute__\s*\(\s*os\s*,\s*['\"]environ['\"]\s*\)",
            "os.environ",
        ),
        (
            r"os\.__getattribute__\s*\(\s*['\"]environ['\"]\s*\)",
            "os.environ",
        ),
        (
            r"os\.__dict__\s*\[\s*['\"]environ['\"]\s*\]",
            "os.environ",
        ),
        (
            r"os\.__dict__\.\s*get\s*\(\s*['\"]environ['\"]\s*\)",
            "os.environ",
        ),
        (
            r"vars\s*\(\s*os\s*\)\s*\[\s*['\"]environ['\"]\s*\]",
            "os.environ",
        ),
        (
            r"importlib\.import_module\s*\(\s*['\"]os['\"]\s*\)\s*\.\s*environ",
            "os.environ",
        ),
        (
            r"(?<![\w.])o\.environ\b",
            "os.environ",
        ),
        (
            r"posix\.environ\b",
            "os.environ",
        ),
        (
            r"process\s*\[\s*['\"]env['\"]\s*\]",
            "process.env",
        ),
    ]
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def normalize_command_obfuscation(command: str) -> str:
    """Fold concat strings and chr()/fromCharCode()/\\xNN so matchers see real paths."""
    # ponytail: XOR/zlib/rot13 and computed-only paths (no argv-visible literals) are the ceiling.
    result = _replace_encoded_literals(command)
    result = _replace_multi_char_codes(result)
    result = _replace_bytes_int_lists(result)
    result = _replace_join_chr_lists(result)
    result = _replace_reverse_slices(result)
    result = _replace_path_like_int_lists(result)
    while True:
        updated = _CHR_LITERAL.sub(
            lambda m: _quoted_literal(chr(int(m.group(1), 0))), result
        )
        if updated == result:
            break
        result = updated
    result = _HEX_ESCAPE.sub(lambda m: _quoted_literal(chr(int(m.group(1), 16))), result)

    def fold_quoted_concat(match: re.Match[str]) -> str:
        s1, s2 = match.group(2), match.group(4)
        return _quoted_literal(s1 + s2)

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
