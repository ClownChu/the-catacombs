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
