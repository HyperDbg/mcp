"""
 * @file test_addr.py
 * @brief parse_addr preserves full 64-bit precision (the JSON-boundary bug fix).
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from hyperdbg_mcp.errors import HyperDbgError  # noqa: E402
from hyperdbg_mcp.toolkit import parse_addr  # noqa: E402


def test_hex_string_keeps_full_64bit_precision():
    # This kernel address has low bits that float64 cannot represent exactly;
    # a str parse must return it byte-for-byte.
    assert parse_addr("0xfffff803927a12f2") == 0xFFFFF803927A12F2


def test_decimal_string_and_int_and_empty():
    assert parse_addr("4096") == 4096
    assert parse_addr("0x1000") == 0x1000
    assert parse_addr(0x1000) == 0x1000  # in-process callers may still pass int
    assert parse_addr("") == 0


def test_invalid_raises():
    with pytest.raises(HyperDbgError):
        parse_addr("notanumber")
