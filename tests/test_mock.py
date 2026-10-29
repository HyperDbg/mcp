"""
 * @file test_mock.py
 * @brief Verify the --mock backend satisfies the tool interface end-to-end.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402

from hyperdbg_mcp import server  # noqa: E402
from hyperdbg_mcp.mock import MockSession  # noqa: E402


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")


async def test_mock_backend_runs_read_tools(tmp_path):
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=MockSession,
    )
    async with Client(srv) as client:
        status = await client.call_tool("hd_status", {})
        regs = await client.call_tool("hd_reg_read_all", {})
        mem = await client.call_tool("hd_mem_read", {"address": "0x1000", "size": 4})
    assert "[mock]" in _text(status)
    assert "0x140001000" in _text(regs).lower()  # mock rip default
    assert "BEGIN UNTRUSTED MEMORY" in _text(mem)
