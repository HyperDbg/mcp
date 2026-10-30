"""
 * @file test_tools_gating.py
 * @brief Verify --read-only does not register destructive tools.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")  # requires the MCP SDK; skipped if absent

from hyperdbg_mcp.tools import register_tools  # noqa: E402

# Every tool that can mutate the target - none may appear under --read-only.
_MUTATING = {"hd_exec_command", "hd_bp_set", "hd_mem_write", "hd_reg_write", "hd_script_run"}
# Non-mutating tools that must remain available under --read-only.
_READ_ONLY_SAFE = {
    "hd_mem_read", "hd_reg_read_all", "hd_reg_read", "hd_eval", "hd_disasm",
    "hd_list_modules", "hd_status", "hd_exec_continue", "hd_exec_pause", "hd_exec_step",
    "hd_script_eval", "hd_script_check", "hd_script_template", "hd_script_cookbook",
}


class FakeMCP:
    """Records tool names passed to the @mcp.tool(...) decorator."""

    def __init__(self):
        self.names: list[str] = []

    def tool(self, **kwargs):
        def decorator(fn):
            self.names.append(kwargs.get("name", fn.__name__))
            return fn

        return decorator


def test_read_only_hides_all_mutating_tools():
    mcp = FakeMCP()
    register_tools(mcp, read_only=True)
    # Regression guard for review C1: no mutating tool (esp. hd_exec_command)
    # may be registered in read-only mode.
    assert _MUTATING.isdisjoint(mcp.names)
    assert _READ_ONLY_SAFE.issubset(set(mcp.names))


def test_full_mode_registers_mutating_tools():
    mcp = FakeMCP()
    register_tools(mcp, read_only=False)
    assert _MUTATING.issubset(set(mcp.names))
    assert _READ_ONLY_SAFE.issubset(set(mcp.names))
