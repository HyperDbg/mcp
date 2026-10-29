"""
 * @file test_integration.py
 * @brief End-to-end MCP protocol tests: in-memory client <-> server with an
 *        injected fake session (no libhyperdbg required).
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp.types import ElicitResult  # noqa: E402

from hyperdbg_mcp import server  # noqa: E402


class FakeSession:
    """Stand-in for HyperDbgSession - no DLL, deterministic outputs."""

    def __init__(self):
        self.connected = False

    def connect(self):
        self.connected = True

    def close(self):
        self.connected = False

    def read_all_registers(self):
        return {"rax": 0xDEAD, "rip": 0x1000}

    def read_memory(self, address, size, *, pid=0, virtual=True):
        return (b"MZ" + b"\x00" * size)[:size]

    def read_register(self, name):
        return 0x41

    def eval_expression(self, expr):
        return 0x7

    def run_command(self, command):
        return f"fake-output:{command}"

    def write_register(self, name, value):  # pragma: no cover - denied before call
        raise AssertionError("write must not run without confirmation")


def _build(read_only: bool, tmp_path):
    return server.build_server(
        read_only=read_only,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=FakeSession,
    )


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")


async def test_read_only_tool_list(tmp_path):
    srv = _build(read_only=True, tmp_path=tmp_path)
    async with Client(srv) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert {"hd_mem_read", "hd_reg_read_all", "hd_disasm"} <= names
    assert {"hd_mem_write", "hd_reg_write", "hd_script_run", "hd_exec_command"}.isdisjoint(names)


async def test_reg_read_all_returns_registers(tmp_path):
    srv = _build(read_only=False, tmp_path=tmp_path)
    async with Client(srv) as client:
        result = await client.call_tool("hd_reg_read_all", {})
    assert "0xdead" in _text(result).lower()


async def test_mem_read_is_untrusted_wrapped(tmp_path):
    srv = _build(read_only=False, tmp_path=tmp_path)
    async with Client(srv) as client:
        result = await client.call_tool("hd_mem_read", {"address": "0x1000", "size": 8})
    assert "BEGIN UNTRUSTED MEMORY" in _text(result)


async def test_write_denied_without_elicitation(tmp_path):
    # The default in-memory client advertises no elicitation capability, so the
    # confirmation must fail closed and the write must never reach the session.
    srv = _build(read_only=False, tmp_path=tmp_path)
    async with Client(srv) as client:
        result = await client.call_tool("hd_reg_write", {"name": "rax", "value": "0x0"})
    # Nobody was asked, so don't blame the user: name the client and the opt-in.
    assert "cannot ask the user to confirm" in _text(result)
    assert "--assume-consent" in _text(result)


def _answer(confirm: bool):
    async def elicit(_context, params):
        assert "set rax = 0x5" in params.message
        return ElicitResult(action="accept", content={"confirm": confirm})

    return elicit


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
@pytest.mark.parametrize("confirm", [True, False])
async def test_write_confirmed_via_elicitation(tmp_path, mode, confirm):
    # 2026-07-28: confirmation rides InputRequiredResult and the client retries;
    # legacy: a synchronous elicitation/create round-trip. Same outcome either way.
    writes = []
    session = FakeSession()
    session.write_register = lambda name, value: writes.append((name, value))
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )
    async with Client(srv, mode=mode, elicitation_callback=_answer(confirm)) as client:
        result = await client.call_tool("hd_reg_write", {"name": "rax", "value": "0x5"})
    if confirm:
        assert "Set rax = 0x5." in _text(result) and writes == [("rax", 5)]
    else:
        assert "Denied by user." in _text(result) and writes == []


async def test_assume_consent_runs_mutating_tools_without_elicitation(tmp_path):
    # A client that cannot elicit still needs the destructive surface:
    # --assume-consent pre-approves it. The default build must keep failing
    # closed - see test_write_denied_without_elicitation.
    writes = []
    session = FakeSession()
    session.write_register = lambda name, value: writes.append((name, value))
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
        assume_consent=True,
    )
    async with Client(srv) as client:
        wrote = await client.call_tool("hd_reg_write", {"name": "rax", "value": "0x5"})
        ran = await client.call_tool("hd_exec_command", {"command": ".status"})
    assert "Set rax = 0x5." in _text(wrote) and writes == [("rax", 5)]
    assert "fake-output:.status" in _text(ran)


async def test_full_tool_surface_present(tmp_path):
    srv = _build(read_only=False, tmp_path=tmp_path)
    async with Client(srv) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    # A sampling across every new domain module.
    assert {
        "hd_mem_display", "hd_sym_examine", "hd_va2pa", "hd_stack", "hd_bp_list",
        "hd_cpuid", "hd_hook_syscall", "hd_hook_ept", "hd_event_list",
        "hd_kernel_base", "hd_vmm_status", "hd_cpu_vendor",
        "hd_assemble", "hd_idt_entries", "hd_smi_count",
    } <= names
    assert len(names) >= 70  # 15 original + 41 (A) + 13 (B) + 4 (C)


async def test_read_only_excludes_gated_new_tools(tmp_path):
    srv = _build(read_only=True, tmp_path=tmp_path)
    async with Client(srv) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert {
        "hd_mem_edit", "hd_hook_ept", "hd_msr_write", "hd_bp_modify",
        "hd_vmm_load", "hd_transparent_enable",
    }.isdisjoint(names)
    assert {"hd_mem_display", "hd_va2pa", "hd_bp_list", "hd_kernel_base"} <= names
