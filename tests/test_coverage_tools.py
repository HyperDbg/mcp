"""
 * @file test_coverage_tools.py
 * @brief The CLI command each coverage-extension tool sends, and which of them
 *        --read-only exposes.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp.types import ElicitResult  # noqa: E402
from test_validation import RecordingSession  # noqa: E402

from hyperdbg_mcp import server  # noqa: E402

_CASES = [
    ("hd_core_switch", {}, "~"),
    ("hd_core_switch", {"core": 2}, "~ 0x2"),
    ("hd_process_attach", {"pid": 0xB60}, ".attach pid 0xb60"),
    ("hd_process_detach", {}, ".detach"),
    ("hd_process_kill", {}, ".kill"),
    ("hd_process_restart", {}, ".restart"),
    ("hd_user_thread_switch", {}, ".switch list"),
    ("hd_user_thread_switch", {"tid": 0x10}, ".switch tid 0x10"),
    ("hd_pagein", {"address": "0x7ff8349f2224", "mode": "wu", "length": 0x6000},
     ".pagein wu 0x7ff8349f2224 l 0x6000"),
    ("hd_hook_mode", {"mode": "both", "pid": 0x1C0}, "!mode ku pid 0x1c0"),
    ("hd_hook_trace", {"trace_type": "step-out", "core": 2}, "!trace step-out core 0x2"),
    ("hd_hook_crwrite", {"cr": 4, "mask": "0x10000"}, "!crwrite 4 mask 0x10000"),
    ("hd_hook_xsetbv", {"xcr": 0, "short_circuit": True}, "!xsetbv 0x0 sc on"),
    ("hd_prealloc", {"kind": "epthook", "count": 5}, "prealloc epthook 0x5"),
    ("hd_preactivate", {}, "preactivate mode"),
    ("hd_mem_display", {"address": "0x1000", "size": 0x20, "fmt": "qword_sym"},
     "dqs 0x1000 l 0x20"),
    ("hd_disasm", {"address": "0x1000", "count": 4, "bits": 32}, "u32 0x1000 l 4"),
    ("hd_apic_local", {}, "!apic"),
    ("hd_pe_parse", {"path": "c:/reverse files/a.exe", "section": ".text"},
     '.pe section .text "c:/reverse files/a.exe"'),
]


@pytest.mark.parametrize(("tool", "args", "expected"), _CASES)
async def test_tool_sends_expected_command(tmp_path, tool, args, expected):
    session = RecordingSession()
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )

    async def accept(_context, _params):
        return ElicitResult(action="accept", content={"confirm": True})

    async with Client(srv, elicitation_callback=accept) as client:
        result = await client.call_tool(tool, args)
    assert not result.is_error, result.content
    assert session.commands == [expected]


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("hd_pagein", {"address": "0x1000", "mode": "pp"}),
        ("hd_hook_crwrite", {"cr": 3}),
        ("hd_disasm", {"address": "0x1000", "bits": 16}),
        ("hd_pe_parse", {"path": 'a.exe" output x'}),
        ("hd_user_thread_switch", {"pid": 1, "tid": 2}),
    ],
)
async def test_coverage_tools_reject_bad_args(tmp_path, tool, args):
    session = RecordingSession()
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )
    async with Client(srv) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error and session.commands == []


async def test_read_only_exposes_only_safe_coverage_tools(tmp_path):
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=RecordingSession,
    )
    async with Client(srv) as client:
        names = {t.name for t in (await client.list_tools()).tools}
    assert {"hd_core_switch", "hd_apic_local", "hd_pe_parse"} <= names
    assert names.isdisjoint(
        {
            "hd_process_attach", "hd_process_kill", "hd_process_restart", "hd_pagein",
            "hd_hook_mode", "hd_hook_trace", "hd_hook_crwrite", "hd_hook_xsetbv",
            "hd_prealloc", "hd_preactivate", "hd_user_thread_switch",
        }
    )
