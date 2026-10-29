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
    ("hd_disasm", {"address": "0x1000", "count": 4, "bits": 32}, "u32 0x1000 l 3c"),
    ("hd_apic_local", {}, "!apic"),
    ("hd_pe_parse", {"path": "c:/reverse files/a.exe", "section": ".text"},
     '.pe section .text "c:/reverse files/a.exe"'),
    ("hd_hook_syscall", {"syscall_number": 0x55, "output": "out1, out2"},
     "!syscall 0x55 output {out1, out2}"),
    ("hd_pt_enable", {"pid": 0x4A8, "buffer_size": 0x200000}, "!pt enable pid 0x4a8 size 0x200000"),
    ("hd_pt_enable", {"process_name": "notepad.exe", "core": 3},
     "!pt enable pname notepad.exe core 0x3"),
    ("hd_pt_control", {"action": "pause"}, "!pt pause"),
    ("hd_pt_filter",
     {"modes": ["user"], "ranges": ["0x140001000-0x140002000", "ntdll"], "stop_ranges": ["nt"]},
     "!pt filter user range1 0x140001000 0x140002000 range2 module ntdll stoprange1 module nt"),
    ("hd_pt_packets", {"packets": ["psb", "tsc"]}, "!pt packet psb tsc"),
    ("hd_pt_dump", {}, "!pt dump print type instruction"),
    ("hd_lbr", {"action": "enable"}, "!lbr enable"),
    ("hd_lbr_filter", {"exclude": ["kernel", "jcc"]}, "!lbr filter kernel jcc"),
    ("hd_lbr_filter", {}, "!lbr filter"),
    ("hd_lbr_dump", {"core": 1}, "!lbrdump core 0x1"),
    ("hd_rev", {"mode": "pattern", "pid": 0x1C0}, "!rev pattern pid 0x1c0"),
    ("hd_mem_dump",
     {"from_address": "0x401000", "to_address": "0x40b000", "path": "c:/rev/a b.dmp"},
     '.dump 0x401000 0x40b000 path "c:/rev/a b.dmp"'),
    ("hd_mem_dump",
     {"from_address": "0x1000", "to_address": "0x2100", "path": "c:/p.dmp", "physical": True},
     '!dump 0x1000 0x2100 path "c:/p.dmp"'),
    ("hd_pci_tree", {}, "!pcitree"),
    ("hd_pci_cam", {"bus": 3, "device": 0, "function": 0, "raw": True}, "!pcicam 3 0 0 x"),
    ("hd_io_in", {"port": 0xCF8, "width": "eax"}, "uin eax 0xcf8"),
    ("hd_io_out", {"port": 0x3F8, "value": 0x4D, "width": "ax"}, "uout ax 0x3f8 0x4d"),
    ("hd_output_list", {}, "output"),
    ("hd_output_create", {"name": "o1", "output_type": "tcp", "address": "192.168.1.10:8080"},
     "output create o1 tcp 192.168.1.10:8080"),
    ("hd_output_create", {"name": "o2", "output_type": "file", "address": "c:/out/e.txt"},
     'output create o2 file "c:/out/e.txt"'),
    ("hd_output", {"action": "open", "name": "o1"}, "output open o1"),
    ("hd_flush", {}, "flush"),
    ("hd_settings", {"option": "syntax", "value": "att"}, "settings syntax att"),
    ("hd_settings", {"option": "autoflush"}, "settings autoflush"),
    ("hd_measure", {"default": True}, "!measure default"),
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
        ("hd_hook_syscall", {"output": "a b"}),
        ("hd_pt_enable", {"pid": 1, "tid": 2}),
        ("hd_pt_enable", {"cr3": "0x1000", "core": 1}),
        ("hd_pt_filter", {}),
        ("hd_pt_filter", {"ranges": ["a", "b", "c", "d", "e"]}),
        ("hd_pt_packets", {"packets": ["psb", "psb"]}),
        ("hd_lbr_filter", {"exclude": ["everything"]}),
        ("hd_mem_dump", {"from_address": "0x2000", "to_address": "0x1000", "path": "c:/a"}),
        ("hd_mem_dump", {"from_address": "0x1000", "to_address": "0x2000", "path": 'a" x'}),
        ("hd_pci_cam", {"bus": 0, "device": 0x20, "function": 0}),
        ("hd_io_out", {"port": 0x60, "value": 0x100}),
        ("hd_io_in", {"port": 0x10000}),
        ("hd_output_create", {"name": "o1", "output_type": "tcp", "address": "x y"}),
        ("hd_output_create", {"name": "a,b", "output_type": "file", "address": "c:/x"}),
        ("hd_settings", {"option": "autounpause", "value": "maybe"}),
        ("hd_settings", {"option": "nosuch"}),
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
    assert {
        "hd_core_switch", "hd_apic_local", "hd_pe_parse", "hd_pt_dump", "hd_lbr_dump",
        "hd_pci_tree", "hd_pci_cam", "hd_output_list", "hd_flush", "hd_settings",
    } <= names
    assert names.isdisjoint(
        {
            "hd_process_attach", "hd_process_kill", "hd_process_restart", "hd_pagein",
            "hd_hook_mode", "hd_hook_trace", "hd_hook_crwrite", "hd_hook_xsetbv",
            "hd_prealloc", "hd_preactivate", "hd_user_thread_switch", "hd_pt_enable",
            "hd_pt_control", "hd_pt_filter", "hd_pt_packets", "hd_lbr", "hd_lbr_filter",
            "hd_rev", "hd_mem_dump", "hd_io_in", "hd_io_out", "hd_output_create",
            "hd_output", "hd_measure",
        }
    )
