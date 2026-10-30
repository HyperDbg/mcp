"""
 * @file test_validation.py
 * @brief Argument validation: no silent fallbacks, no option smuggling into
 *        CLI commands, confirmations that show what will actually run.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp.types import ElicitResult  # noqa: E402

from hyperdbg_mcp import server  # noqa: E402
from hyperdbg_mcp.errors import HyperDbgError  # noqa: E402
from hyperdbg_mcp.toolkit import (  # noqa: E402
    bracket_body,
    choose,
    hex_values,
    pure_expression,
    token,
)


class RecordingSession:
    def __init__(self):
        self.commands: list[str] = []

    def connect(self):
        pass

    def close(self):
        pass

    def run_command(self, command):
        self.commands.append(command)
        if command.startswith("rdmsr"):  # TSC_AUX = 5 on core 0 and 1
            core = command.split(" core ")[1] if " core " in command else None
            cores = [core] if core else ["0x0", "0x1"]
            return "".join(f"core : {c} - msr[c0000103] = 00000000`00000005\n" for c in cores)
        return f"ok:{command}"


def _build(tmp_path, read_only=False):
    session = RecordingSession()
    srv = server.build_server(
        read_only=read_only,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )
    return srv, session


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")


@pytest.mark.parametrize(
    "script",
    [
        "printf(\"%d\", @rax); }",  # closes the block early
        "x = 1; } pid 4 {",  # smuggles an option
        "x = 1; // comment",  # `//` swallows the closing brace
        "/* { */ x = 1;",
        "x = \"unterminated;",
        "x = 1 \\} y",
        "if (1) {",
    ],
)
def test_bracket_body_rejects_escapes(script):
    with pytest.raises(HyperDbgError):
        bracket_body(script)


@pytest.mark.parametrize(
    "script",
    ["printf(\"%llx\\n\", @rax);", "if (@rax == 1) { pause(); }", 'printf("}{");'],
)
def test_bracket_body_accepts_scripts(script):
    assert bracket_body(script) == script


def test_token_and_hex_values():
    assert token("nt!_EPROCESS", "t") == "nt!_EPROCESS"
    for bad in ("_EPROCESS output C:/x.h", "a\tb", 'a"b', "a{b", ""):
        with pytest.raises(HyperDbgError):
            token(bad, "t")
    assert hex_values(" 90 0x90 cc ") == "90 0x90 cc"
    for bad in ("90 pid 4", "zz", ""):
        with pytest.raises(HyperDbgError):
            hex_values(bad)
    assert choose("a", {"a": "x"}, "n") == "x"
    with pytest.raises(HyperDbgError, match="use a"):
        choose("b", {"a": "x"}, "n")


async def test_read_only_tool_cannot_smuggle_output_option(tmp_path):
    srv, session = _build(tmp_path, read_only=True)
    async with Client(srv) as client:
        result = await client.call_tool(
            "hd_struct_export", {"type_name": "_EPROCESS output C:/Windows/x.h"}
        )
    assert result.is_error and session.commands == []


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("hd_bp_modify", {"breakpoint_id": 1, "action": "delete"}),
        ("hd_mem_edit", {"address": "0x1000", "value": "90", "fmt": "qwrd"}),
        ("hd_mem_display", {"address": "0x1000", "fmt": "words"}),
        ("hd_stack", {"fmt": "params"}),
        ("hd_event_sc", {"state": "yes"}),
        ("hd_hook_monitor", {"attribute": "rw pid 4", "from_address": "0", "to_address": "1"}),
        ("hd_hook_tsc", {"stage": "before"}),
    ],
)
async def test_unknown_choice_is_an_error_not_a_default(tmp_path, tool, args):
    srv, session = _build(tmp_path)
    async with Client(srv) as client:
        result = await client.call_tool(tool, args)
    assert result.is_error and "invalid" in _text(result)
    assert session.commands == []


async def test_hook_confirmation_shows_full_command(tmp_path):
    srv, session = _build(tmp_path)
    seen = []

    async def elicit(_context, params):
        seen.append(params.message)
        return ElicitResult(action="accept", content={"confirm": True})

    async with Client(srv, elicitation_callback=elicit) as client:
        await client.call_tool(
            "hd_hook_ept",
            {"address": "0x1000", "script": "eb(@rcx, 0x90);", "stage": "post"},
        )
    assert "script { eb(@rcx, 0x90); }" in seen[0] and "stage post" in seen[0]
    assert session.commands == ["!epthook 0x1000 stage post script { eb(@rcx, 0x90); }"]


class SymbolSession(RecordingSession):
    def __init__(self):
        super().__init__()
        self.evaluated: list[str] = []
        self.reads: list[int] = []

    def eval_expression(self, expr):
        self.evaluated.append(expr)
        return 0xFFFFF80279C00000

    def read_memory(self, address, size, *, pid=0, virtual=True):
        self.reads.append(address)
        return b"\x00" * size


@pytest.mark.parametrize(
    "address", ["nt!KdDebuggerEnabled", "nt!PsLoadedModuleList + 0x8", "@rip-10"]
)
async def test_mem_read_resolves_symbolic_addresses(tmp_path, address):
    session = SymbolSession()
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )
    async with Client(srv) as client:
        result = await client.call_tool("hd_mem_read", {"address": address, "size": 1})
    assert not result.is_error, _text(result)
    assert session.evaluated == [address] and session.reads == [0xFFFFF80279C00000]


@pytest.mark.parametrize(
    "address", ["eq(nt!KdDebuggerEnabled, 1)", "nt!X; eb(0, 1)", "poi(nt!X)", "1 + 2"]
)
async def test_mem_read_never_evaluates_arbitrary_script(tmp_path, address):
    # The script engine can write memory: only symbol(+offset) reaches it.
    session = SymbolSession()
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )
    async with Client(srv) as client:
        result = await client.call_tool("hd_mem_read", {"address": address, "size": 1})
    assert result.is_error and "invalid address" in _text(result)
    assert session.evaluated == [] and session.reads == []


def test_disasm_keeps_only_the_requested_instructions():
    from hyperdbg_mcp.tools import _first_instructions

    listing = (
        "ntkrnlmp!KeBugCheckEx:\n"
        "fffff802`79afd130    48 89 4C 24 08    mov qword ptr ss:[rsp+0x08], rcx\n"
        "fffff802`79afd135    48 89 54 24 10    mov qword ptr ss:[rsp+0x10], rdx\n"
        "fffff802`79afd13a    4C 89 44 24 18    mov qword ptr ss:[rsp+0x18], r8\n"
    )
    out = _first_instructions(listing, 2)
    assert out.startswith("ntkrnlmp!KeBugCheckEx:\n")
    assert "79afd135" in out and "79afd13a" not in out


@pytest.mark.parametrize(
    "expr",
    [
        "poi(@rsp) + 8",
        "dq(nt!PsLoadedModuleList) == 0",
        'strcmp(@rcx, "a;b{c}") != 0',
        "virtual_to_physical(@rip) >= 0x1000",
    ],
)
def test_pure_expression_accepts_reads(expr):
    assert pure_expression(expr) == expr


@pytest.mark.parametrize(
    "expr",
    [
        "eq(nt!KdDebuggerEnabled, 1)",
        "1); eq(0xfffff80000000000, 0",
        "EB(@rcx, 0x90)",
        "@rax = 1",
        "$t0++",
        "memcpy(0x1000, 0x2000, 8)",
        "event_disable(1)",
        "{ pause() }",
        "",
    ],
)
def test_pure_expression_rejects_side_effects(expr):
    with pytest.raises(HyperDbgError):
        pure_expression(expr)


async def test_eval_never_reaches_the_engine_with_a_write(tmp_path):
    session = SymbolSession()
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )
    async with Client(srv) as client:
        result = await client.call_tool("hd_eval", {"expression": "1); eq(0, 0"})
    assert result.is_error and session.evaluated == []


@pytest.mark.parametrize(
    ("output", "failed"),
    [
        ("incorrect use of the 'ucpuid'\n\nucpuid : reads CPUID...", True),
        ("\nerr, listing breakpoints is only valid in debugger-mode\n", True),
        ("DBDF | VID:DID\nerr, cannot open file 'pci.ids'\n0000:00:00:0 | 8086:a707", False),
        ("core : 0x0 - msr[c0000082] = fffff800`df2c1840", False),
        ("the trace (hypertrace) module is not loaded. Did you use 'load trace' command?", True),
        # an event's failed output source, printed while this command ran
        ("err, there was an error transferring the message to the remote sources\n", False),
        (
            "err, there was an error transferring the message to the remote sources\n"
            "err, the process id is invalid",
            True,
        ),
        # a progress line comes before the verdict (recorded from '.attach pid 4')
        (
            "Attaching to process 0x4 (4)...\n\n"
            "err, unable to detect whether the process was 32-bit or 64-bit (c000002e)\n",
            True,
        ),
        ("", False),
    ],
)
def test_printed_failures_are_errors(output, failed):
    from hyperdbg_mcp.session import _reports_failure

    assert _reports_failure(output) is failed


class FailingSession(RecordingSession):
    def run_command(self, command):
        super().run_command(command)
        raise HyperDbgError("run_command failed: err, not in Debugger Mode")


async def test_gated_tool_failure_is_a_tool_error(tmp_path):
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=FailingSession,
        assume_consent=True,
    )
    async with Client(srv) as client:
        result = await client.call_tool("hd_process_switch", {"pid": 4})
    assert result.is_error and "Debugger Mode" in _text(result)


async def _call_confirmed(tmp_path, tool, args):
    srv, session = _build(tmp_path)
    asked: list[str] = []

    async def accept(_context, params):
        asked.append(params.message)
        return ElicitResult(action="accept", content={"confirm": True})

    async with Client(srv, elicitation_callback=accept) as client:
        result = await client.call_tool(tool, args)
    return result, session, asked


async def test_per_core_msr_needs_a_core(tmp_path):
    # GS base on every core = every core on one KPCR: refused before any write
    result, session, _ = await _call_confirmed(
        tmp_path, "hd_msr_write", {"msr_id": "0xC0000101", "value": "0x0"}
    )
    assert result.is_error and "every core" in _text(result)
    assert not any(c.startswith("wrmsr") for c in session.commands)


async def test_critical_msr_write_shows_the_current_value(tmp_path):
    result, session, asked = await _call_confirmed(
        tmp_path, "hd_msr_write", {"msr_id": "0xC0000103", "value": "0x7", "core": 1}
    )
    assert not result.is_error
    assert "IA32_TSC_AUX" in asked[0] and "now 0x5" in asked[0] and "CRITICAL" in asked[0]
    # read again when the confirmed call is retried: the write uses a fresh value
    assert set(session.commands[:-1]) == {"rdmsr 0xc0000103 core 0x1"}
    assert session.commands[-1] == "wrmsr 0xc0000103 0x7 core 0x1"


async def test_msr_compare_and_write(tmp_path):
    stale, session, _ = await _call_confirmed(
        tmp_path,
        "hd_msr_write",
        {"msr_id": "0xC0000103", "value": "0x5", "core": 0, "expected_current": "0x4"},
    )
    assert stale.is_error and "no longer holds 0x4" in _text(stale)
    assert not any(c.startswith("wrmsr") for c in session.commands)

    same, _, asked = await _call_confirmed(
        tmp_path,
        "hd_msr_write",
        {"msr_id": "0xC0000103", "value": "0x5", "core": 0, "expected_current": "0x5"},
    )
    assert not same.is_error and "the value it already holds" in asked[0]


def test_msr_values_parse_backticked_output():
    from hyperdbg_mcp.tools_system import _parse_msr_values

    out = (
        "core : 0x0 - msr[c0000082] = fffff800`df2c1840\n"
        "core : 0x1 - msr[c0000082] = fffff800`df2c1840\n"
    )
    assert _parse_msr_values(out) == {0: 0xFFFFF800DF2C1840, 1: 0xFFFFF800DF2C1840}


async def test_memory_compare_and_write(tmp_path):
    from hyperdbg_mcp.mock import MockSession

    session = MockSession()
    session.connect()
    srv = server.build_server(
        read_only=False,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
    )

    async def accept(_context, _params):
        return ElicitResult(action="accept", content={"confirm": True})

    async with Client(srv, elicitation_callback=accept) as client:
        # the mock reads (address + i) & 0xff: 0x1000 holds 00 01 02 03
        stale = await client.call_tool(
            "hd_mem_write",
            {"address": "0x1000", "data_hex": "90909090", "expected_current": "cccccccc"},
        )
        assert stale.is_error and "no longer holds cccccccc" in _text(stale)
        assert session._mem == {}
        ok = await client.call_tool(
            "hd_mem_write",
            {"address": "0x1000", "data_hex": "90909090", "expected_current": "00010203"},
        )
        assert not ok.is_error and session._mem[0x1000] == 0x90


@pytest.mark.parametrize("msr", ["0xC0000100", "0xC0000102"])
async def test_thread_context_msrs_are_refused(tmp_path, msr):
    result, session, _ = await _call_confirmed(
        tmp_path, "hd_msr_write", {"msr_id": msr, "value": "0x0", "core": 0}
    )
    assert result.is_error and "context switch" in _text(result)
    assert session.commands == []
