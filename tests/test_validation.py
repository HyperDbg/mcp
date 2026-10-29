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
from hyperdbg_mcp.toolkit import bracket_body, choose, hex_values, token  # noqa: E402


class RecordingSession:
    def __init__(self):
        self.commands: list[str] = []

    def connect(self):
        pass

    def close(self):
        pass

    def run_command(self, command):
        self.commands.append(command)
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
