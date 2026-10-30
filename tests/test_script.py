"""
 * @file test_script.py
 * @brief Script-engine helpers: the read-only check, where a script would run,
 *        parse errors with line/column/hint, event-script templates, tools.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from ctypes import addressof, create_string_buffer, pointer

import pytest
from mcp import Client

from hyperdbg_mcp import ffi, server
from hyperdbg_mcp.errors import HyperDbgError
from hyperdbg_mcp.script import (
    build_template,
    format_parse_error,
    needs_target_context,
    read_only_script,
)
from hyperdbg_mcp.session import HyperDbgSession

_NOT_CONNECTED = (
    b"err, you're not connected to any debuggee (neither user debugger nor kernel debugger)\n"
)
_NOT_PAUSED = b"err, the target process is NOT paused, you should run 'pause' to pause it\n"


@pytest.mark.parametrize(
    "script",
    [
        'x = poi(@rsp); printf("%llx\\n", x);',
        'for (i = 0; i < 4; i++) { printf("%llx\\n", dq(@rsp + i * 8)); }',
        "int sq(int x) { return x * x; } print(sq(2));",
        "p = poi(nt!PsLoadedModuleList); while (p != nt!PsLoadedModuleList) { p = poi(p); }",
        'if (strcmp(@rcx, "a=b; eq(0,0)") == 0) { print(1); } else { print(2); }',
        "x = 1; x += 2; --x; // a comment with eq(0, 0)\nprint(x);",
    ],
)
def test_read_only_script_accepts_reads(script):
    assert read_only_script(script) == script


@pytest.mark.parametrize(
    ("script", "why"),
    [
        ("@rax = 1;", "register"),
        (".count = .count + 1;", "global"),
        ("$pid = 4;", "pseudo-register"),
        ("eq(@rsp, 0);", "eq()"),
        ("memcpy(1, 2, 3);", "memcpy()"),
        ("event_sc(1);", "event_sc()"),
        ("pause();", "pause()"),
        ("*p = 1;", "pointer"),
        ("p->x = 1;", "pointer"),
        ("a[1] = 2;", "pointer"),
        ("s.x = 1;", "struct member"),
        ("@rax++;", "register"),
        ("++.g;", "global"),
        ('#include "C:/secret.txt"', "#include"),
        ("", "empty"),
    ],
)
def test_read_only_script_refuses_writes(script, why):
    with pytest.raises(HyperDbgError, match="empty|hd_script_run") as ei:
        read_only_script(script)
    assert why in str(ei.value)


def test_needs_target_context():
    assert needs_target_context("nt!PsLoadedModuleList + 0x10") == []
    assert needs_target_context("1 + 2 * 3") == []
    assert needs_target_context("poi(@rsp) + $pid + poi(@rsp)") == ["poi()", "@rsp", "$pid"]
    assert needs_target_context('strlen("@rax")') == ["strlen()"]


def test_parse_error_names_line_column_and_hint():
    msg = "Line 2:\nx = foo + 1;\n    ^\nSyntax Error: Unresolved Variable\n"
    text = format_parse_error(msg)
    assert text.startswith("script error at line 3, column 5: Syntax Error: Unresolved Variable")
    assert "\n  x = foo + 1;\n      ^\n" in text
    assert "hint:" in text and "'@'" in text
    assert format_parse_error("something odd") == "script error: something odd"
    sym = format_parse_error("Line 0:\nx = nt!Nope + 1;\n    ^\nSyntax Error: Invalid Syntax")
    assert "line 1, column 5" in sym and "nt!Nope is not a known symbol" in sym
    hexname = format_parse_error("Line 0:\nint sq(int a) {\n           ^\nSyntax Error: Invalid")
    assert "'a' reads as the hex number 0xa" in hexname
    # the engine's excerpt of a later line starts one character late
    late = format_parse_error(
        "Line 1:\n = nt!Nope;\n   ^\nSyntax Error: Invalid Syntax", "x = 1;\ny = nt!Nope;"
    )
    assert "line 2, column 5" in late and "\n  y = nt!Nope;\n      ^\n" in late


def test_templates():
    log = build_template("log", fields="@rcx, s:@rdx, poi(@rsp+28)", tag="ntc")
    assert log == (
        'printf("ntc core=%x pid=%x tid=%x rip=%llx @rcx=%llx @rdx=%s poi(@rsp+28)=%llx\\n", '
        "$core, $pid, $tid, @rip, @rcx, @rdx, poi(@rsp+28));"
    )
    assert build_template("log_if", condition="$pid == 4").startswith("if ($pid == 4) { printf(")
    assert build_template("count", tag="x", every=256) == (
        "if (0) { .x_hits = 0; } .x_hits = .x_hits + 1; "
        'if (.x_hits % 0x100 == 0) { printf("x hits=%d\\n", .x_hits); }'
    )
    assert build_template("break_if", condition="@rcx == 0").endswith("pause(); }")
    assert build_template("block_if", condition="@rcx == 0").endswith("event_sc(1); }")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"kind": "nope"},
        {"kind": "log_if"},  # needs a condition
        {"kind": "log", "fields": "eq(0, 0)"},
        {"kind": "log", "fields": "@rcx); pause("},
        {"kind": "log_if", "condition": "@rax = 1"},
        {"kind": "log", "tag": "a b"},
        {"kind": "count", "every": 0},
    ],
)
def test_template_rejects_bad_input(kwargs):
    kind = kwargs.pop("kind")
    with pytest.raises(HyperDbgError):
        build_template(kind, **kwargs)


# --------------------------------------------------------------------------- #
# session: engine context and parse check                                      #
# --------------------------------------------------------------------------- #
class ScriptDll:
    """libhyperdbg stand-in whose script engine answers like the real one."""

    def __init__(self, engine: bytes = b""):
        self._cb = None
        self.engine = engine  # what run_script prints before failing; b"" = runs
        self.scripts: list[bytes] = []
        self.evaluated: list[bytes] = []

    def hyperdbg_u_set_text_message_callback(self, cb):
        self._cb = cb

    def hyperdbg_u_unset_text_message_callback(self):
        pass

    def hyperdbg_u_connect_local_debugger(self):
        pass

    def hyperdbg_u_run_script(self, script, _show):
        if self.engine:
            self._cb(self.engine)
            raise HyperDbgError("hyperdbg_u_run_script failed")  # its errcheck
        if script == b")":
            self._cb(b"Line 1:\n)\n^\nSyntax Error: Invalid Syntax\n")
            raise HyperDbgError("hyperdbg_u_run_script failed")
        self.scripts.append(script)
        self._cb(b"printed\n")
        return 1

    def hyperdbg_u_eval_expression(self, expr, _has_error):
        self.evaluated.append(expr)
        return 0x10


class FakeParser:
    """script-engine stand-in: ScriptEngineParse with a fixed error message."""

    def __init__(self, message: bytes | None = None):
        self._text = create_string_buffer(message) if message else None
        self.freed = 0

    def ScriptEngineParse(self, _script):  # noqa: N802 - the export's name
        buf = ffi.SYMBOL_BUFFER()
        buf.Message = addressof(self._text) if self._text is not None else None
        return pointer(buf)

    def RemoveSymbolBuffer(self, _buf):  # noqa: N802
        self.freed += 1


def _local(engine: bytes = b"", parser=None) -> tuple[HyperDbgSession, ScriptDll]:
    dll = ScriptDll(engine)
    s = HyperDbgSession(dll=dll)
    s._script_engine = parser
    s.connect_local()
    return s, dll


@pytest.mark.parametrize(
    ("engine", "context"),
    [(_NOT_CONNECTED, "simulated"), (_NOT_PAUSED, "running"), (b"", "target")],
)
def test_engine_context(engine, context):
    s, dll = _local(engine)
    assert s.engine_context() == context
    assert dll.scripts == []  # the probe never runs anything


def test_eval_refuses_register_reads_in_a_simulated_engine():
    s, dll = _local(_NOT_CONNECTED)
    with pytest.raises(HyperDbgError, match="only simulates") as ei:
        s.eval_expression("poi(@rsp)")
    assert "poi(), @rsp" in str(ei.value)
    assert dll.evaluated == []
    assert s.eval_expression("nt!KiSystemCall64 + 3") == 0x10  # symbols still work


def test_eval_refuses_a_running_process():
    s, _ = _local(_NOT_PAUSED)
    with pytest.raises(HyperDbgError, match="hd_exec_pause"):
        s.eval_expression("@rip")


def test_eval_reads_a_paused_process():
    s, dll = _local()
    assert s.eval_expression("@rip") == 0x10 and dll.evaluated == [b"@rip"]


def test_run_script_explains_where_scripts_run():
    s, _ = _local(_NOT_CONNECTED)
    with pytest.raises(HyperDbgError, match="paused user-mode process"):
        s.run_script("print(1);")


def test_run_script_parses_first():
    parser = FakeParser(b"Line 1:\nprint(x);\n      ^\nSyntax Error: Unresolved Variable")
    s, dll = _local(parser=parser)
    with pytest.raises(HyperDbgError, match="line 2, column 7") as ei:
        s.run_script("print(x);")
    assert "hint:" in str(ei.value)
    assert dll.scripts == [] and parser.freed == 1


def test_check_script_ok_and_run():
    parser = FakeParser()
    s, dll = _local(parser=parser)
    assert s.check_script("print(1);") is None
    assert s.run_script("print(1);") == "printed\n"
    assert dll.scripts == [b"print(1);"] and parser.freed == 2


# --------------------------------------------------------------------------- #
# tools                                                                        #
# --------------------------------------------------------------------------- #
class ScriptSession:
    def __init__(self, parse_error: str | None = None):
        self.parse_error = parse_error
        self.scripts: list[str] = []
        self.commands: list[str] = []

    def connect(self):
        pass

    def close(self):
        pass

    def check_script(self, _script):
        return self.parse_error

    def run_script(self, script):
        self.scripts.append(script)
        return "a=1 b=2\n"

    def run_command(self, command):
        self.commands.append(command)
        return "ok"


def _server(tmp_path, session, read_only=True):
    return server.build_server(
        read_only=read_only,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: session,
        assume_consent=True,
    )


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")


async def test_script_eval_runs_reads_without_confirmation(tmp_path):
    session = ScriptSession()
    async with Client(_server(tmp_path, session)) as client:
        ok = await client.call_tool("hd_script_eval", {"script": 'printf("a=%x", poi(@rsp));'})
        bad = await client.call_tool("hd_script_eval", {"script": "eq(@rsp, 0);"})
    assert not ok.is_error and "a=1 b=2" in _text(ok)
    assert bad.is_error and "hd_script_run" in _text(bad)
    assert session.scripts == ['printf("a=%x", poi(@rsp));']


async def test_script_check_reports_the_parser_error(tmp_path):
    session = ScriptSession("Line 1:\nx = ;\n    ^\nSyntax Error: Invalid Syntax")
    async with Client(_server(tmp_path, session)) as client:
        bad = await client.call_tool("hd_script_check", {"script": "x = ;"})
        session.parse_error = None
        ok = await client.call_tool("hd_script_check", {"script": "x = 1;", "read_only": True})
    assert bad.is_error and "line 2, column 5" in _text(bad) and "hint:" in _text(bad)
    assert _text(ok) == "The script parses. It is read-only."


async def test_hook_script_is_parsed_before_the_hook_is_set(tmp_path):
    session = ScriptSession("Line 1:\nprint(y);\n      ^\nSyntax Error: Unresolved Variable")
    async with Client(_server(tmp_path, session, read_only=False)) as client:
        result = await client.call_tool(
            "hd_hook_ept", {"address": "0x1000", "script": "print(y);"}
        )
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert result.is_error and "Unresolved Variable" in _text(result)
    assert session.commands == []
    assert "hd_script_template" in tools["hd_hook_ept"].description


async def test_template_tool_and_cookbook(tmp_path):
    async with Client(_server(tmp_path, ScriptSession())) as client:
        tpl = await client.call_tool("hd_script_template", {"kind": "count", "tag": "n"})
        book = await client.call_tool("hd_script_cookbook", {})
        res = await client.read_resource("hyperdbg://script/cookbook")
    assert _text(tpl).startswith("if (0) { .n_hits = 0; } .n_hits = .n_hits + 1;")
    assert "## Functions" in _text(book)
    assert res.contents[0].text == _text(book)
