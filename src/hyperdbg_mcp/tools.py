"""
 * @file tools.py
 * @author munraimix
 * @brief MCP tool definitions wrapping a HyperDbgSession.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Structure (DESIGN §10, §11):
 *   - Read tools are annotated read-only and wrap all debuggee-sourced output
 *     in the untrusted-data envelope. They are plain (sync) functions so
 *     MCPServer runs them in its worker-thread pool, off the event loop.
 *   - Confirmation-gated tools are async (require_confirmation is async). Their
 *     blocking ctypes work is offloaded via anyio.to_thread.run_sync so the event loop
 *     is never frozen.
 *   - Any tool that can mutate the target (arbitrary command, breakpoints,
 *     memory/register/script writes) is registered ONLY when not --read-only.
 *   - Every call is written to the append-only audit log.
"""

from __future__ import annotations

import re
from functools import partial
from typing import TYPE_CHECKING, Annotated

import anyio
from mcp.server.mcpserver import Context
from mcp.types import InputRequiredResult, ToolAnnotations
from pydantic import BaseModel, Field

from .errors import HyperDbgError
from .safety import wrap_untrusted
from .script import COOKBOOK, TEMPLATE_KINDS, TemplateKind, build_template, read_only_script
from .toolkit import (
    choose,
    denial,
    parse_addr,
    parsed_script,
    pure_expression,
    require_confirmation,
    resolve_addr,
)

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer

    from .server import AppContext

_MAX_DISASM = 256
_MAX_INSN_LEN = 15  # longest x86 instruction, in bytes
# A disassembly line starts with its address: fffff802`79afd130 or 00401000.
_INSN_LINE = re.compile(r"[0-9a-fA-F]{8}(?:`[0-9a-fA-F]{8})?\s")


def _first_instructions(listing: str, count: int) -> str:
    """Cut a `u` listing after `count` instruction lines (symbol labels kept)."""
    lines, seen = [], 0
    for line in listing.splitlines(keepends=True):
        if _INSN_LINE.match(line):
            if seen == count:
                break
            seen += 1
        lines.append(line)
    return "".join(lines)


class RegisterDump(BaseModel):
    registers: dict[str, str] = Field(description="Register name -> hex value")


class MemoryDump(BaseModel):
    address: str
    size: int
    hex: str = Field(description="Captured bytes, hex-encoded (untrusted-fenced)")


def _app(ctx: Context) -> AppContext:
    return ctx.request_context.lifespan_context


def register_tools(mcp: MCPServer, *, read_only: bool) -> None:
    """Register tools. Any target-mutating tool is skipped when read_only."""

    _RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False)
    _STATE = ToolAnnotations(readOnlyHint=False, destructiveHint=False)
    _DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)
    # Never touches the target: same answer for the same input.
    _OFFLINE = ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )

    # ===== READ tools (safe; always registered) =========================== #
    @mcp.tool(name="hd_mem_read", annotations=_RO)
    def hd_mem_read(
        address: str, size: int, ctx: Context, pid: int = 0, virtual: bool = True
    ) -> MemoryDump:
        """Read `size` bytes of debuggee memory from `address`.

        `address` is hex/decimal (0xfffff800...) or a symbol such as
        `nt!KdDebuggerEnabled` or `nt!PsLoadedModuleList+0x8` (needs symbols).
        """
        app = _app(ctx)
        addr = resolve_addr(ctx, address)
        data = app.session.read_memory(addr, size, pid=pid, virtual=virtual)
        app.audit.record(
            "hd_mem_read", {"address": hex(addr), "size": size}, status="ok", target_pid=pid
        )
        return MemoryDump(
            address=hex(addr), size=len(data), hex=wrap_untrusted(data.hex(), "memory")
        )

    @mcp.tool(name="hd_reg_read_all", annotations=_RO)
    def hd_reg_read_all(ctx: Context) -> RegisterDump:
        """Read all general-purpose + segment/flags/rip registers."""
        app = _app(ctx)
        regs = app.session.read_all_registers()
        app.audit.record("hd_reg_read_all", {}, status="ok")
        return RegisterDump(registers={k: hex(v) for k, v in regs.items()})

    @mcp.tool(name="hd_reg_read", annotations=_RO)
    def hd_reg_read(name: str, ctx: Context) -> str:
        """Read a single register by name (e.g. 'rax', 'rip')."""
        app = _app(ctx)
        value = app.session.read_register(name)
        app.audit.record("hd_reg_read", {"name": name}, status="ok")
        return hex(value)

    @mcp.tool(name="hd_eval", annotations=_RO)
    def hd_eval(expression: str, ctx: Context) -> str:
        """Evaluate a side-effect-free script expression (`poi(@rsp)+8`) to an integer.

        Only reading functions are allowed (poi, db..dq, *_pa, strlen, ...); run
        anything that writes with hd_script_run. Numbers are hex by default
        (0n10 is decimal). In local VMI mode with no paused process HyperDbg only
        simulates the engine: symbols and arithmetic work, and an expression
        that reads @registers, $pseudo-registers or memory is refused (it would
        read 0) - pause a process first, or use hd_reg_read / hd_mem_read.
        """
        app = _app(ctx)
        value = app.session.eval_expression(pure_expression(expression))
        app.audit.record("hd_eval", {"expression": expression}, status="ok")
        return hex(value)

    @mcp.tool(name="hd_script_eval", annotations=_RO)
    def hd_script_eval(
        script: Annotated[str, Field(description="HyperDbg script that only reads and prints")],
        ctx: Context,
    ) -> str:
        """Run a read-only HyperDbg script and return what it prints.

        For values hd_eval can't return: several at once, strings (%s, %ws),
        loops over lists or arrays. Local variables, if/while/for, functions the
        script defines, the reading functions and printf/print are allowed;
        writes to registers, globals or memory and state-changing functions are
        refused (use hd_script_run). Runs where hd_script_run runs: Debugger
        Mode, or a paused user-mode process in local VMI mode. Syntax and
        functions: hd_script_cookbook.

        Example: for (i = 0; i < 4; i++) { printf("%llx\\n", dq(@rsp + i * 8)); }
        """
        app = _app(ctx)
        out = app.session.run_script(read_only_script(script))
        app.audit.record("hd_script_eval", {}, status="ok")
        if not out.strip():
            return "(the script printed nothing)"
        return wrap_untrusted(out, "script-output")

    @mcp.tool(name="hd_script_check", annotations=_OFFLINE)
    def hd_script_check(
        script: Annotated[str, Field(description="HyperDbg script to parse (not run)")],
        ctx: Context,
        read_only: Annotated[
            bool, Field(description="also require it to pass hd_script_eval's read-only check")
        ] = False,
    ) -> str:
        """Check a script's syntax with HyperDbg's own parser, without running it.

        Use it on a hook's script= before setting the hook, or to fix a script
        that failed. An error names the line and column, with a hint.
        read_only=True also checks it would be accepted by hd_script_eval.
        """
        if read_only:
            read_only_script(script)
        parsed_script(ctx, script)
        return "The script parses." + (" It is read-only." if read_only else "")

    @mcp.tool(name="hd_script_cookbook", annotations=_OFFLINE)
    def hd_script_cookbook() -> str:
        """HyperDbg script syntax, functions, where scripts run, and recipes.

        Read it before writing a script for hd_script_eval, hd_script_run or a
        hook's script= (also the hyperdbg://script/cookbook resource).
        """
        return COOKBOOK

    @mcp.tool(name="hd_script_template", annotations=_OFFLINE)
    def hd_script_template(
        kind: TemplateKind,
        fields: Annotated[
            str, Field(description='comma-separated expressions, e.g. "@rcx, s:@rdx, d:@r8"')
        ] = "",
        condition: Annotated[
            str, Field(description='one expression, e.g. "$pid == 0x1234" (the *_if kinds)')
        ] = "",
        tag: Annotated[
            str, Field(pattern=r"^[A-Za-z_]\w*$", description="a word that starts every line")
        ] = "hit",
        every: Annotated[int, Field(ge=1, description="count: print every Nth hit")] = 1,
    ) -> str:
        """Build an event script to pass as script= to a hook tool (runs nothing).

        kinds:
          log       print core, pid, tid, rip and `fields` on every hit
          log_if    the same, only when `condition` holds
          count     count hits in the global .<tag>_hits, print every `every`th
          break_if  log, then pause into the debugger when `condition` holds
                    (Debugger Mode)
          block_if  log, then drop the event (event_sc) when `condition` holds:
                    a pre-stage event with short_circuit
        fields: comma-separated expressions printed as hex; prefix one with s:
        (char* string), ws: (wchar_t* string) or d: (decimal), e.g.
        "@rcx, s:@rdx, poi(@rsp+28)". condition: one expression, e.g.
        "$pid == 0x1234 && @rcx != 0". tag: a word that starts every line.
        """
        script = build_template(kind, fields=fields, condition=condition, tag=tag, every=every)
        kinds = ", ".join(TEMPLATE_KINDS)
        return f"{script}\n\n(pass it as script= to a hook tool; kinds: {kinds})"

    @mcp.tool(name="hd_disasm", annotations=_RO)
    def hd_disasm(address: str, ctx: Context, count: int = 16, bits: int = 64) -> str:
        """Disassemble up to `count` instructions at `address` (hex or symbol; read-only).

        bits=32 decodes x86 (WoW64 / 32-bit) code instead of x64.
        """
        app = _app(ctx)
        addr = resolve_addr(ctx, address)
        count = max(1, min(count, _MAX_DISASM))
        cmd = choose(str(bits), {"64": "u", "32": "u32"}, "bits")
        # `l` is a length in bytes, not instructions: ask for the longest
        # `count` instructions can be, then keep the first `count`.
        out = app.session.run_command(f"{cmd} {hex(addr)} l {count * _MAX_INSN_LEN:x}")
        out = _first_instructions(out, count)
        app.audit.record("hd_disasm", {"address": hex(addr), "count": count}, status="ok")
        return wrap_untrusted(out, "disassembly")

    @mcp.tool(name="hd_list_modules", annotations=_RO)
    def hd_list_modules(ctx: Context) -> str:
        """List loaded modules (lm)."""
        app = _app(ctx)
        out = app.session.run_command("lm")
        app.audit.record("hd_list_modules", {}, status="ok")
        return wrap_untrusted(out, "modules")

    @mcp.tool(name="hd_status", annotations=_RO)
    def hd_status(ctx: Context) -> str:
        """Report HyperDbg debugger status (.status)."""
        app = _app(ctx)
        out = app.session.run_command(".status")
        app.audit.record("hd_status", {}, status="ok")
        return wrap_untrusted(out, "status")

    # ===== execution-control (no memory writes; allowed in read-only) ===== #
    @mcp.tool(name="hd_exec_continue", annotations=_STATE)
    def hd_exec_continue(ctx: Context) -> str:
        """Resume the debuggee; returns at once while it keeps running.

        Until it halts again (breakpoint, event, or hd_exec_pause) target tools
        refuse with "debuggee is running"; hd_connection_status shows running=.
        """
        app = _app(ctx)
        running = app.session.continue_debuggee()
        app.audit.record("hd_exec_continue", {}, status="ok")
        if running:
            return "Continued; the debuggee is running (halts on a breakpoint/event or pause)."
        return "Continued."

    @mcp.tool(name="hd_exec_pause", annotations=_STATE)
    def hd_exec_pause(ctx: Context) -> str:
        """Halt a running debuggee and wait until it is halted (up to 10 s)."""
        app = _app(ctx)
        app.session.pause_debuggee()
        app.audit.record("hd_exec_pause", {}, status="ok")
        return "Paused."

    @mcp.tool(name="hd_exec_step", annotations=_STATE)
    def hd_exec_step(ctx: Context, mode: str = "over") -> str:
        """Single-step the debuggee. mode = over | in | instr."""
        app = _app(ctx)
        app.session.step(mode)
        app.audit.record("hd_exec_step", {"mode": mode}, status="ok")
        return f"Stepped ({mode})."

    if read_only:
        return

    # ===== target-mutating tools (NOT registered under --read-only) ======= #
    @mcp.tool(name="hd_exec_command", annotations=_DESTRUCTIVE)
    async def hd_exec_command(command: str, ctx: Context) -> str | InputRequiredResult:
        """Run a raw HyperDbg CLI command (arbitrary; may modify the target)."""
        app = _app(ctx)
        confirmed = await require_confirmation(ctx, f"run `{command}`")
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record("hd_exec_command", {"command": command}, status="denied")
            return denial(ctx)
        try:
            out = await anyio.to_thread.run_sync(app.session.run_command, command)
        except HyperDbgError as exc:
            app.audit.record("hd_exec_command", {"command": command}, status="error")
            return str(exc)  # session already fences debuggee output on failure
        app.audit.record("hd_exec_command", {"command": command}, status="ok")
        return wrap_untrusted(out, "command-output")

    @mcp.tool(name="hd_bp_set", annotations=_STATE)
    def hd_bp_set(address: str, ctx: Context, pid: int = 0, tid: int = 0, core: int = 0) -> str:
        """Set a breakpoint at `address` (hex string; patches the target; full mode only)."""
        app = _app(ctx)
        addr = resolve_addr(ctx, address)
        app.session.set_breakpoint(addr, pid=pid, tid=tid, core=core)
        app.audit.record("hd_bp_set", {"address": hex(addr)}, status="ok", target_pid=pid)
        return f"Breakpoint set at {hex(addr)}."

    @mcp.tool(name="hd_mem_write", annotations=_DESTRUCTIVE)
    async def hd_mem_write(
        address: str, data_hex: str, ctx: Context, pid: int = 0, expected_current: str = ""
    ) -> str | InputRequiredResult:
        """Write raw bytes (hex-encoded) to debuggee memory at `address` (hex string).

        expected_current (hex, same length as data_hex) writes only if memory
        still holds those bytes: a compare-and-write, so a patch computed from an
        earlier read can't land on code or data that changed since.
        """
        app = _app(ctx)
        addr = resolve_addr(ctx, address)
        try:
            payload = bytes.fromhex(data_hex)
            expected = bytes.fromhex(expected_current) if expected_current else None
        except ValueError as exc:
            raise HyperDbgError(f"invalid hex: {exc}") from None
        if not payload:
            raise HyperDbgError("data_hex is empty")
        what = f"write {len(payload)} bytes to {hex(addr)}"
        if expected is not None:
            if len(expected) != len(payload):
                raise HyperDbgError("expected_current must be as long as data_hex")
            current = await anyio.to_thread.run_sync(
                partial(app.session.read_memory, addr, len(payload), pid=pid)
            )
            if current != expected:
                raise HyperDbgError(
                    f"memory at {hex(addr)} no longer holds {expected.hex()} "
                    f"(now {current.hex()}); nothing written"
                )
            if current == payload:
                what += " (the bytes it already holds)"
        confirmed = await require_confirmation(ctx, what)
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record("hd_mem_write", {"address": hex(addr)}, status="denied")
            return denial(ctx)
        await anyio.to_thread.run_sync(
            partial(app.session.write_memory_bytes, addr, payload, pid=pid)
        )
        app.audit.record(
            "hd_mem_write", {"address": hex(addr), "len": len(payload)}, status="ok", target_pid=pid
        )
        return f"Wrote {len(payload)} bytes to {hex(addr)}."

    @mcp.tool(name="hd_reg_write", annotations=_DESTRUCTIVE)
    async def hd_reg_write(name: str, value: str, ctx: Context) -> str | InputRequiredResult:
        """Write a value (hex string) to a single register."""
        app = _app(ctx)
        val = parse_addr(value)
        confirmed = await require_confirmation(ctx, f"set {name} = {hex(val)}")
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record("hd_reg_write", {"name": name}, status="denied")
            return denial(ctx)
        await anyio.to_thread.run_sync(app.session.write_register, name, val)
        app.audit.record("hd_reg_write", {"name": name}, status="ok")
        return f"Set {name} = {hex(val)}."

    @mcp.tool(name="hd_script_run", annotations=_DESTRUCTIVE)
    async def hd_script_run(script: str, ctx: Context) -> str | InputRequiredResult:
        """Run a HyperDbg script (Turing-complete; can modify target state).

        Returns what it prints. It is parsed first: a syntax error names the
        line and column, with a hint. It runs in Debugger Mode, or in a paused
        user-mode process in local VMI mode. For a script that only reads, use
        hd_script_eval (no confirmation). Syntax, functions and recipes: the
        hd_script_cookbook.
        """
        app = _app(ctx)
        confirmed = await require_confirmation(ctx, "run a HyperDbg script")
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record("hd_script_run", {}, status="denied")
            return denial(ctx)
        out = await anyio.to_thread.run_sync(app.session.run_script, script)
        app.audit.record("hd_script_run", {}, status="ok")
        return wrap_untrusted(out, "script-output") if out.strip() else "Script executed."
