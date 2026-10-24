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

from functools import partial
from typing import TYPE_CHECKING

import anyio
from mcp.server.mcpserver import Context
from mcp.types import InputRequiredResult, ToolAnnotations
from pydantic import BaseModel, Field

from .errors import HyperDbgError
from .safety import wrap_untrusted
from .toolkit import choose, parse_addr, require_confirmation

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer

    from .server import AppContext

_MAX_DISASM = 256


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

    # ===== READ tools (safe; always registered) =========================== #
    @mcp.tool(name="hd_mem_read", annotations=_RO)
    def hd_mem_read(
        address: str, size: int, ctx: Context, pid: int = 0, virtual: bool = True
    ) -> MemoryDump:
        """Read `size` bytes of debuggee memory from `address` (hex string, e.g. 0xfffff800...)."""
        app = _app(ctx)
        addr = parse_addr(address)
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
        """Evaluate a HyperDbg script expression and return its integer value."""
        app = _app(ctx)
        value = app.session.eval_expression(expression)
        app.audit.record("hd_eval", {"expression": expression}, status="ok")
        return hex(value)

    @mcp.tool(name="hd_disasm", annotations=_RO)
    def hd_disasm(address: str, ctx: Context, count: int = 16, bits: int = 64) -> str:
        """Disassemble up to `count` instructions at `address` (hex string; read-only).

        bits=32 decodes x86 (WoW64 / 32-bit) code instead of x64.
        """
        app = _app(ctx)
        addr = parse_addr(address)
        count = max(1, min(count, _MAX_DISASM))
        cmd = choose(str(bits), {"64": "u", "32": "u32"}, "bits")
        out = app.session.run_command(f"{cmd} {hex(addr)} l {count:x}")
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
        """Continue (resume) the debuggee."""
        app = _app(ctx)
        app.session.continue_debuggee()
        app.audit.record("hd_exec_continue", {}, status="ok")
        return "Continued."

    @mcp.tool(name="hd_exec_pause", annotations=_STATE)
    def hd_exec_pause(ctx: Context) -> str:
        """Pause (halt) the debuggee."""
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
            return "Denied by user."
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
        addr = parse_addr(address)
        app.session.set_breakpoint(addr, pid=pid, tid=tid, core=core)
        app.audit.record("hd_bp_set", {"address": hex(addr)}, status="ok", target_pid=pid)
        return f"Breakpoint set at {hex(addr)}."

    @mcp.tool(name="hd_mem_write", annotations=_DESTRUCTIVE)
    async def hd_mem_write(
        address: str, data_hex: str, ctx: Context, pid: int = 0
    ) -> str | InputRequiredResult:
        """Write raw bytes (hex-encoded) to debuggee memory at `address` (hex string)."""
        app = _app(ctx)
        addr = parse_addr(address)
        payload = bytes.fromhex(data_hex)
        confirmed = await require_confirmation(ctx, f"write {len(payload)} bytes to {hex(addr)}")
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record("hd_mem_write", {"address": hex(addr)}, status="denied")
            return "Denied by user."
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
            return "Denied by user."
        await anyio.to_thread.run_sync(app.session.write_register, name, val)
        app.audit.record("hd_reg_write", {"name": name}, status="ok")
        return f"Set {name} = {hex(val)}."

    @mcp.tool(name="hd_script_run", annotations=_DESTRUCTIVE)
    async def hd_script_run(script: str, ctx: Context) -> str | InputRequiredResult:
        """Run a HyperDbg script (Turing-complete; can modify target state)."""
        app = _app(ctx)
        confirmed = await require_confirmation(ctx, "run a HyperDbg script")
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record("hd_script_run", {}, status="denied")
            return "Denied by user."
        await anyio.to_thread.run_sync(app.session.run_script, script)
        app.audit.record("hd_script_run", {}, status="ok")
        return "Script executed."
