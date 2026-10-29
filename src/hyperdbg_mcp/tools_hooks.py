"""
* @file tools_hooks.py
* @author munraimix
* @brief HyperDbg hook tools (ept, syscall, cpuid, msr, io, exception, interrupt, dr, tsc,
*        pmc, mode, trace, crwrite, xsetbv) and the prealloc/preactivate they rely on.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import (
    DESTRUCTIVE,
    STATE,
    bracket_body,
    choose,
    parse_addr,
    resolve_addr,
    run_text,
    run_text_confirmed,
)

_STAGES = {"pre": "pre", "post": "post", "all": "all"}
_MONITOR_ATTRS = {a: a for a in ("r", "w", "x", "rw", "rx", "wx", "rwx")}
_MODES = {"user": "u", "kernel": "k", "both": "ku"}
_TRACE_TYPES = {t: t for t in ("step-in", "step-out", "instrument-step")}
_PREALLOC_TYPES = {
    t: t
    for t in (
        "thread-interception",
        "monitor",
        "epthook",
        "epthook2",
        "regular-event",
        "big-event",
        "regular-safe-buffer",
        "big-safe-buffer",
    )
}


def _suffix(pid: int, core: int, script: str, stage: str = "", short_circuit: bool = False) -> str:
    """Build the event-option suffix (pid/core/stage/sc/script) for a hook command."""
    parts = []
    if pid:
        parts.append(f" pid {pid:#x}")
    if core:
        parts.append(f" core {core:#x}")
    if stage:
        parts.append(" stage " + choose(stage, _STAGES, "stage"))
    if short_circuit:
        parts.append(" sc on")
    if script:
        parts.append(f" script {{ {bracket_body(script)} }}")
    return "".join(parts)


def register_hooks(mcp: MCPServer, *, read_only: bool) -> None:
    if read_only:
        return

    @mcp.tool(name="hd_hook_ept", annotations=DESTRUCTIVE)
    async def hd_hook_ept(
        address: str,
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Set EPT (Extended Page Tables) hook at address (hex string)."""
        addr = resolve_addr(ctx, address)
        cmd = f"!epthook {addr:#x}" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set ept hook at {addr:#x}: {cmd}",
            audit="hd_hook_ept",
            kind="events",
            args={"address": addr},
        )

    @mcp.tool(name="hd_hook_ept2", annotations=DESTRUCTIVE)
    async def hd_hook_ept2(
        address: str,
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Set EPT2 (Extended Page Tables 2) hook at address (hex string)."""
        addr = resolve_addr(ctx, address)
        cmd = f"!epthook2 {addr:#x}" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set ept2 hook at {addr:#x}: {cmd}",
            audit="hd_hook_ept2",
            kind="events",
            args={"address": addr},
        )

    @mcp.tool(name="hd_hook_monitor", annotations=DESTRUCTIVE)
    async def hd_hook_monitor(
        attribute: str,
        from_address: str,
        to_address: str,
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Monitor r|w|x|rw|rx|wx|rwx accesses to an address range (hex strings)."""
        frm = resolve_addr(ctx, from_address)
        to = resolve_addr(ctx, to_address)
        attr = choose(attribute, _MONITOR_ATTRS, "attribute")
        cmd = f"!monitor {attr} {frm:#x} {to:#x}" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set monitor hook on {attribute}: {cmd}",
            audit="hd_hook_monitor",
            kind="events",
            args={"attribute": attribute, "from_address": frm, "to_address": to},
        )

    @mcp.tool(name="hd_hook_syscall", annotations=DESTRUCTIVE)
    async def hd_hook_syscall(
        ctx: Context,
        syscall_number: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all syscalls or specific syscall if syscall_number >= 0."""
        cmd = "!syscall"
        if syscall_number >= 0:
            cmd += f" {syscall_number:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set syscall hook: {cmd}",
            audit="hd_hook_syscall",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_sysret", annotations=DESTRUCTIVE)
    async def hd_hook_sysret(
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook sysret (return from syscall) instruction."""
        cmd = "!sysret" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set sysret hook: {cmd}",
            audit="hd_hook_sysret",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_cpuid", annotations=DESTRUCTIVE)
    async def hd_hook_cpuid(
        ctx: Context,
        eax: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all CPUID or specific function if eax >= 0."""
        cmd = "!cpuid"
        if eax >= 0:
            cmd += f" {eax:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set cpuid hook: {cmd}",
            audit="hd_hook_cpuid",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_msrread", annotations=DESTRUCTIVE)
    async def hd_hook_msrread(
        ctx: Context,
        msr: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all MSR reads or specific MSR if msr >= 0."""
        cmd = "!msrread"
        if msr >= 0:
            cmd += f" {msr:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set msrread hook: {cmd}",
            audit="hd_hook_msrread",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_msrwrite", annotations=DESTRUCTIVE)
    async def hd_hook_msrwrite(
        ctx: Context,
        msr: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all MSR writes or specific MSR if msr >= 0."""
        cmd = "!msrwrite"
        if msr >= 0:
            cmd += f" {msr:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set msrwrite hook: {cmd}",
            audit="hd_hook_msrwrite",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_tsc", annotations=DESTRUCTIVE)
    async def hd_hook_tsc(
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook TSC (Time Stamp Counter) instruction."""
        cmd = "!tsc" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx, cmd, what=f"set tsc hook: {cmd}", audit="hd_hook_tsc", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_pmc", annotations=DESTRUCTIVE)
    async def hd_hook_pmc(
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook PMC (Performance Monitoring Counters)."""
        cmd = "!pmc" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx, cmd, what=f"set pmc hook: {cmd}", audit="hd_hook_pmc", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_ioin", annotations=DESTRUCTIVE)
    async def hd_hook_ioin(
        ctx: Context,
        port: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all IN instructions or specific port if port >= 0."""
        cmd = "!ioin"
        if port >= 0:
            cmd += f" {port:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set ioin hook: {cmd}",
            audit="hd_hook_ioin",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_ioout", annotations=DESTRUCTIVE)
    async def hd_hook_ioout(
        ctx: Context,
        port: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all OUT instructions or specific port if port >= 0."""
        cmd = "!ioout"
        if port >= 0:
            cmd += f" {port:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set ioout hook: {cmd}",
            audit="hd_hook_ioout",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_vmcall", annotations=DESTRUCTIVE)
    async def hd_hook_vmcall(
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook VMCALL (hypervisor call) instruction."""
        cmd = "!vmcall" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set vmcall hook: {cmd}",
            audit="hd_hook_vmcall",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_exception", annotations=DESTRUCTIVE)
    async def hd_hook_exception(
        ctx: Context,
        idt_index: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all exceptions or specific exception if idt_index >= 0."""
        cmd = "!exception"
        if idt_index >= 0:
            cmd += f" {idt_index:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set exception hook: {cmd}",
            audit="hd_hook_exception",
            kind="events",
            args={},
        )

    @mcp.tool(name="hd_hook_interrupt", annotations=DESTRUCTIVE)
    async def hd_hook_interrupt(
        idt_index: int,
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook specific interrupt by IDT index."""
        cmd = f"!interrupt {idt_index:#x}" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set interrupt {idt_index:#x} hook: {cmd}",
            audit="hd_hook_interrupt",
            kind="events",
            args={"idt_index": idt_index},
        )

    @mcp.tool(name="hd_hook_dr", annotations=DESTRUCTIVE)
    async def hd_hook_dr(
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook debug register access."""
        cmd = "!dr" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx, cmd, what=f"set dr hook: {cmd}", audit="hd_hook_dr", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_mode", annotations=DESTRUCTIVE)
    async def hd_hook_mode(
        mode: str,
        pid: int,
        ctx: Context,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Trap user/kernel mode transitions of process `pid` (mode: user|kernel|both).

        Run hd_preactivate first (mode-based execution traps must be preactivated).
        """
        m = choose(mode, _MODES, "mode")
        cmd = f"!mode {m}" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"trap {mode}-mode execution of process {pid:#x}: {cmd}",
            audit="hd_hook_mode",
            kind="events",
            args={"mode": mode, "pid": pid},
        )

    @mcp.tool(name="hd_hook_trace", annotations=DESTRUCTIVE)
    async def hd_hook_trace(
        trace_type: str,
        ctx: Context,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Trace execution as an event (trace_type: step-in|step-out|instrument-step)."""
        t = choose(trace_type, _TRACE_TYPES, "trace_type")
        cmd = f"!trace {t}" + _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set {t} trace event: {cmd}",
            audit="hd_hook_trace",
            kind="events",
            args={"trace_type": t},
        )

    @mcp.tool(name="hd_hook_crwrite", annotations=DESTRUCTIVE)
    async def hd_hook_crwrite(
        cr: int,
        ctx: Context,
        mask: str = "0",
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook writes to control register CR0 or CR4 (optional bit `mask`, hex string)."""
        if cr not in (0, 4):
            raise HyperDbgError(f"invalid cr {cr} (use 0 | 4)")
        cmd = f"!crwrite {cr}"
        m = parse_addr(mask)
        if m:
            cmd += f" mask {m:#x}"
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set CR{cr} write hook: {cmd}",
            audit="hd_hook_crwrite",
            kind="events",
            args={"cr": cr, "mask": m},
        )

    @mcp.tool(name="hd_hook_xsetbv", annotations=DESTRUCTIVE)
    async def hd_hook_xsetbv(
        ctx: Context,
        xcr: int = -1,
        pid: int = 0,
        core: int = 0,
        script: str = "",
        stage: str = "",
        short_circuit: bool = False,
    ) -> str | InputRequiredResult:
        """Hook all XSETBV instructions or a specific XCR if xcr >= 0."""
        cmd = "!xsetbv" + (f" {xcr:#x}" if xcr >= 0 else "")
        cmd += _suffix(pid, core, script, stage, short_circuit)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set xsetbv hook: {cmd}",
            audit="hd_hook_xsetbv",
            kind="events",
            args={"xcr": xcr},
        )

    # ----- resources hooks need before they are set ----------------------- #
    @mcp.tool(name="hd_prealloc", annotations=STATE)
    def hd_prealloc(kind: str, ctx: Context, count: int = 1) -> str:
        """Pre-allocate pools so many hooks/events can be set at once.

        kind: thread-interception|monitor|epthook|epthook2|regular-event|big-event|
        regular-safe-buffer|big-safe-buffer.
        """
        cmd = f"prealloc {choose(kind, _PREALLOC_TYPES, 'kind')} {count:#x}"
        return run_text(ctx, cmd, audit="hd_prealloc", kind="events", args={"kind": kind})

    @mcp.tool(name="hd_preactivate", annotations=STATE)
    def hd_preactivate(ctx: Context, feature: str = "mode") -> str:
        """Preactivate a feature before use (feature: mode, required by hd_hook_mode)."""
        cmd = f"preactivate {choose(feature, {'mode': 'mode'}, 'feature')}"
        return run_text(ctx, cmd, audit="hd_preactivate", kind="events", args={"feature": feature})
