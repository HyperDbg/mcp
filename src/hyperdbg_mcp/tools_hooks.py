"""
* @file tools_hooks.py
* @author munraimix
* @brief HyperDbg hook tools (ept, syscall, cpuid, msr, io, exception, interrupt, dr, tsc, pmc).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from .toolkit import DESTRUCTIVE, parse_addr, run_text_confirmed


def _suffix(pid: int, core: int, script: str) -> str:
    """Build suffix string from pid, core, and script parameters."""
    parts = []
    if pid:
        parts.append(f" pid {pid:#x}")
    if core:
        parts.append(f" core {core:#x}")
    if script:
        parts.append(f" script {{ {script} }}")
    return "".join(parts)


def register_hooks(mcp: FastMCP, *, read_only: bool) -> None:
    if read_only:
        return

    @mcp.tool(name="hd_hook_ept", annotations=DESTRUCTIVE)
    async def hd_hook_ept(
        address: str, ctx: Context, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Set EPT (Extended Page Tables) hook at address (hex string)."""
        addr = parse_addr(address)
        cmd = f"!epthook {addr:#x}" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set ept hook at {addr:#x}",
            audit="hd_hook_ept",
            kind="events",
            args={"address": addr},
        )

    @mcp.tool(name="hd_hook_ept2", annotations=DESTRUCTIVE)
    async def hd_hook_ept2(
        address: str, ctx: Context, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Set EPT2 (Extended Page Tables 2) hook at address (hex string)."""
        addr = parse_addr(address)
        cmd = f"!epthook2 {addr:#x}" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set ept2 hook at {addr:#x}",
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
    ) -> str:
        """Monitor memory attribute (read/write) in an address range (hex strings)."""
        frm = parse_addr(from_address)
        to = parse_addr(to_address)
        cmd = f"!monitor {attribute} {frm:#x} {to:#x}" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set monitor hook on {attribute}",
            audit="hd_hook_monitor",
            kind="events",
            args={"attribute": attribute, "from_address": frm, "to_address": to},
        )

    @mcp.tool(name="hd_hook_syscall", annotations=DESTRUCTIVE)
    async def hd_hook_syscall(
        ctx: Context, syscall_number: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all syscalls or specific syscall if syscall_number >= 0."""
        cmd = "!syscall"
        if syscall_number >= 0:
            cmd += f" {syscall_number:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set syscall hook", audit="hd_hook_syscall", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_sysret", annotations=DESTRUCTIVE)
    async def hd_hook_sysret(ctx: Context, pid: int = 0, core: int = 0, script: str = "") -> str:
        """Hook sysret (return from syscall) instruction."""
        cmd = "!sysret" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set sysret hook", audit="hd_hook_sysret", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_cpuid", annotations=DESTRUCTIVE)
    async def hd_hook_cpuid(
        ctx: Context, eax: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all CPUID or specific function if eax >= 0."""
        cmd = "!cpuid"
        if eax >= 0:
            cmd += f" {eax:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set cpuid hook", audit="hd_hook_cpuid", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_msrread", annotations=DESTRUCTIVE)
    async def hd_hook_msrread(
        ctx: Context, msr: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all MSR reads or specific MSR if msr >= 0."""
        cmd = "!msrread"
        if msr >= 0:
            cmd += f" {msr:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set msrread hook", audit="hd_hook_msrread", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_msrwrite", annotations=DESTRUCTIVE)
    async def hd_hook_msrwrite(
        ctx: Context, msr: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all MSR writes or specific MSR if msr >= 0."""
        cmd = "!msrwrite"
        if msr >= 0:
            cmd += f" {msr:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set msrwrite hook", audit="hd_hook_msrwrite", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_tsc", annotations=DESTRUCTIVE)
    async def hd_hook_tsc(ctx: Context, pid: int = 0, core: int = 0, script: str = "") -> str:
        """Hook TSC (Time Stamp Counter) instruction."""
        cmd = "!tsc" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set tsc hook", audit="hd_hook_tsc", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_pmc", annotations=DESTRUCTIVE)
    async def hd_hook_pmc(ctx: Context, pid: int = 0, core: int = 0, script: str = "") -> str:
        """Hook PMC (Performance Monitoring Counters)."""
        cmd = "!pmc" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set pmc hook", audit="hd_hook_pmc", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_ioin", annotations=DESTRUCTIVE)
    async def hd_hook_ioin(
        ctx: Context, port: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all IN instructions or specific port if port >= 0."""
        cmd = "!ioin"
        if port >= 0:
            cmd += f" {port:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set ioin hook", audit="hd_hook_ioin", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_ioout", annotations=DESTRUCTIVE)
    async def hd_hook_ioout(
        ctx: Context, port: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all OUT instructions or specific port if port >= 0."""
        cmd = "!ioout"
        if port >= 0:
            cmd += f" {port:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set ioout hook", audit="hd_hook_ioout", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_vmcall", annotations=DESTRUCTIVE)
    async def hd_hook_vmcall(ctx: Context, pid: int = 0, core: int = 0, script: str = "") -> str:
        """Hook VMCALL (hypervisor call) instruction."""
        cmd = "!vmcall" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set vmcall hook", audit="hd_hook_vmcall", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_exception", annotations=DESTRUCTIVE)
    async def hd_hook_exception(
        ctx: Context, idt_index: int = -1, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook all exceptions or specific exception if idt_index >= 0."""
        cmd = "!exception"
        if idt_index >= 0:
            cmd += f" {idt_index:#x}"
        cmd += _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set exception hook", audit="hd_hook_exception", kind="events", args={}
        )

    @mcp.tool(name="hd_hook_interrupt", annotations=DESTRUCTIVE)
    async def hd_hook_interrupt(
        idt_index: int, ctx: Context, pid: int = 0, core: int = 0, script: str = ""
    ) -> str:
        """Hook specific interrupt by IDT index."""
        cmd = f"!interrupt {idt_index:#x}" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set interrupt {idt_index:#x} hook",
            audit="hd_hook_interrupt",
            kind="events",
            args={"idt_index": idt_index},
        )

    @mcp.tool(name="hd_hook_dr", annotations=DESTRUCTIVE)
    async def hd_hook_dr(ctx: Context, pid: int = 0, core: int = 0, script: str = "") -> str:
        """Hook debug register access."""
        cmd = "!dr" + _suffix(pid, core, script)
        return await run_text_confirmed(
            ctx, cmd, what="set dr hook", audit="hd_hook_dr", kind="events", args={}
        )
