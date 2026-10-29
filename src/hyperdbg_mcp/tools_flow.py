"""
* @file tools_flow.py
* @author munraimix
* @brief HyperDbg flow control tools (breakpoints, cores, process/thread switching,
*        user-mode process lifecycle).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import DESTRUCTIVE, RO, STATE, choose, run_text, run_text_confirmed


def register_flow(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_bp_list", annotations=RO)
    def hd_bp_list(ctx: Context) -> str:
        """List all breakpoints."""
        return run_text(ctx, "bl", audit="hd_bp_list", kind="breakpoints")

    @mcp.tool(name="hd_core_switch", annotations=STATE)
    def hd_core_switch(ctx: Context, core: int = -1) -> str:
        """Show the operating core (core < 0) or switch the halted debugger to `core`.

        Registers, stack and per-core reads all follow the operating core.
        """
        cmd = "~" if core < 0 else f"~ {core:#x}"
        return run_text(ctx, cmd, audit="hd_core_switch", kind="flow", args={"core": core})

    if read_only:
        return

    @mcp.tool(name="hd_bp_modify", annotations=DESTRUCTIVE)
    async def hd_bp_modify(
        breakpoint_id: int, action: str, ctx: Context
    ) -> str | InputRequiredResult:
        """Modify breakpoint state (action: enable|disable|clear)."""
        cmd_map = {"enable": "be", "disable": "bd", "clear": "bc"}
        cmd = choose(action, cmd_map, "action")
        cmd_str = f"{cmd} {breakpoint_id:#x}"
        return await run_text_confirmed(
            ctx,
            cmd_str,
            what=f"{action} breakpoint {breakpoint_id:#x}",
            audit="hd_bp_modify",
            kind="breakpoints",
            args={"breakpoint_id": breakpoint_id, "action": action},
        )

    @mcp.tool(name="hd_process_switch", annotations=DESTRUCTIVE)
    async def hd_process_switch(
        ctx: Context, pid: int = 0, eprocess: int = 0, list_only: bool = False
    ) -> str | InputRequiredResult:
        """Switch process context (list_only lists processes, pid or eprocess to switch)."""
        if list_only:
            cmd = ".process list"
            what = "list processes"
        elif pid:
            cmd = f".process pid {pid:#x}"
            what = f"switch to process {pid:#x}"
        elif eprocess:
            cmd = f".process process {eprocess:#x}"
            what = f"switch to process {eprocess:#x}"
        else:
            cmd = ".process list"
            what = "list processes"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=what,
            audit="hd_process_switch",
            kind="process",
            args={"pid": pid, "eprocess": eprocess},
        )

    @mcp.tool(name="hd_thread_switch", annotations=DESTRUCTIVE)
    async def hd_thread_switch(
        ctx: Context, tid: int = 0, ethread: int = 0, list_only: bool = False
    ) -> str | InputRequiredResult:
        """Switch thread context (list_only lists threads, tid or ethread to switch)."""
        if list_only:
            cmd = ".thread list"
            what = "list threads"
        elif tid:
            cmd = f".thread tid {tid:#x}"
            what = f"switch to thread {tid:#x}"
        elif ethread:
            cmd = f".thread thread {ethread:#x}"
            what = f"switch to thread {ethread:#x}"
        else:
            cmd = ".thread list"
            what = "list threads"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=what,
            audit="hd_thread_switch",
            kind="thread",
            args={"tid": tid, "ethread": ethread},
        )

    # ----- user-mode debugging (VMI mode): attach / detach / kill / restart -- #
    @mcp.tool(name="hd_process_attach", annotations=DESTRUCTIVE)
    async def hd_process_attach(pid: int, ctx: Context) -> str | InputRequiredResult:
        """Attach to a running user-mode process by pid (VMI mode)."""
        cmd = f".attach pid {pid:#x}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"attach to process {pid:#x}: {cmd}",
            audit="hd_process_attach",
            kind="process",
            args={"pid": pid},
        )

    @mcp.tool(name="hd_process_detach", annotations=DESTRUCTIVE)
    async def hd_process_detach(ctx: Context) -> str | InputRequiredResult:
        """Detach from the user-mode process being debugged."""
        return await run_text_confirmed(
            ctx,
            ".detach",
            what="detach from the debugged process: .detach",
            audit="hd_process_detach",
            kind="process",
        )

    @mcp.tool(name="hd_process_kill", annotations=DESTRUCTIVE)
    async def hd_process_kill(ctx: Context) -> str | InputRequiredResult:
        """Terminate the user-mode process being debugged."""
        return await run_text_confirmed(
            ctx,
            ".kill",
            what="TERMINATE the debugged process: .kill",
            audit="hd_process_kill",
            kind="process",
        )

    @mcp.tool(name="hd_process_restart", annotations=DESTRUCTIVE)
    async def hd_process_restart(ctx: Context) -> str | InputRequiredResult:
        """Kill and re-start the process previously launched with hd_process_start."""
        return await run_text_confirmed(
            ctx,
            ".restart",
            what="kill and restart the started process: .restart",
            audit="hd_process_restart",
            kind="process",
        )

    @mcp.tool(name="hd_user_thread_switch", annotations=STATE)
    def hd_user_thread_switch(ctx: Context, pid: int = 0, tid: int = 0) -> str:
        """List attached user-mode threads (no args) or switch to one by pid or tid."""
        if pid and tid:
            raise HyperDbgError("pass pid or tid, not both")
        cmd = f".switch pid {pid:#x}" if pid else f".switch tid {tid:#x}" if tid else ".switch list"
        return run_text(
            ctx, cmd, audit="hd_user_thread_switch", kind="process", args={"pid": pid, "tid": tid}
        )
