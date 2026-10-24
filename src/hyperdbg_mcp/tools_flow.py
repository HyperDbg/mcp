"""
* @file tools_flow.py
* @author munraimix
* @brief HyperDbg flow control tools (breakpoints, process/thread switching).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .toolkit import DESTRUCTIVE, RO, run_text, run_text_confirmed


def register_flow(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_bp_list", annotations=RO)
    def hd_bp_list(ctx: Context) -> str:
        """List all breakpoints."""
        return run_text(ctx, "bl", audit="hd_bp_list", kind="breakpoints")

    if read_only:
        return

    @mcp.tool(name="hd_bp_modify", annotations=DESTRUCTIVE)
    async def hd_bp_modify(
        breakpoint_id: int, action: str, ctx: Context
    ) -> str | InputRequiredResult:
        """Modify breakpoint state (action: enable|disable|clear)."""
        cmd_map = {"enable": "be", "disable": "bd", "clear": "bc"}
        cmd = cmd_map.get(action, "be")
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
