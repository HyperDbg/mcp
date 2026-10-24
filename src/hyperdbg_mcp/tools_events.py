"""
* @file tools_events.py
* @author munraimix
* @brief HyperDbg event management tools.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .toolkit import DESTRUCTIVE, RO, run_text, run_text_confirmed


def register_events(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_event_list", annotations=RO)
    def hd_event_list(ctx: Context) -> str:
        """List all debugger events."""
        cmd = "events"
        return run_text(ctx, cmd, audit="hd_event_list", kind="events")

    if read_only:
        return

    @mcp.tool(name="hd_event_enable", annotations=DESTRUCTIVE)
    async def hd_event_enable(target: str, ctx: Context) -> str | InputRequiredResult:
        """Enable debugger event(s) by target."""
        cmd = f"events e {target}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"enable events {target}",
            audit="hd_event_enable",
            kind="events",
            args={"target": target},
        )

    @mcp.tool(name="hd_event_disable", annotations=DESTRUCTIVE)
    async def hd_event_disable(target: str, ctx: Context) -> str | InputRequiredResult:
        """Disable debugger event(s) by target."""
        cmd = f"events d {target}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"disable events {target}",
            audit="hd_event_disable",
            kind="events",
            args={"target": target},
        )

    @mcp.tool(name="hd_event_clear", annotations=DESTRUCTIVE)
    async def hd_event_clear(target: str, ctx: Context) -> str | InputRequiredResult:
        """Clear debugger event(s) by target."""
        cmd = f"events c {target}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"clear events {target}",
            audit="hd_event_clear",
            kind="events",
            args={"target": target},
        )

    @mcp.tool(name="hd_event_sc", annotations=DESTRUCTIVE)
    async def hd_event_sc(state: str, ctx: Context) -> str | InputRequiredResult:
        """Set step-over event syscall handling (state: on|off)."""
        cmd = f"events sc {state}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set event syscall handling to {state}",
            audit="hd_event_sc",
            kind="events",
            args={"state": state},
        )
