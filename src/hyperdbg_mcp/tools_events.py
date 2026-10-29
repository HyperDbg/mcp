"""
* @file tools_events.py
* @author munraimix
* @brief HyperDbg event management tools.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .toolkit import DESTRUCTIVE, RO, choose, run_text, run_text_confirmed, token

_ON_OFF = {"on": "on", "off": "off"}


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
        """Enable event(s) by target: an event id (hex) or `all`."""
        cmd = f"events e {token(target, 'target')}"
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
        """Disable event(s) by target: an event id (hex) or `all`."""
        cmd = f"events d {token(target, 'target')}"
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
        """Clear event(s) by target: an event id (hex) or `all`."""
        cmd = f"events c {token(target, 'target')}"
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
        """Turn global event short-circuiting on|off (skip the trapped instruction)."""
        cmd = f"events sc {choose(state, _ON_OFF, 'state')}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set event short-circuiting {state}",
            audit="hd_event_sc",
            kind="events",
            args={"state": state},
        )
