"""
* @file tools_debugger.py
* @author munraimix
* @brief Debugger-side state: event output sources (output), the kernel message
*        buffer (flush), debugger settings, and transparent-mode timing (!measure).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import re

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import (
    DESTRUCTIVE,
    RO,
    STATE,
    choose,
    host_path,
    output_names,
    run_text,
    run_text_confirmed,
)

_OUTPUT_TYPES = {t: t for t in ("file", "namedpipe", "tcp", "module")}
_OUTPUT_ACTIONS = {"open": "open", "close": "close"}
_TCP_ADDRESS = re.compile(r"[\w.-]+:\d{1,5}")
# settings option -> allowed values (on/off switches, or the disassembly syntax)
_SETTINGS = {
    "autounpause": {"on", "off"},
    "autoflush": {"on", "off"},
    "addressconversion": {"on", "off"},
    "syntax": {"intel", "att", "masm"},
}


def _one_name(name: str) -> str:
    if "," in name:
        raise HyperDbgError(f"invalid name {name!r} (one name)")
    return output_names(name)


def register_debugger(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_output_list", annotations=RO)
    def hd_output_list(ctx: Context) -> str:
        """List event output sources (where events can send their output)."""
        return run_text(ctx, "output", audit="hd_output_list", kind="output")

    @mcp.tool(name="hd_flush", annotations=STATE)
    def hd_flush(ctx: Context) -> str:
        """Drop the messages still buffered in the kernel (e.g. after a noisy event)."""
        return run_text(ctx, "flush", audit="hd_flush", kind="output")

    @mcp.tool(name="hd_settings", annotations=STATE)
    def hd_settings(option: str, ctx: Context, value: str = "") -> str:
        """Show or change a debugger setting.

        option: autounpause | autoflush | addressconversion (on/off), or syntax
        (intel/att/masm, the disassembly syntax). Empty value shows the current one.
        """
        allowed = _SETTINGS.get(option)
        if allowed is None:
            raise HyperDbgError(f"invalid option {option!r} (use {' | '.join(_SETTINGS)})")
        if value and value not in allowed:
            raise HyperDbgError(
                f"invalid value {value!r} for {option} (use {' | '.join(sorted(allowed))})"
            )
        cmd = f"settings {option}" + (f" {value}" if value else "")
        return run_text(
            ctx, cmd, audit="hd_settings", kind="settings", args={"option": option, "value": value}
        )

    if read_only:
        return

    @mcp.tool(name="hd_output_create", annotations=DESTRUCTIVE)
    async def hd_output_create(
        name: str, output_type: str, address: str, ctx: Context
    ) -> str | InputRequiredResult:
        """Create an event output source; open it with hd_output, then pass its name
        as `output` to a hook.

        output_type / address: file (a path on the debugger host), namedpipe
        (\\\\.\\Pipe\\Name), tcp (host:port), or module (a DLL path that receives the
        output).
        """
        kind = choose(output_type, _OUTPUT_TYPES, "output_type")
        if kind == "tcp":
            if not _TCP_ADDRESS.fullmatch(address):
                raise HyperDbgError(f"invalid tcp address {address!r} (host:port)")
            target = address
        else:
            target = host_path(address, "address")
        cmd = f"output create {_one_name(name)} {kind} {target}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"create output source: {cmd}",
            audit="hd_output_create",
            kind="output",
            args={"name": name, "output_type": output_type, "address": address},
        )

    @mcp.tool(name="hd_output", annotations=DESTRUCTIVE)
    async def hd_output(action: str, name: str, ctx: Context) -> str | InputRequiredResult:
        """Open or close an output source created with hd_output_create."""
        cmd = f"output {choose(action, _OUTPUT_ACTIONS, 'action')} {_one_name(name)}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"{action} output source {name}",
            audit="hd_output",
            kind="output",
            args={"action": action, "name": name},
        )
