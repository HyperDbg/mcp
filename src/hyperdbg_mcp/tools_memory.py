"""
* @file tools_memory.py
* @author munraimix
* @brief Memory display, search, and editing tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .toolkit import DESTRUCTIVE, RO, parse_addr, run_text, run_text_confirmed


def register_memory(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_mem_display", annotations=RO)
    def hd_mem_display(
        address: str,
        ctx: Context,
        size: int = 0x80,
        fmt: str = "byte",
        pid: int = 0,
        physical: bool = False,
    ) -> str:
        """Display debuggee memory at address (hex string; fmt: byte|char|dword|qword)."""
        addr = parse_addr(address)
        base = {"byte": "db", "char": "dc", "dword": "dd", "qword": "dq"}.get(fmt, "db")
        if physical:
            base = "!" + base
        # HyperDbg length modifier is `l <hex>` (hardware-confirmed: bare/`L`
        # length is rejected - see the `u`-command fix in tools.py).
        cmd = f"{base} {addr:#x} l {size:#x}" + (f" pid {pid:#x}" if pid else "")
        return run_text(
            ctx, cmd, audit="hd_mem_display", kind="memory", args={"address": addr, "size": size}
        )

    @mcp.tool(name="hd_mem_search", annotations=RO)
    def hd_mem_search(
        address: str,
        value: str,
        ctx: Context,
        fmt: str = "byte",
        length: int = 0,
        pid: int = 0,
        physical: bool = False,
    ) -> str:
        """Search memory for `value` from `address` (hex string; fmt: byte|dword|qword)."""
        addr = parse_addr(address)
        base = {"byte": "sb", "dword": "sd", "qword": "sq"}.get(fmt, "sb")
        if physical:
            base = "!" + base
        cmd = f"{base} {addr:#x} {value}"
        if length:
            cmd += f" l {length:#x}"
        if pid:
            cmd += f" pid {pid:#x}"
        return run_text(
            ctx,
            cmd,
            audit="hd_mem_search",
            kind="memory",
            args={"address": addr, "value": value},
        )

    if read_only:
        return

    @mcp.tool(name="hd_mem_edit", annotations=DESTRUCTIVE)
    async def hd_mem_edit(
        address: str,
        value: str,
        ctx: Context,
        fmt: str = "byte",
        pid: int = 0,
        physical: bool = False,
    ) -> str | InputRequiredResult:
        """Edit debuggee memory at address (hex string; fmt: byte|dword|qword)."""
        addr = parse_addr(address)
        base = {"byte": "eb", "dword": "ed", "qword": "eq"}.get(fmt, "eb")
        if physical:
            base = "!" + base
        cmd = f"{base} {addr:#x} {value}" + (f" pid {pid:#x}" if pid else "")
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"edit memory at {addr:#x}",
            audit="hd_mem_edit",
            kind="memory",
            args={"address": addr},
        )
