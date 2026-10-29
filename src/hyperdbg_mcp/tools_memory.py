"""
* @file tools_memory.py
* @author munraimix
* @brief Memory display, search, and editing tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import re

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import DESTRUCTIVE, RO, choose, hex_values, resolve_addr, run_text, run_text_confirmed

_DISPLAY = {
    "byte": "db",
    "word": "dw",
    "dword": "dd",
    "qword": "dq",
    "char": "dc",
    "ascii": "da",
    "dword_sym": "dds",
    "qword_sym": "dqs",
    "ptr_sym": "dps",
}
_SEARCH = {"byte": "sb", "dword": "sd", "qword": "sq"}
_EDIT = {"byte": "eb", "dword": "ed", "qword": "eq"}


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
        """Display debuggee memory at address (hex string).

        fmt: byte|word|dword|qword|char|ascii, or dword_sym|qword_sym|ptr_sym to
        resolve each value to a symbol (dds/dqs/dps - the way to read a stack).
        """
        addr = resolve_addr(ctx, address)
        base = choose(fmt, _DISPLAY, "fmt")
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
        addr = resolve_addr(ctx, address)
        base = choose(fmt, _SEARCH, "fmt")
        if physical:
            base = "!" + base
        cmd = f"{base} {addr:#x} {hex_values(value)}"
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
        addr = resolve_addr(ctx, address)
        base = choose(fmt, _EDIT, "fmt")
        if physical:
            base = "!" + base
        cmd = f"{base} {addr:#x} {hex_values(value)}" + (f" pid {pid:#x}" if pid else "")
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"edit memory at {addr:#x}: {cmd}",
            audit="hd_mem_edit",
            kind="memory",
            args={"address": addr},
        )

    @mcp.tool(name="hd_pagein", annotations=DESTRUCTIVE)
    async def hd_pagein(
        address: str, ctx: Context, length: int = 0, mode: str = ""
    ) -> str | InputRequiredResult:
        """Page a paged-out range into RAM by injecting a #PF into the debuggee.

        Use it when a read fails on a valid but non-resident address; continue the
        debuggee afterwards so the fault is served. mode: any of p (present),
        w (write), u (user), f (fetch), e.g. "wu"; empty = kernel read.
        """
        if not re.fullmatch(r"[pwuf]{0,4}", mode) or len(set(mode)) != len(mode):
            raise HyperDbgError(f"invalid mode {mode!r} (letters from p, w, u, f, each once)")
        addr = resolve_addr(ctx, address)
        cmd = ".pagein" + (f" {mode}" if mode else "") + f" {addr:#x}"
        if length:
            cmd += f" l {length:#x}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"inject a page fault to page in {addr:#x}: {cmd}",
            audit="hd_pagein",
            kind="memory",
            args={"address": addr, "length": length, "mode": mode},
        )
