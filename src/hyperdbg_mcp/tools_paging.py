"""
* @file tools_paging.py
* @author munraimix
* @brief HyperDbg virtual memory and paging tools.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from .toolkit import RO, parse_addr, run_text


def register_paging(mcp: FastMCP, *, read_only: bool) -> None:
    @mcp.tool(name="hd_va2pa", annotations=RO)
    def hd_va2pa(virtual_address: str, ctx: Context, pid: int = 0) -> str:
        """Convert virtual address (hex string) to physical address."""
        va = parse_addr(virtual_address)
        cmd = f"!va2pa {va:#x}"
        if pid:
            cmd += f" pid {pid:#x}"
        return run_text(ctx, cmd, audit="hd_va2pa", kind="paging", args={"virtual_address": va})

    @mcp.tool(name="hd_pa2va", annotations=RO)
    def hd_pa2va(physical_address: str, ctx: Context, pid: int = 0) -> str:
        """Convert physical address (hex string) to virtual address."""
        pa = parse_addr(physical_address)
        cmd = f"!pa2va {pa:#x}"
        if pid:
            cmd += f" pid {pid:#x}"
        return run_text(ctx, cmd, audit="hd_pa2va", kind="paging", args={"physical_address": pa})

    @mcp.tool(name="hd_pte", annotations=RO)
    def hd_pte(virtual_address: str, ctx: Context, pid: int = 0) -> str:
        """Display page table entry for virtual address (hex string)."""
        va = parse_addr(virtual_address)
        cmd = f"!pte {va:#x}"
        if pid:
            cmd += f" pid {pid:#x}"
        return run_text(ctx, cmd, audit="hd_pte", kind="paging", args={"virtual_address": va})

    @mcp.tool(name="hd_stack", annotations=RO)
    def hd_stack(ctx: Context, fmt: str = "calls", base: str = "0", length: int = 0) -> str:
        """Display stack trace (fmt: calls|params32|params64); base is an optional hex string."""
        cmd_map = {"calls": "k", "params32": "kd", "params64": "kq"}
        cmd = cmd_map.get(fmt, "k")
        base_addr = parse_addr(base)
        if base_addr:
            cmd += f" base {base_addr:#x}"
        if length:
            cmd += f" l {length:#x}"
        return run_text(ctx, cmd, audit="hd_stack", kind="paging", args={"fmt": fmt})
