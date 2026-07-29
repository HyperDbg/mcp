"""
* @file tools_symbols.py
* @author munraimix
* @brief Symbol and type information tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.fastmcp import Context, FastMCP

from .toolkit import RO, parse_addr, run_text


def register_symbols(mcp: FastMCP, *, read_only: bool) -> None:
    @mcp.tool(name="hd_sym_examine", annotations=RO)
    def hd_sym_examine(pattern: str, ctx: Context) -> str:
        """Examine symbol by pattern."""
        cmd = f"x {pattern}"
        return run_text(ctx, cmd, audit="hd_sym_examine", kind="symbols", args={"pattern": pattern})

    @mcp.tool(name="hd_struct_display", annotations=RO)
    def hd_struct_display(type_name: str, ctx: Context, address: str = "0", pid: int = 0) -> str:
        """Display struct type definition, optionally at `address` (hex string)."""
        cmd = f"dt {type_name}"
        addr = parse_addr(address)
        if addr:
            cmd += f" {addr:#x}"
        if pid:
            cmd += f" pid {pid:#x}"
        return run_text(
            ctx, cmd, audit="hd_struct_display", kind="symbols", args={"type_name": type_name}
        )

    @mcp.tool(name="hd_struct_export", annotations=RO)
    def hd_struct_export(type_name: str, ctx: Context) -> str:
        """Export struct type definition."""
        cmd = f"struct {type_name}"
        return run_text(
            ctx, cmd, audit="hd_struct_export", kind="symbols", args={"type_name": type_name}
        )

    @mcp.tool(name="hd_sym_path", annotations=RO)
    def hd_sym_path(path: str, ctx: Context) -> str:
        """Set symbol search path."""
        cmd = f".sympath {path}"
        return run_text(ctx, cmd, audit="hd_sym_path", kind="symbols", args={"path": path})

    @mcp.tool(name="hd_sym_reload", annotations=RO)
    def hd_sym_reload(ctx: Context) -> str:
        """Reload all symbols."""
        cmd = ".sym reload"
        return run_text(ctx, cmd, audit="hd_sym_reload", kind="symbols", args={})
