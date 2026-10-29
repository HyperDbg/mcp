"""
* @file tools_symbols.py
* @author munraimix
* @brief Symbol and type information tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer

from .errors import HyperDbgError
from .safety import wrap_untrusted
from .toolkit import RO, STATE, app_ctx, host_path, resolve_addr, run_text, token


def _type_text(ctx: Context, cmd: str, *, audit: str, type_name: str) -> str:
    """run_text for dt/struct, which print nothing at all for an unknown type."""
    app = app_ctx(ctx)
    out = app.session.run_command(cmd)
    if not out.strip():
        raise HyperDbgError(
            f"type {type_name!r} not found (module!_TYPE, e.g. nt!_EPROCESS; "
            "symbols loaded with hd_sym_path + hd_sym_reload?)"
        )
    app.audit.record(audit, {"type_name": type_name}, status="ok")
    return wrap_untrusted(out, "symbols")


def register_symbols(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_sym_examine", annotations=RO)
    def hd_sym_examine(pattern: str, ctx: Context) -> str:
        """Examine symbol by pattern."""
        cmd = f"x {token(pattern, 'pattern')}"
        return run_text(ctx, cmd, audit="hd_sym_examine", kind="symbols", args={"pattern": pattern})

    @mcp.tool(name="hd_struct_display", annotations=RO)
    def hd_struct_display(type_name: str, ctx: Context, address: str = "0", pid: int = 0) -> str:
        """Display struct type definition, optionally at `address` (hex string)."""
        cmd = f"dt {token(type_name, 'type_name')}"
        addr = resolve_addr(ctx, address)
        if addr:
            cmd += f" {addr:#x}"
        if pid:
            cmd += f" pid {pid:#x}"
        return _type_text(ctx, cmd, audit="hd_struct_display", type_name=type_name)

    @mcp.tool(name="hd_struct_export", annotations=RO)
    def hd_struct_export(type_name: str, ctx: Context) -> str:
        """Export struct type definition."""
        cmd = f"struct {token(type_name, 'type_name')}"
        return _type_text(ctx, cmd, audit="hd_struct_export", type_name=type_name)

    @mcp.tool(name="hd_pe_parse", annotations=RO)
    def hd_pe_parse(path: str, ctx: Context, section: str = "") -> str:
        """Parse a PE file on the debugger host: headers, or dump one `section` (.text).

        Section dumps are capped by HyperDbg at 1 MiB per section, 4 MiB total.
        """
        what = f"section {token(section, 'section')}" if section else "header"
        cmd = f".pe {what} {host_path(path)}"
        return run_text(ctx, cmd, audit="hd_pe_parse", kind="pe", args={"path": path})

    @mcp.tool(name="hd_sym_path", annotations=STATE)
    def hd_sym_path(path: str, ctx: Context) -> str:
        """Set symbol search path."""
        cmd = f".sympath {token(path, 'path')}"
        return run_text(ctx, cmd, audit="hd_sym_path", kind="symbols", args={"path": path})

    @mcp.tool(name="hd_sym_reload", annotations=STATE)
    def hd_sym_reload(ctx: Context) -> str:
        """Reload all symbols."""
        cmd = ".sym reload"
        return run_text(ctx, cmd, audit="hd_sym_reload", kind="symbols", args={})
