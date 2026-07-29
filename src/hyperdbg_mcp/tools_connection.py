"""
* @file tools_connection.py
* @author munraimix
* @brief Lazy connect / disconnect / reconnect tools.
* @copyright This project is released under the GNU Public License v3.
*
* These let the server start instantly and attach to a target on demand, which
* is how an MCP client (Claude Code, Desktop, etc.) expects to launch it: the
* client spawns the server at session start, then the agent connects to
* whatever the user has (local VMI, or Debugger Mode over serial/pipe/net).
* Connecting at startup instead would block the client's init handshake, since
* the first serial connect reinstalls the debuggee driver and syncs symbols.
*
* Connection management is registered even under --read-only: attaching and
* detaching is not a target mutation, and you must be able to connect to read.
"""

from __future__ import annotations

import anyio
from mcp.server.fastmcp import Context, FastMCP

from .errors import HyperDbgError
from .toolkit import RO, STATE, app_ctx

_TRANSPORTS = ("serial", "local", "pipe", "net")


def _do_connect(
    session,
    transport: str,
    port: str,
    baudrate: int,
    pause: bool,
    pipe: str,
    ip: str,
    net_port: str,
) -> None:
    if transport == "serial":
        session.connect_remote_com(port, baudrate, pause=pause)
    elif transport == "local":
        session.connect_local()
    elif transport == "pipe":
        session.connect_remote_pipe(pipe, pause=pause)
    elif transport == "net":
        session.connect_remote_net(ip, net_port)
    else:
        raise HyperDbgError(f"unknown transport {transport!r} (use one of {_TRANSPORTS})")


def register_connection(mcp: FastMCP, *, read_only: bool) -> None:
    # Remember the last successful connect so hd_reconnect can repeat it.
    last: dict[str, object] = {}

    @mcp.tool(name="hd_connect", annotations=STATE)
    async def hd_connect(
        ctx: Context,
        transport: str = "serial",
        port: str = "com4",
        baudrate: int = 115200,
        pause: bool = True,
        pipe: str = "",
        ip: str = "",
        net_port: str = "",
    ) -> str:
        """Attach the debugger to a target.

        transport:
          - "serial": Debugger Mode over a COM port (`port`, `baudrate`).
            pause=True halts the debuggee on connect, giving a valid CPU context
            for register/memory reads; resume later with hd_exec_continue.
          - "local": local VMI mode (single machine, via the local hypervisor).
          - "pipe": Debugger Mode over a named pipe (`pipe`).
          - "net": Debugger Mode over TCP (`ip`, `net_port`).

        The first serial/pipe connect can take a minute or two while the
        debuggee reinstalls its driver and synchronizes symbols.
        """
        a = app_ctx(ctx)
        if a.session.is_connected:
            return f"already connected ({a.session.mode}); hd_disconnect first"
        try:
            await anyio.to_thread.run_sync(
                _do_connect, a.session, transport, port, baudrate, pause, pipe, ip, net_port
            )
        except HyperDbgError as exc:
            a.audit.record("hd_connect", {"transport": transport}, status="error")
            return f"connect failed: {exc}"
        last.update(
            transport=transport,
            port=port,
            baudrate=baudrate,
            pause=pause,
            pipe=pipe,
            ip=ip,
            net_port=net_port,
        )
        a.audit.record("hd_connect", {"transport": transport, "port": port}, status="ok")
        return f"connected ({a.session.mode}, transport={transport})"

    @mcp.tool(name="hd_disconnect", annotations=STATE)
    async def hd_disconnect(ctx: Context) -> str:
        """Cleanly detach: resume the debuggee, then send the close packet. Idempotent.

        Always prefer this over killing the server, so the debuggee is never
        stranded mid-frame (the case the serial resync fix guards against).
        """
        a = app_ctx(ctx)
        await anyio.to_thread.run_sync(a.session.close)
        a.audit.record("hd_disconnect", {}, status="ok")
        return "disconnected (resume + clean close sent)"

    @mcp.tool(name="hd_reconnect", annotations=STATE)
    async def hd_reconnect(ctx: Context) -> str:
        """Cleanly disconnect, then reconnect with the last-used settings."""
        a = app_ctx(ctx)
        if not last:
            return "no previous connection to repeat; use hd_connect first"
        await anyio.to_thread.run_sync(a.session.close)
        try:
            await anyio.to_thread.run_sync(
                _do_connect,
                a.session,
                last["transport"],
                last["port"],
                last["baudrate"],
                last["pause"],
                last["pipe"],
                last["ip"],
                last["net_port"],
            )
        except HyperDbgError as exc:
            a.audit.record("hd_reconnect", {}, status="error")
            return f"reconnect failed: {exc}"
        a.audit.record("hd_reconnect", {}, status="ok")
        return f"reconnected ({a.session.mode})"

    @mcp.tool(name="hd_connection_status", annotations=RO)
    def hd_connection_status(ctx: Context) -> str:
        """Report whether the debugger is attached and in which mode."""
        s = app_ctx(ctx).session
        return f"connected={s.is_connected}, mode={s.mode}"
