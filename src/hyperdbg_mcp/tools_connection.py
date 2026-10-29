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
from mcp.server.mcpserver import Context, MCPServer

from .errors import HyperDbgError
from .toolkit import RO, STATE, app_ctx, choose

_TRANSPORTS = ("serial", "local", "pipe", "net")
_REATTACH = {m: m for m in ("auto", "always", "never")}


def _reattached(app) -> bool:
    return getattr(app.session, "reattached", False)


def _do_connect(
    session,
    transport: str,
    port: str,
    baudrate: int,
    pause: bool,
    pipe: str,
    ip: str,
    net_port: str,
    wait: float | None = None,
    reattach: str = "auto",
) -> bool:
    """Connect; False if a serial/pipe connect is still waiting for the handshake."""
    if transport == "serial":
        done = session.connect_remote_com(port, baudrate, pause=pause, wait=wait, reattach=reattach)
        return done is not False
    if transport == "local":
        session.connect_local()
    elif transport == "pipe":
        done = session.connect_remote_pipe(pipe, pause=pause, wait=wait, reattach=reattach)
        return done is not False
    elif transport == "net":
        session.connect_remote_net(ip, net_port)
    else:
        raise HyperDbgError(f"unknown transport {transport!r} (use one of {_TRANSPORTS})")
    return True


def _waiting(wait: float) -> str:
    return (
        f"connecting: no handshake from the debuggee within {wait:.0f}s; still waiting in the "
        "background (hd_connection_status shows connected= when it arrives). The first "
        "connect can take a minute or two. If it never arrives, the debuggee is bound to an "
        "earlier debugger session (it sends its handshake once per `.debug prepare`): "
        "restart it - reboot the VM / rerun `.debug prepare` - and this connect completes."
    )


def register_connection(mcp: MCPServer, *, read_only: bool) -> None:
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
        wait_seconds: int = 10,
        reattach: str = "auto",
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
        debuggee reinstalls its driver and synchronizes symbols. A serial/pipe
        connect returns after `wait_seconds` at most and keeps waiting for the
        debuggee in the background; check hd_connection_status.

        reattach ("auto" | "always" | "never"): a debuggee sends its handshake once
        per `.debug prepare`, so after its debugger died (e.g. this server was
        restarted) only a takeover reaches it. With a libhyperdbg that has
        `.debug remote ... reattach`, "auto" takes such a debuggee over and still
        handshakes with one that waits for a debugger; otherwise it is a plain
        handshake. "never" always handshakes.
        """
        a = app_ctx(ctx)
        if a.session.is_connected:
            return f"already connected ({a.session.mode}); hd_disconnect first"
        if getattr(a.session, "is_connecting", False):
            return "still connecting: waiting for the debuggee's handshake (hd_connection_status)"
        wait = float(max(1, min(wait_seconds, 50)))  # stay under clients' ~60 s tool timeout
        mode = choose(reattach, _REATTACH, "reattach")
        try:
            done = await anyio.to_thread.run_sync(
                _do_connect,
                a.session,
                transport,
                port,
                baudrate,
                pause,
                pipe,
                ip,
                net_port,
                wait,
                mode,
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
            reattach=mode,
        )
        if not done:
            a.audit.record("hd_connect", {"transport": transport, "port": port}, status="pending")
            return _waiting(wait)
        a.audit.record("hd_connect", {"transport": transport, "port": port}, status="ok")
        how = ", reattached to a debuggee left by an earlier debugger" if _reattached(a) else ""
        return f"connected ({a.session.mode}, transport={transport}{how})"

    @mcp.tool(name="hd_disconnect", annotations=STATE)
    async def hd_disconnect(ctx: Context) -> str:
        """Cleanly detach: resume the debuggee, then send the close packet. Idempotent.

        Always prefer this over killing the server, so the debuggee is never
        stranded mid-frame (the case the serial resync fix guards against).
        """
        a = app_ctx(ctx)
        if getattr(a.session, "is_connecting", False):
            return (
                "a connect is still waiting for the debuggee's handshake and libhyperdbg cannot "
                "abort it: restart the debuggee to let it complete, or restart this server "
                "to drop it"
            )
        await anyio.to_thread.run_sync(a.session.close)
        a.audit.record("hd_disconnect", {}, status="ok")
        return "disconnected (resume + clean close sent)"

    @mcp.tool(name="hd_reconnect", annotations=STATE)
    async def hd_reconnect(ctx: Context) -> str:
        """Cleanly disconnect, then reconnect with the last-used settings."""
        a = app_ctx(ctx)
        if not last:
            return "no previous connection to repeat; use hd_connect first"
        if getattr(a.session, "is_connecting", False):
            return "still connecting: waiting for the debuggee's handshake (hd_connection_status)"
        await anyio.to_thread.run_sync(a.session.close)
        try:
            done = await anyio.to_thread.run_sync(
                _do_connect,
                a.session,
                last["transport"],
                last["port"],
                last["baudrate"],
                last["pause"],
                last["pipe"],
                last["ip"],
                last["net_port"],
                10.0,
                last["reattach"],
            )
        except HyperDbgError as exc:
            a.audit.record("hd_reconnect", {}, status="error")
            return f"reconnect failed: {exc}"
        if not done:
            return _waiting(10.0)
        a.audit.record("hd_reconnect", {}, status="ok")
        return f"reconnected ({a.session.mode})"

    @mcp.tool(name="hd_connection_status", annotations=RO)
    def hd_connection_status(ctx: Context) -> str:
        """Report whether the debugger is attached and in which mode."""
        s = app_ctx(ctx).session
        running = getattr(s, "is_running", False)
        out = f"connected={s.is_connected}, mode={s.mode}, running={running}"
        if getattr(s, "reattached", False):
            out += ", reattached=True"
        if getattr(s, "is_connecting", False):
            out += ", connecting=True (waiting for the debuggee's handshake)"
        elif not s.is_connected and getattr(s, "last_connect_error", None):
            out += f"\nlast connect failed: {s.last_connect_error}"
        return out
