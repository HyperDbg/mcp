"""
 * @file server.py
 * @author munraimix
 * @brief MCP server entry point for HyperDbg.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import argparse
import atexit
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server.fastmcp import FastMCP

from .safety import AuditLog
from .session import HyperDbgSession
from .tools import register_tools
from .tools_connection import register_connection
from .tools_events import register_events
from .tools_flow import register_flow
from .tools_hooks import register_hooks
from .tools_hw import register_hw
from .tools_memory import register_memory
from .tools_paging import register_paging
from .tools_sdk import register_sdk
from .tools_symbols import register_symbols
from .tools_system import register_system

# Every domain module's register_<domain>(mcp, *, read_only) entry point.
_TOOL_MODULES = (
    register_connection,
    register_memory,
    register_symbols,
    register_paging,
    register_flow,
    register_system,
    register_hooks,
    register_events,
    register_sdk,
    register_hw,
)


@dataclass
class AppContext:
    session: HyperDbgSession
    audit: AuditLog
    read_only: bool


def build_server(
    *,
    read_only: bool,
    lib_path: str | None,
    audit_path: str,
    session_factory: Callable[[], HyperDbgSession] | None = None,
    connect: Callable[[HyperDbgSession], None] | None = None,
) -> FastMCP:
    audit = AuditLog(audit_path)

    def _default_factory() -> HyperDbgSession:
        return HyperDbgSession(dll=None if lib_path is None else _load(lib_path))

    factory = session_factory or _default_factory
    # None => lazy: the client attaches on demand via the hd_connect tool. A
    # startup connect would block the MCP client's init handshake, since the
    # first serial connect reinstalls the debuggee driver and syncs symbols.
    do_connect = connect

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[AppContext]:
        session = factory()
        if do_connect is not None:
            do_connect(session)
        # Backstop: ensure the graceful disconnect runs even on interpreter
        # exit. close() is idempotent, so the finally + atexit can't double-act.
        atexit.register(session.close)
        try:
            yield AppContext(session=session, audit=audit, read_only=read_only)
        finally:
            atexit.unregister(session.close)
            session.close()

    mcp = FastMCP("hyperdbg-mcp", lifespan=lifespan)
    register_tools(mcp, read_only=read_only)
    for register in _TOOL_MODULES:
        register(mcp, read_only=read_only)
    return mcp


def _load(lib_path: str):
    from .ffi import load_libhyperdbg

    return load_libhyperdbg(lib_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="HyperDbg MCP server")
    parser.add_argument(
        "--read-only",
        action="store_true",
        help=(
            "Register only non-mutating tools: reads, disassembly, module list, "
            "and execution control (continue/pause/step). Excludes arbitrary "
            "commands, breakpoints, and memory/register/script writes."
        ),
    )
    parser.add_argument(
        "--lib-path",
        default=None,
        help="Path to libhyperdbg.dll (else HYPERDBG_LIB_PATH / default search).",
    )
    parser.add_argument(
        "--audit-log",
        default="audit-hyperdbg-mcp.jsonl",
        help="Append-only audit log path.",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run against an in-process mock backend (no HyperDbg / DLL required).",
    )
    # Auto-connect at startup. Default (no flag) is lazy: the client attaches
    # on demand via the hd_connect tool, which is the right model for an MCP
    # server launched by a client.
    parser.add_argument(
        "--local",
        action="store_true",
        help="Auto-connect local VMI mode at startup (default: lazy; attach via hd_connect).",
    )
    parser.add_argument("--remote-com", default=None, help="Connect over a COM port, e.g. com4.")
    parser.add_argument("--baudrate", type=int, default=115200, help="Baud rate for --remote-com.")
    parser.add_argument("--remote-pipe", default=None, help="Connect over a named pipe.")
    parser.add_argument("--remote-net", default=None, help="Connect over TCP as IP:PORT.")
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Do not halt the debuggee on connect (default: pause for a valid CPU context).",
    )
    args = parser.parse_args()

    session_factory = None
    if args.mock:
        from .mock import MockSession

        session_factory = MockSession

    pause = not args.no_pause
    connect: Callable[[HyperDbgSession], None] | None = None
    if args.remote_com:
        def connect(s):
            s.connect_remote_com(args.remote_com, args.baudrate, pause=pause)
    elif args.remote_pipe:
        def connect(s):
            s.connect_remote_pipe(args.remote_pipe, pause=pause)
    elif args.remote_net:
        ip, _, port = args.remote_net.partition(":")
        def connect(s):
            s.connect_remote_net(ip, port)
    elif args.local:
        def connect(s):
            s.connect_local()
    # else: lazy - attach on demand via the hd_connect tool

    server = build_server(
        read_only=args.read_only,
        lib_path=args.lib_path,
        audit_path=args.audit_log,
        session_factory=session_factory,
        connect=connect,
    )
    server.run()  # stdio transport by default


if __name__ == "__main__":
    main()
