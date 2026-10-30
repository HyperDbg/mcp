"""
 * @file test_connection.py
 * @brief Lazy connect/disconnect/reconnect tools + always-available gating.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")  # requires the MCP SDK; skipped if absent

from hyperdbg_mcp.errors import HyperDbgError  # noqa: E402
from hyperdbg_mcp.mock import MockSession  # noqa: E402
from hyperdbg_mcp.tools_connection import register_connection  # noqa: E402


class CaptureMCP:
    """Records the decorated tool functions by name."""

    def __init__(self):
        self.funcs = {}

    def tool(self, **kwargs):
        def deco(fn):
            self.funcs[kwargs["name"]] = fn
            return fn

        return deco


class _FakeAudit:
    def __init__(self):
        self.records = []

    def record(self, name, args, status):
        self.records.append((name, status))


class _AppCtx:
    def __init__(self, session):
        self.session = session
        self.audit = _FakeAudit()
        self.read_only = False


class _Ctx:
    def __init__(self, app):
        self.request_context = type("RC", (), {"lifespan_context": app})()


def _wire(read_only: bool = False):
    mcp = CaptureMCP()
    register_connection(mcp, read_only=read_only)
    app = _AppCtx(MockSession())
    return mcp, app, _Ctx(app)


def test_connection_tools_registered_even_in_read_only():
    mcp, _, _ = _wire(read_only=True)
    assert {"hd_connect", "hd_disconnect", "hd_reconnect", "hd_connection_status"} <= set(
        mcp.funcs
    )


async def test_connect_status_disconnect_cycle():
    mcp, app, ctx = _wire()
    assert "connected=False" in mcp.funcs["hd_connection_status"](ctx)

    out = await mcp.funcs["hd_connect"](ctx)  # default transport = serial
    assert app.session.is_connected and app.session.mode == "remote"
    assert "connected" in out

    status = mcp.funcs["hd_connection_status"](ctx)
    assert "connected=True" in status and "remote" in status

    # connecting again while connected is refused, not silently re-done
    again = await mcp.funcs["hd_connect"](ctx)
    assert "already connected" in again

    out2 = await mcp.funcs["hd_disconnect"](ctx)
    assert "disconnected" in out2 and not app.session.is_connected


async def test_connect_local_then_reconnect_repeats_last():
    mcp, app, ctx = _wire()
    await mcp.funcs["hd_connect"](ctx, transport="local")
    assert app.session.mode == "local"

    await mcp.funcs["hd_reconnect"](ctx)
    assert app.session.is_connected and app.session.mode == "local"


async def test_unknown_transport_reports_error():
    mcp, app, ctx = _wire()
    # a tool error (isError), not a successful result that says it failed
    with pytest.raises(HyperDbgError, match="connect failed"):
        await mcp.funcs["hd_connect"](ctx, transport="bogus")
    assert not app.session.is_connected


async def test_disconnect_when_not_connected_says_so():
    mcp, _, ctx = _wire()
    assert await mcp.funcs["hd_disconnect"](ctx) == "not connected"
