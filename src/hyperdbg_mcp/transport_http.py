"""
 * @file transport_http.py
 * @brief Streamable HTTP transport behind a mandatory bearer token.
 * @copyright This project is released under the GNU Public License v3.
 *
 * stdio ties the debugger session to one client process: every client
 * restart (and an MCP client's probe process) starts a fresh server, and the
 * old one unloads the VMM on exit. Over Streamable HTTP one long-lived server
 * keeps the HyperDbg session - loaded VMM, symbols, a halted remote debuggee -
 * while clients come and go.
 *
 * Anyone who can reach the endpoint drives a ring-0 debugger, so HTTP never
 * runs without a token, loopback included (other local users and processes
 * can reach loopback too). The token comes from the environment, never argv,
 * which other processes can read.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.mcpserver import MCPServer
    from starlette.types import ASGIApp, Receive, Scope, Send

TOKEN_ENV = "HYPERDBG_MCP_TOKEN"
_MIN_TOKEN_LEN = 32


class BearerAuth:
    """Reject every HTTP request that lacks `Authorization: Bearer <token>`."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            supplied = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self._expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"www-authenticate", b'Bearer realm="hyperdbg-mcp"'),
                            (b"content-type", b"text/plain"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": b"unauthorized\n"})
                return
        await self._app(scope, receive, send)


def check_token(token: str | None) -> str:
    """Return the token, or explain why HTTP mode cannot start."""
    if not token:
        raise SystemExit(
            f"--transport http needs a bearer token in ${TOKEN_ENV} "
            f"(at least {_MIN_TOKEN_LEN} characters), e.g. "
            "python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    if len(token) < _MIN_TOKEN_LEN:
        raise SystemExit(f"${TOKEN_ENV} is too short (need {_MIN_TOKEN_LEN}+ characters)")
    return token


def build_http_app(mcp: MCPServer, *, host: str, token: str) -> ASGIApp:
    # The SDK turns on DNS-rebinding protection by itself for a loopback host.
    return BearerAuth(mcp.streamable_http_app(host=host), token)


def serve_http(mcp: MCPServer, *, host: str, port: int, token: str) -> None:
    import uvicorn

    app = build_http_app(mcp, host=host, token=token)
    uvicorn.run(app, host=host, port=port, log_level="warning")
