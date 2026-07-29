"""
 * @file toolkit.py
 * @author munraimix
 * @brief Shared helpers every tools_<domain> module builds on.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Contract for domain modules (tools_<domain>.py):
 *   - import RO / STATE / DESTRUCTIVE, app_ctx, require_confirmation,
 *     run_text, run_text_confirmed from this module;
 *   - expose register_<domain>(mcp, *, read_only) that registers tools;
 *   - read tools are plain `def` (FastMCP runs them in a worker thread) and
 *     use run_text(...); target-mutating tools are `async def`, gated with
 *     run_text_confirmed(...) or an explicit require_confirmation() check, and
 *     are registered ONLY when not read_only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import anyio
from mcp.server.fastmcp import Context
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from .errors import HyperDbgError
from .safety import wrap_untrusted

if TYPE_CHECKING:  # pragma: no cover
    from .server import AppContext

# Annotation presets (see DESIGN §10).
RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False)
STATE = ToolAnnotations(readOnlyHint=False, destructiveHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)


class Confirm(BaseModel):
    confirm: bool = Field(description="Proceed with this operation on the live target?")


def app_ctx(ctx: Context) -> AppContext:
    return ctx.request_context.lifespan_context


def parse_addr(value: str | int) -> int:
    """Parse a 64-bit address/value that arrived as a hex or decimal string.

    64-bit kernel addresses exceed JSON/float64's exact integer range (2^53),
    so an int-typed parameter loses its low bits crossing the MCP boundary.
    Address and 64-bit value parameters are therefore typed `str` and parsed
    here (int is still accepted for in-process callers such as tests/mock).
    """
    if isinstance(value, int):
        return value
    text = value.strip()
    try:
        return int(text, 0) if text else 0
    except ValueError as exc:
        raise HyperDbgError(
            f"invalid address/value {value!r} (use hex like 0x... or decimal)"
        ) from exc


async def require_confirmation(ctx: Context, what: str) -> bool:
    """Ask the client to confirm; deny-by-default if elicitation is unavailable."""
    try:
        result = await ctx.elicit(
            message=f"HyperDbg is a ring-0 debugger. Confirm: {what}", schema=Confirm
        )
    except Exception:
        return False
    return result.action == "accept" and bool(result.data and result.data.confirm)


def run_text(
    ctx: Context,
    command: str,
    *,
    audit: str,
    kind: str,
    args: dict[str, Any] | None = None,
) -> str:
    """Run a HyperDbg CLI command; return its output wrapped as untrusted data.

    For read/query tools (plain `def`). FastMCP runs sync tools off the event
    loop, so the blocking call here is fine.
    """
    a = app_ctx(ctx)
    out = a.session.run_command(command)
    a.audit.record(audit, args or {}, status="ok")
    return wrap_untrusted(out, kind)


async def run_text_confirmed(
    ctx: Context,
    command: str,
    *,
    what: str,
    audit: str,
    kind: str,
    args: dict[str, Any] | None = None,
) -> str:
    """Confirm, then run a target-mutating command off-thread; fence the output.

    For destructive tools (async `def`). Denies by default if the client can't
    elicit. Any HyperDbgError is fenced (session already wraps failure output).
    """
    a = app_ctx(ctx)
    if not await require_confirmation(ctx, what):
        a.audit.record(audit, args or {}, status="denied")
        return "Denied by user."
    try:
        out = await anyio.to_thread.run_sync(a.session.run_command, command)
    except HyperDbgError as exc:
        a.audit.record(audit, args or {}, status="error")
        return str(exc)
    a.audit.record(audit, args or {}, status="ok")
    return wrap_untrusted(out, kind)
