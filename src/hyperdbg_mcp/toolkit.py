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
 *   - read tools are plain `def` (MCPServer runs them in a worker thread) and
 *     use run_text(...); target-mutating tools are `async def`, gated with
 *     run_text_confirmed(...) or an explicit require_confirmation() check, and
 *     are registered ONLY when not read_only.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

import anyio
from mcp.server.elicitation import render_elicitation_schema
from mcp.server.mcpserver import Context
from mcp.types import (
    ElicitRequest,
    ElicitRequestFormParams,
    ElicitResult,
    InputRequiredResult,
    ToolAnnotations,
)
from mcp_types.version import is_version_at_least
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


_CONFIRM_KEY = "confirm"


def _can_elicit_form(ctx: Context) -> bool:
    caps = ctx.client_capabilities
    e = caps.elicitation if caps is not None else None
    # A bare `elicitation: {}` (pre-modes shape) counts as form support.
    return e is not None and (e.form is not None or e.url is None)


async def require_confirmation(ctx: Context, what: str) -> bool | InputRequiredResult:
    """Ask the client to confirm; deny-by-default if elicitation is unavailable.

    At protocol >= 2026-07-28 the server can't call the client mid-request, so
    the first round returns an InputRequiredResult (return it from the tool);
    the client retries the call with the answer in `input_responses`. Older
    revisions keep the synchronous `elicitation/create` round-trip.
    """
    message = f"HyperDbg is a ring-0 debugger. Confirm: {what}"
    version = ctx.protocol_version
    if version is None or not is_version_at_least(version, "2026-07-28"):
        try:
            result = await ctx.elicit(message=message, schema=Confirm)
        except Exception:
            return False
        return result.action == "accept" and bool(result.data and result.data.confirm)

    # Bind the answer to this exact question so a stale/forged answer to a
    # different operation can't confirm this one.
    digest = hashlib.sha256(message.encode()).hexdigest()
    answer = (ctx.input_responses or {}).get(_CONFIRM_KEY)
    if isinstance(answer, ElicitResult) and ctx.request_state == digest:
        return answer.action == "accept" and bool((answer.content or {}).get("confirm") is True)
    if not _can_elicit_form(ctx):
        return False
    return InputRequiredResult(
        input_requests={
            _CONFIRM_KEY: ElicitRequest(
                params=ElicitRequestFormParams(
                    message=message, requested_schema=render_elicitation_schema(Confirm)
                )
            )
        },
        request_state=digest,
    )


def run_text(
    ctx: Context,
    command: str,
    *,
    audit: str,
    kind: str,
    args: dict[str, Any] | None = None,
) -> str:
    """Run a HyperDbg CLI command; return its output wrapped as untrusted data.

    For read/query tools (plain `def`). MCPServer runs sync tools off the event
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
) -> str | InputRequiredResult:
    """Confirm, then run a target-mutating command off-thread; fence the output.

    For destructive tools (async `def`). Denies by default if the client can't
    elicit. Any HyperDbgError is fenced (session already wraps failure output).
    """
    a = app_ctx(ctx)
    confirmed = await require_confirmation(ctx, what)
    if isinstance(confirmed, InputRequiredResult):
        return confirmed
    if not confirmed:
        a.audit.record(audit, args or {}, status="denied")
        return "Denied by user."
    try:
        out = await anyio.to_thread.run_sync(a.session.run_command, command)
    except HyperDbgError as exc:
        a.audit.record(audit, args or {}, status="error")
        return str(exc)
    a.audit.record(audit, args or {}, status="ok")
    return wrap_untrusted(out, kind)
