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
import re
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


# `nt!KdDebuggerEnabled`, `nt!PsLoadedModuleList+0x10`, `@rip-8`: a symbol or
# register plus hex offsets, nothing else. HyperDbg evaluates addresses with its
# script engine, which also has side-effecting functions (eb/ed/eq...), so only
# this read-only shape is ever handed to it.
_SYMBOLIC_ADDR = re.compile(
    r"(?:[A-Za-z_][\w.]*!)?[A-Za-z_@$][\w@$.]*(?:\s*[+-]\s*(?:0x)?[0-9a-fA-F`]+)*"
)


def resolve_addr(ctx: Context, value: str | int) -> int:
    """parse_addr, plus symbolic addresses resolved through HyperDbg's symbols."""
    try:
        return parse_addr(value)
    except HyperDbgError:
        if not isinstance(value, str) or not _SYMBOLIC_ADDR.fullmatch(value.strip()):
            raise
    return app_ctx(ctx).session.eval_expression(value.strip())


def choose(value: str, allowed: dict[str, str], name: str) -> str:
    """Map a user-facing choice to its CLI token; reject unknown values loudly."""
    try:
        return allowed[value]
    except KeyError:
        raise HyperDbgError(
            f"invalid {name} {value!r} (use {' | '.join(allowed)})"
        ) from None


_HEX_VALUES = re.compile(r"(?:0x)?[0-9a-fA-F`]+(?: (?:0x)?[0-9a-fA-F`]+)*")


def token(value: str, name: str) -> str:
    """Require exactly one CLI token, so a value can't smuggle in extra options.

    HyperDbg runs one command per call, but options inside it are positional
    words: `struct T output C:/x.h` would write a file even from a "read" tool.
    """
    if not value or any(c.isspace() or c in '"{}' for c in value):
        raise HyperDbgError(f"invalid {name} {value!r} (one word, no spaces/quotes/braces)")
    return value


def hex_values(value: str, name: str = "value") -> str:
    """Require space-separated hex values (`90 90 cc`), nothing else."""
    if not _HEX_VALUES.fullmatch(value.strip()):
        raise HyperDbgError(f"invalid {name} {value!r} (space-separated hex values)")
    return value.strip()


def bracket_body(text: str, name: str = "script") -> str:
    """Validate text for a `{ ... }` block exactly as HyperDbg's tokenizer reads it.

    The tokenizer counts nested braces outside quotes, and a `//` or `/*`
    comment outside quotes swallows the rest of the line (closing brace and
    every option after it). Anything that could end the block early or leak
    into the surrounding command is rejected instead of escaped.
    """
    depth, in_quotes, prev = 0, False, ""
    for i, c in enumerate(text):
        if in_quotes:
            if c == '"' and prev != "\\":
                in_quotes = False
        elif c == '"':
            in_quotes = True
        elif c == "\\":
            raise HyperDbgError(f"{name}: backslash outside a string literal is not allowed")
        elif c == "/" and text[i + 1 : i + 2] in ("/", "*"):
            raise HyperDbgError(f"{name}: comments are not allowed (they swallow the '}}')")
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                raise HyperDbgError(f"{name}: unbalanced '}}'")
        prev = c
    if in_quotes or depth:
        raise HyperDbgError(f"{name}: unbalanced braces or unterminated string")
    return text


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

    `--assume-consent` short-circuits this: clients that advertise no
    elicitation (and so would deny every mutating tool) run pre-approved.
    """
    if app_ctx(ctx).assume_consent:
        return True
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
