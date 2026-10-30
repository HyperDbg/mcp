"""
 * @file tool_sweep.py
 * @author munraimix
 * @brief Exercise every registered MCP tool against the mock backend.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Full-surface smoke: registers all tool modules, wires a MockSession, and
 * invokes each tool once with signature-derived arguments. Deterministic, no
 * hardware, no risk. This is the right way to confirm the whole tool surface
 * is wired and callable (the live kernel rig is for targeted checks only).
 *
 *   python scripts/tool_sweep.py
 """

from __future__ import annotations

import asyncio
import inspect

from hyperdbg_mcp.mock import MockSession
from hyperdbg_mcp.tools import register_tools
from hyperdbg_mcp.tools_connection import register_connection
from hyperdbg_mcp.tools_events import register_events
from hyperdbg_mcp.tools_flow import register_flow
from hyperdbg_mcp.tools_hooks import register_hooks
from hyperdbg_mcp.tools_hw import register_hw
from hyperdbg_mcp.tools_memory import register_memory
from hyperdbg_mcp.tools_paging import register_paging
from hyperdbg_mcp.tools_sdk import register_sdk
from hyperdbg_mcp.tools_symbols import register_symbols
from hyperdbg_mcp.tools_system import register_system

_REGISTRARS = [
    register_tools,
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
]


class CaptureMCP:
    def __init__(self):
        self.funcs: dict[str, object] = {}

    def tool(self, **kwargs):
        def deco(fn):
            self.funcs[kwargs.get("name", fn.__name__)] = fn
            return fn

        return deco


class _Audit:
    def record(self, *a, **k):
        pass


class _App:
    def __init__(self, session):
        self.session = session
        self.audit = _Audit()
        self.read_only = False


class _ElicitResult:
    action = "accept"

    class data:  # noqa: N801 - simple stand-in
        confirm = True


class _Ctx:
    """Fake MCP Context: lifespan_context + an auto-accepting elicit()."""

    protocol_version = None  # pre-2026-07-28 path: synchronous ctx.elicit()

    def __init__(self, app):
        self.request_context = type("RC", (), {"lifespan_context": app})()

    async def elicit(self, *a, **k):
        return _ElicitResult()


def _arg_for(pname: str, annotation) -> object:
    name = pname.lower()
    # `from __future__ import annotations` makes hints strings at runtime, so
    # normalise to a type name before deciding.
    ann = annotation if isinstance(annotation, str) else getattr(annotation, "__name__", "")
    # Type wins first (disambiguates same-named params, e.g. int vs str `value`).
    if ann == "int":
        if name == "cr":
            return 4  # only CR0/CR4 are valid for !crwrite
        if "address" in name or "addr" in name or "base" in name:
            return 0x1000
        return 1
    if ann == "bool":
        return False
    str_hints = {
        "command": ".status",
        "expression": "1+1",
        "expr": "1+1",
        "code": "nop",
        "name": "rax",
        "value": "90",
        "data_hex": "90",  # valid for bytes.fromhex in hd_mem_write
        "path": r"C:\\mock.exe",
        "symbol": "nt!MockSym",
        "struct_name": "_EPROCESS",
        "transport": "local",
        "fmt": "byte",
        # enum-like params are validated server-side, so pass a real choice
        "attribute": "rw",
        "state": "off",
        "mode": "user",
        "trace_type": "step-in",
        "kind": "epthook",
        "target": "all",
        "action": "disable",
    }
    if name in str_hints:
        return str_hints[name]
    # 64-bit address/value params are now hex strings (parsed server-side).
    if "address" in name or "addr" in name or "base" in name:
        return "0x1000"
    return "mock"


def _build_kwargs(fn, ctx) -> dict:
    kwargs = {}
    for pname, p in inspect.signature(fn).parameters.items():
        ann = p.annotation
        # the MCP Context param (typed Context) gets our fake ctx
        if pname == "ctx" or getattr(ann, "__name__", "") == "Context":
            kwargs[pname] = ctx
            continue
        if p.default is not inspect.Parameter.empty:
            continue  # optional: use the tool's default
        kwargs[pname] = _arg_for(pname, ann)
    return kwargs


async def _call(fn, ctx):
    kwargs = _build_kwargs(fn, ctx)
    if inspect.iscoroutinefunction(fn):
        return await fn(**kwargs)
    return fn(**kwargs)


async def main() -> int:
    mcp = CaptureMCP()
    for reg in _REGISTRARS:
        reg(mcp, read_only=False)

    app = _App(MockSession())
    app.session.connect_local()
    ctx = _Ctx(app)

    ok, fail = 0, 0
    for name in sorted(mcp.funcs):
        try:
            result = await _call(mcp.funcs[name], ctx)
            first = str(result).strip().splitlines()[0] if result else "(empty)"
            print(f"[PASS] {name:28} -> {first[:70]}")
            ok += 1
        except Exception as exc:  # noqa: BLE001 - report every failure
            print(f"[FAIL] {name:28} -> {type(exc).__name__}: {exc}")
            fail += 1

    print(f"\n{ok + fail} tools exercised: {ok} PASS, {fail} FAIL")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
