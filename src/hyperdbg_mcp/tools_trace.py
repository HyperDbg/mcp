"""
* @file tools_trace.py
* @author munraimix
* @brief Hardware tracing tools: Intel Processor Trace (!pt) and Last Branch
*        Record (!lbr, !lbrdump). Both need the trace module (hd_modules_load_all).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import re

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import DESTRUCTIVE, RO, choose, resolve_addr, run_text, run_text_confirmed, token

_PT_ACTIONS = {a: a for a in ("disable", "pause", "resume", "flush")}
_PT_DUMP_TYPES = {"instruction": "instruction", "packet": "packet"}
_PT_MODES = {"user", "kernel"}
_PT_PACKETS = {"psb", "pip", "tsc", "mtc", "cyc", "tnt", "tip", "fup", "mode"}
_LBR_ACTIONS = {a: a for a in ("enable", "disable", "flush")}
_LBR_FILTERS = {
    "kernel",
    "user",
    "jcc",
    "rel_call",
    "ind_call",
    "return",
    "ind_jmp",
    "rel_jmp",
    "far",
    "other_branches",
    "call_stack",
}
_RANGE = re.compile(r"\s*(\S+)\s*-\s*(\S+)\s*")


def _words(values: list[str], allowed: set[str], name: str) -> str:
    bad = [v for v in values if v not in allowed]
    if bad or len(set(values)) != len(values):
        raise HyperDbgError(
            f"invalid {name} {values!r} (each once, from {' | '.join(sorted(allowed))})"
        )
    return " ".join(values)


def _pt_ranges(ctx: Context, ranges: list[str], keyword: str) -> str:
    """`FROM-TO` (addresses/symbols) or a module name (`main`, `nt`, `ntdll`) per range."""
    if len(ranges) > 4:
        raise HyperDbgError(f"at most 4 {keyword}s (Intel PT has 4 address-range filters)")
    parts = []
    for i, item in enumerate(ranges, 1):
        m = _RANGE.fullmatch(item)
        if m:
            frm, to = resolve_addr(ctx, m.group(1)), resolve_addr(ctx, m.group(2))
            parts.append(f"{keyword}{i} {frm:#x} {to:#x}")
        else:
            parts.append(f"{keyword}{i} module {token(item, keyword)}")
    return " ".join(parts)


def register_trace(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_pt_dump", annotations=RO)
    def hd_pt_dump(ctx: Context, dump_type: str = "instruction") -> str:
        """Print the captured Intel PT trace, decoded as instructions or raw packets."""
        cmd = f"!pt dump print type {choose(dump_type, _PT_DUMP_TYPES, 'dump_type')}"
        return run_text(ctx, cmd, audit="hd_pt_dump", kind="trace", args={"dump_type": dump_type})

    @mcp.tool(name="hd_lbr_dump", annotations=RO)
    def hd_lbr_dump(ctx: Context, core: int = -1) -> str:
        """Dump the Last Branch Record stack (configure it first with hd_lbr)."""
        cmd = "!lbrdump" + (f" core {core:#x}" if core >= 0 else "")
        return run_text(ctx, cmd, audit="hd_lbr_dump", kind="trace", args={"core": core})

    if read_only:
        return

    @mcp.tool(name="hd_pt_enable", annotations=DESTRUCTIVE)
    async def hd_pt_enable(
        ctx: Context,
        pid: int = 0,
        tid: int = 0,
        process_name: str = "",
        cr3: str = "",
        buffer_size: int = 0,
        core: int = -1,
    ) -> str | InputRequiredResult:
        """Start Intel Processor Trace, optionally for one process/thread/CR3.

        Needs the trace module: load it with hd_modules_load_all. The trace
        thread keeps printing (decoding, exit) into later tools' output.

        Give at most one of pid, tid, process_name, cr3. buffer_size is per core
        (bytes); core limits tracing to one core.
        """
        targets = [
            f"pid {pid:#x}" if pid else "",
            f"tid {tid:#x}" if tid else "",
            f"pname {token(process_name, 'process_name')}" if process_name else "",
            f"cr3 {resolve_addr(ctx, cr3):#x}" if cr3 else "",
        ]
        targets = [t for t in targets if t]
        if len(targets) > 1:
            raise HyperDbgError("give at most one of pid, tid, process_name, cr3")
        if cr3 and core >= 0:
            raise HyperDbgError("core can't be combined with cr3")
        cmd = " ".join(
            ["!pt enable", *targets]
            + ([f"size {buffer_size:#x}"] if buffer_size else [])
            + ([f"core {core:#x}"] if core >= 0 else [])
        )
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"enable Intel PT: {cmd}",
            audit="hd_pt_enable",
            kind="trace",
            args={"pid": pid, "tid": tid, "process_name": process_name, "core": core},
        )

    @mcp.tool(name="hd_pt_control", annotations=DESTRUCTIVE)
    async def hd_pt_control(action: str, ctx: Context) -> str | InputRequiredResult:
        """Control a running Intel PT trace: disable | pause | resume | flush."""
        cmd = f"!pt {choose(action, _PT_ACTIONS, 'action')}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"Intel PT {action}",
            audit="hd_pt_control",
            kind="trace",
            args={"action": action},
        )

    @mcp.tool(name="hd_pt_filter", annotations=DESTRUCTIVE)
    async def hd_pt_filter(
        ctx: Context,
        modes: list[str] | None = None,
        ranges: list[str] | None = None,
        stop_ranges: list[str] | None = None,
    ) -> str | InputRequiredResult:
        """Restrict what Intel PT records.

        modes: "user" and/or "kernel". ranges / stop_ranges (up to 4 each): trace
        only inside, or stop tracing on entering, each range given as `FROM-TO`
        (addresses or symbols) or a module name (`main` = the traced process's image,
        `nt`, `ntdll`, ...).
        """
        parts = []
        if modes:
            parts.append(_words(modes, _PT_MODES, "modes"))
        if ranges:
            parts.append(_pt_ranges(ctx, ranges, "range"))
        if stop_ranges:
            parts.append(_pt_ranges(ctx, stop_ranges, "stoprange"))
        if not parts:
            raise HyperDbgError("give modes, ranges or stop_ranges")
        cmd = "!pt filter " + " ".join(parts)
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set Intel PT filter: {cmd}",
            audit="hd_pt_filter",
            kind="trace",
            args={"modes": modes, "ranges": ranges, "stop_ranges": stop_ranges},
        )

    @mcp.tool(name="hd_pt_packets", annotations=DESTRUCTIVE)
    async def hd_pt_packets(packets: list[str], ctx: Context) -> str | InputRequiredResult:
        """Choose the optional Intel PT packets: psb pip tsc mtc cyc tnt tip fup mode."""
        cmd = "!pt packet " + _words(packets, _PT_PACKETS, "packets")
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set Intel PT packets: {cmd}",
            audit="hd_pt_packets",
            kind="trace",
            args={"packets": packets},
        )

    @mcp.tool(name="hd_lbr", annotations=DESTRUCTIVE)
    async def hd_lbr(action: str, ctx: Context) -> str | InputRequiredResult:
        """Last Branch Record: enable | disable | flush (read it with hd_lbr_dump).

        Needs the trace module: load it with hd_modules_load_all.
        """
        cmd = f"!lbr {choose(action, _LBR_ACTIONS, 'action')}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"LBR {action}",
            audit="hd_lbr",
            kind="trace",
            args={"action": action},
        )

    @mcp.tool(name="hd_lbr_filter", annotations=DESTRUCTIVE)
    async def hd_lbr_filter(
        ctx: Context, exclude: list[str] | None = None
    ) -> str | InputRequiredResult:
        """Set which branches LBR does NOT record; empty = record everything.

        exclude: kernel, user, jcc, rel_call, ind_call, return, ind_jmp, rel_jmp,
        far, other_branches; or call_stack with kernel or user only (records calls
        and returns as a call stack).
        """
        cmd = "!lbr filter"
        if exclude:
            cmd += " " + _words(exclude, _LBR_FILTERS, "exclude")
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"set LBR filter: {cmd}",
            audit="hd_lbr_filter",
            kind="trace",
            args={"exclude": exclude},
        )
