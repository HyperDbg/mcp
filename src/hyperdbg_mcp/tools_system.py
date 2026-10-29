"""
* @file tools_system.py
* @author munraimix
* @brief System information and MSR access tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import re

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import (
    DESTRUCTIVE,
    RO,
    app_ctx,
    choose,
    parse_addr,
    run_text,
    run_text_confirmed,
)

_IO_REGISTERS = {"al": "al", "ax": "ax", "eax": "eax"}  # 8, 16, 32-bit access
_IO_WIDTH = {"al": 0xFF, "ax": 0xFFFF, "eax": 0xFFFFFFFF}

# MSRs that hold a different value on every core: one value written to all of
# them is always wrong (the GS bases point at each core's KPCR - every core then
# runs with the same one and the machine bugchecks).
_PER_CORE_MSRS = {
    0x10: "IA32_TIME_STAMP_COUNTER",
    0x1B: "IA32_APIC_BASE",
    0x6E0: "IA32_TSC_DEADLINE",
    0xC0000100: "IA32_FS_BASE",
    0xC0000101: "IA32_GS_BASE",
    0xC0000102: "IA32_KERNEL_GS_BASE",
    0xC0000103: "IA32_TSC_AUX",
}
# The user-mode FS / GS base of whichever thread runs on the core (Windows swaps
# them on every context switch): a value read is already stale when it is
# written, and writing it hands one thread's TEB to another.
_THREAD_CONTEXT_MSRS = {0xC0000100: "IA32_FS_BASE", 0xC0000102: "IA32_KERNEL_GS_BASE"}
# MSRs where a wrong value bugchecks or hangs the machine at once (system-call
# and sysenter entry points, paging/long-mode control, memory types).
_CRITICAL_MSRS = {
    **_PER_CORE_MSRS,
    0x174: "IA32_SYSENTER_CS",
    0x175: "IA32_SYSENTER_ESP",
    0x176: "IA32_SYSENTER_EIP",
    0x277: "IA32_PAT",
    0x2FF: "IA32_MTRR_DEF_TYPE",
    0xC0000080: "IA32_EFER",
    0xC0000081: "IA32_STAR",
    0xC0000082: "IA32_LSTAR",
    0xC0000083: "IA32_CSTAR",
    0xC0000084: "IA32_FMASK",
}
_MSR_LINE = re.compile(
    r"core\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*-\s*msr\[[0-9a-fA-F]+\]\s*=\s*([0-9a-fA-F`]+)"
)


def _msr_name(msr: int) -> str:
    if 0x800 <= msr <= 0x8FF:
        return "x2APIC register"
    return _CRITICAL_MSRS.get(msr, "")


def _parse_msr_values(output: str) -> dict[int, int]:
    """`core : 0x0 - msr[c0000082] = fffff800`df2c1840` lines -> {core: value}."""
    return {
        int(core, 0): int(value.replace("`", ""), 16)
        for core, value in _MSR_LINE.findall(output)
    }


def register_system(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_cpu_info", annotations=RO)
    def hd_cpu_info(ctx: Context) -> str:
        """Query CPU information."""
        return run_text(ctx, "cpu", audit="hd_cpu_info", kind="system")

    @mcp.tool(name="hd_cpuid", annotations=RO)
    def hd_cpuid(opcode: int, ctx: Context, subfunction: int = 0) -> str:
        """Execute CPUID instruction (opcode, optional subfunction)."""
        cmd = f"ucpuid {opcode:#x}"
        if subfunction:
            cmd += f" {subfunction:#x}"
        return run_text(ctx, cmd, audit="hd_cpuid", kind="system", args={"opcode": opcode})

    @mcp.tool(name="hd_msr_read", annotations=RO)
    def hd_msr_read(msr_id: str, ctx: Context, core: int = -1) -> str:
        """Read a Model-Specific Register (MSR id as hex, e.g. "0xC0000082") on every
        core, or on one `core`."""
        msr = parse_addr(msr_id)
        cmd = f"rdmsr {msr:#x}" + (f" core {core:#x}" if core >= 0 else "")
        return run_text(ctx, cmd, audit="hd_msr_read", kind="system", args={"msr_id": msr})

    if read_only:
        return

    @mcp.tool(name="hd_msr_write", annotations=DESTRUCTIVE)
    async def hd_msr_write(
        msr_id: str,
        value: str,
        ctx: Context,
        core: int = -1,
        expected_current: str = "",
    ) -> str | InputRequiredResult:
        """Write a Model-Specific Register (MSR id and 64-bit value as hex strings) on
        every core, or on one `core`.

        FS_BASE / KERNEL_GS_BASE are refused: they hold the running thread's
        value and change on every context switch. Other per-core MSRs (GS base,
        TSC, TSC_AUX, APIC base, x2APIC, TSC deadline) need `core`: one value on
        every core bugchecks the machine.
        For critical MSRs (also LSTAR/STAR/CSTAR/FMASK, SYSENTER_*, EFER, PAT,
        MTRR default type) the current value is read first and shown in the
        confirmation. expected_current (hex) writes only if the register still
        holds that value on the target core(s): a compare-and-write, so a value
        read earlier can't overwrite one that changed since.
        """
        msr = parse_addr(msr_id)
        new_value = parse_addr(value)
        if not 0 <= msr <= 0xFFFFFFFF:
            raise HyperDbgError(f"invalid MSR id {msr_id!r} (32-bit)")
        if not 0 <= new_value <= 0xFFFFFFFFFFFFFFFF:
            raise HyperDbgError(f"invalid value {value!r} (64-bit)")
        name = _msr_name(msr)
        if msr in _THREAD_CONTEXT_MSRS:
            raise HyperDbgError(
                f"MSR {msr:#x} ({name}) belongs to the thread running on the core and changes "
                "on every context switch; set a thread's FS/GS base in its context instead "
                "(hd_reg_write on a halted thread)"
            )
        if core < 0 and (msr in _PER_CORE_MSRS or 0x800 <= msr <= 0x8FF):
            raise HyperDbgError(
                f"MSR {msr:#x} ({name}) holds a different value on every core: give `core` "
                "(writing one value to all cores bugchecks the machine)"
            )
        core_opt = f" core {core:#x}" if core >= 0 else ""
        what = f"write MSR {msr:#x}" + (f" ({name})" if name else "") + f" = {new_value:#x}"
        what += f" on core {core}" if core >= 0 else " on every core"
        if name or expected_current:
            session = app_ctx(ctx).session
            current = _parse_msr_values(
                await anyio.to_thread.run_sync(session.run_command, f"rdmsr {msr:#x}{core_opt}")
            )
            if not current:
                raise HyperDbgError(f"could not read the current value of MSR {msr:#x}")
            if expected_current:
                expected = parse_addr(expected_current)
                changed = {c: v for c, v in current.items() if v != expected}
                if changed:
                    raise HyperDbgError(
                        f"MSR {msr:#x} no longer holds {expected:#x} (now "
                        + ", ".join(f"core {c}: {v:#x}" for c, v in sorted(changed.items()))
                        + "); nothing written"
                    )
            values = sorted(set(current.values()))
            if all(v == new_value for v in values):
                what += " (the value it already holds)"
            else:
                what += "; now " + ", ".join(f"{v:#x}" for v in values)
                if name:
                    what += ". CRITICAL: a wrong value bugchecks the machine"
        cmd = f"wrmsr {msr:#x} {new_value:#x}{core_opt}"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=what,
            audit="hd_msr_write",
            kind="system",
            args={"msr_id": msr, "core": core},
        )

    @mcp.tool(name="hd_io_in", annotations=DESTRUCTIVE)
    async def hd_io_in(port: int, ctx: Context, width: str = "al") -> str | InputRequiredResult:
        """Read an I/O port (width: al = 8, ax = 16, eax = 32 bits).

        Gated: reading a device register can change its state (e.g. port 0x60
        consumes the pending keyboard byte).
        """
        if not 0 <= port <= 0xFFFF:
            raise HyperDbgError("port must be 0-0xffff")
        cmd = f"uin {choose(width, _IO_REGISTERS, 'width')} {port:#x}"
        return await run_text_confirmed(
            ctx, cmd, what=f"read I/O port {port:#x}", audit="hd_io_in", kind="system",
            args={"port": port, "width": width},
        )

    @mcp.tool(name="hd_io_out", annotations=DESTRUCTIVE)
    async def hd_io_out(
        port: int, value: int, ctx: Context, width: str = "al"
    ) -> str | InputRequiredResult:
        """Write `value` to an I/O port (width: al = 8, ax = 16, eax = 32 bits)."""
        reg = choose(width, _IO_REGISTERS, "width")
        if not 0 <= port <= 0xFFFF:
            raise HyperDbgError("port must be 0-0xffff")
        if not 0 <= value <= _IO_WIDTH[reg]:
            raise HyperDbgError(f"value does not fit in {reg}")
        cmd = f"uout {reg} {port:#x} {value:#x}"
        return await run_text_confirmed(
            ctx, cmd, what=f"write {value:#x} to I/O port {port:#x}", audit="hd_io_out",
            kind="system", args={"port": port, "value": value, "width": width},
        )
