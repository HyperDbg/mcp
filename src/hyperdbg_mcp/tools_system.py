"""
* @file tools_system.py
* @author munraimix
* @brief System information and MSR access tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import DESTRUCTIVE, RO, choose, parse_addr, run_text, run_text_confirmed

_IO_REGISTERS = {"al": "al", "ax": "ax", "eax": "eax"}  # 8, 16, 32-bit access
_IO_WIDTH = {"al": 0xFF, "ax": 0xFFFF, "eax": 0xFFFFFFFF}


def register_system(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_cpu_info", annotations=RO)
    def hd_cpu_info(ctx: Context) -> str:
        """Query CPU information."""
        return run_text(ctx, "cpu", audit="hd_cpu_info", kind="system")

    @mcp.tool(name="hd_cpuid", annotations=RO)
    def hd_cpuid(opcode: int, ctx: Context, subfunction: int = 0, kernel_mode: bool = False) -> str:
        """Execute CPUID instruction (opcode, optional subfunction)."""
        cmd = f"ucpuid {opcode:#x}"
        if subfunction:
            cmd += f" {subfunction:#x}"
        if kernel_mode:
            cmd += " KernelMode yes"
        return run_text(ctx, cmd, audit="hd_cpuid", kind="system", args={"opcode": opcode})

    @mcp.tool(name="hd_msr_read", annotations=RO)
    def hd_msr_read(msr_id: int, ctx: Context, kernel_mode: bool = False) -> str:
        """Read a Model-Specific Register (MSR)."""
        cmd = f"rdmsr {msr_id:#x}"
        if kernel_mode:
            cmd += " KernelMode yes"
        return run_text(ctx, cmd, audit="hd_msr_read", kind="system", args={"msr_id": msr_id})

    if read_only:
        return

    @mcp.tool(name="hd_msr_write", annotations=DESTRUCTIVE)
    async def hd_msr_write(
        msr_id: int, value: str, ctx: Context, kernel_mode: bool = False
    ) -> str | InputRequiredResult:
        """Write a Model-Specific Register (MSR); value is a 64-bit hex string."""
        cmd = f"wrmsr {msr_id:#x} {parse_addr(value):#x}"
        if kernel_mode:
            cmd += " KernelMode yes"
        return await run_text_confirmed(
            ctx,
            cmd,
            what=f"write MSR {msr_id:#x}",
            audit="hd_msr_write",
            kind="system",
            args={"msr_id": msr_id},
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
