"""
* @file tools_system.py
* @author munraimix
* @brief System information and MSR access tools for HyperDbg.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .toolkit import DESTRUCTIVE, RO, parse_addr, run_text, run_text_confirmed


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
