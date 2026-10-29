"""
* @file tools_sdk.py
* @author munraimix
* @brief Simple SDK-typed tools (direct libhyperdbg calls, not CLI passthrough).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from functools import partial

import anyio
from mcp.server.mcpserver import Context, MCPServer
from mcp.types import InputRequiredResult

from .errors import HyperDbgError
from .toolkit import DESTRUCTIVE, RO, STATE, app_ctx, denial, require_confirmation


def register_sdk(mcp: MCPServer, *, read_only: bool) -> None:
    # ----- SAFE reads (no target-controlled text -> no untrusted envelope) --- #
    @mcp.tool(name="hd_kernel_base", annotations=RO)
    def hd_kernel_base(ctx: Context) -> str:
        """Get the Windows kernel (nt) image base address."""
        app = app_ctx(ctx)
        value = app.session.get_kernel_base()
        app.audit.record("hd_kernel_base", {}, status="ok")
        return hex(value)

    @mcp.tool(name="hd_cpu_vendor", annotations=RO)
    def hd_cpu_vendor(ctx: Context) -> str:
        """Get the CPU vendor (Intel | AMD | Other)."""
        app = app_ctx(ctx)
        vendor = app.session.get_processor_vendor()
        app.audit.record("hd_cpu_vendor", {}, status="ok")
        return vendor

    @mcp.tool(name="hd_vmx_support", annotations=RO)
    def hd_vmx_support(ctx: Context) -> str:
        """Report whether the CPU supports Intel VMX."""
        app = app_ctx(ctx)
        app.audit.record("hd_vmx_support", {}, status="ok")
        return f"vmx_supported={app.session.detect_vmx_support()}"

    @mcp.tool(name="hd_vmm_status", annotations=RO)
    def hd_vmm_status(ctx: Context) -> str:
        """Report whether a HyperDbg module (VMM) is currently loaded."""
        app = app_ctx(ctx)
        app.audit.record("hd_vmm_status", {}, status="ok")
        return f"module_loaded={app.session.is_any_module_loaded()}"

    # ----- navigation (execution control; allowed in read-only) ------------ #
    @mcp.tool(name="hd_step_out", annotations=STATE)
    def hd_step_out(ctx: Context, last_instruction: bool = False) -> str:
        """Run until the current function returns (gu / go-up)."""
        app = app_ctx(ctx)
        app.session.step_out(last_instruction)
        app.audit.record("hd_step_out", {}, status="ok")
        return "Stepped out."

    @mcp.tool(name="hd_step_track", annotations=STATE)
    def hd_step_track(ctx: Context) -> str:
        """Instrumentation step-in with tracking (!track)."""
        app = app_ctx(ctx)
        app.session.step_track()
        app.audit.record("hd_step_track", {}, status="ok")
        return "Tracking step."

    if read_only:
        return

    # ----- GATED (consequential SDK ops; confirmed, not in read-only) ------ #
    async def _gated(ctx, *, what, audit, fn, ok):
        app = app_ctx(ctx)
        confirmed = await require_confirmation(ctx, what)
        if isinstance(confirmed, InputRequiredResult):
            return confirmed
        if not confirmed:
            app.audit.record(audit, {}, status="denied")
            return denial(ctx)
        try:
            result = await anyio.to_thread.run_sync(fn)
        except HyperDbgError:
            app.audit.record(audit, {}, status="error")
            raise
        app.audit.record(audit, {}, status="ok")
        return ok(result) if callable(ok) else ok

    @mcp.tool(name="hd_vmm_load", annotations=DESTRUCTIVE)
    async def hd_vmm_load(ctx: Context) -> str | InputRequiredResult:
        """Load the HyperDbg hypervisor (VMM) and debug this machine (local VMI mode).

        Ring-0; requires a DSE-off boot. Debugger Mode (serial/pipe/net) is for
        a debugger on another machine and must not load the VMM here.
        """
        return await _gated(
            ctx,
            what="load the HyperDbg VMM (hypervisor)",
            audit="hd_vmm_load",
            fn=app_ctx(ctx).session.load_vmm,
            ok="VMM loaded (kd driver installed); connected in local VMI mode.",
        )

    @mcp.tool(name="hd_vmm_unload", annotations=DESTRUCTIVE)
    async def hd_vmm_unload(ctx: Context) -> str | InputRequiredResult:
        """Unload the HyperDbg hypervisor (VMM)."""
        return await _gated(
            ctx,
            what="unload the HyperDbg VMM",
            audit="hd_vmm_unload",
            fn=app_ctx(ctx).session.unload_vmm,
            ok="VMM and kd module unloaded.",
        )

    @mcp.tool(name="hd_modules_load_all", annotations=DESTRUCTIVE)
    async def hd_modules_load_all(ctx: Context) -> str | InputRequiredResult:
        """Load all HyperDbg kernel modules."""
        return await _gated(
            ctx,
            what="load all HyperDbg modules",
            audit="hd_modules_load_all",
            fn=app_ctx(ctx).session.load_all_modules,
            ok="All modules loaded (kd driver installed); connected in local VMI mode.",
        )

    @mcp.tool(name="hd_modules_unload_all", annotations=DESTRUCTIVE)
    async def hd_modules_unload_all(ctx: Context) -> str | InputRequiredResult:
        """Unload all HyperDbg kernel modules."""
        return await _gated(
            ctx,
            what="unload all HyperDbg modules",
            audit="hd_modules_unload_all",
            fn=app_ctx(ctx).session.unload_all_modules,
            ok="All modules unloaded.",
        )

    @mcp.tool(name="hd_transparent_enable", annotations=DESTRUCTIVE)
    async def hd_transparent_enable(
        ctx: Context, pid: int = 0, name: str = "", evade_mask: int = 0x1F
    ) -> str | InputRequiredResult:
        """Enable transparent mode to hide the debugger (evade_mask ALL=0x1F)."""
        return await _gated(
            ctx,
            what="enable transparent (anti-detection) mode",
            audit="hd_transparent_enable",
            fn=partial(
                app_ctx(ctx).session.enable_transparent_mode,
                pid=pid,
                name=name,
                evade_mask=evade_mask,
            ),
            ok="Transparent mode enabled.",
        )

    @mcp.tool(name="hd_transparent_disable", annotations=DESTRUCTIVE)
    async def hd_transparent_disable(ctx: Context) -> str | InputRequiredResult:
        """Disable transparent mode (unhide the debugger)."""
        return await _gated(
            ctx,
            what="disable transparent mode",
            audit="hd_transparent_disable",
            fn=app_ctx(ctx).session.disable_transparent_mode,
            ok="Transparent mode disabled.",
        )

    @mcp.tool(name="hd_process_start", annotations=DESTRUCTIVE)
    async def hd_process_start(
        path: str, ctx: Context, args: str = ""
    ) -> str | InputRequiredResult:
        """Start a new process (optionally with args), breaking at its entry point.

        HyperDbg's user debugger is beta: if the process is killed while still
        stopped at the entry point, the int3 there can stay in the image's shared
        page, and every later instance of that program crashes (0x80000003) until
        the original byte is written back (hd_mem_edit, physical).
        """
        return await _gated(
            ctx,
            what=f"start process {path}",
            audit="hd_process_start",
            fn=partial(app_ctx(ctx).session.start_process, path, args),
            ok=f"Started {path}.",
        )
