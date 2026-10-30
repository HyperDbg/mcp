"""
* @file tools_hw.py
* @author munraimix
* @brief Structured hardware SDK tools (assembler + APIC/IDT/SMI/LBR/PT packets).
* @copyright This project is released under the GNU Public License v3.
*
* These wrap the binary-packet libhyperdbg exports. Struct layouts are verified
* against the SDK headers. NOTE: not yet hardware-validated (need Intel PT/LBR
* hardware + a debug session); the CLI passthrough (!apic/!idt/!pt/...) remains
* the fallback until these are exercised on a real target.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer

from .errors import HyperDbgError
from .toolkit import RO, app_ctx, resolve_addr, run_text


def register_hw(mcp: MCPServer, *, read_only: bool) -> None:
    @mcp.tool(name="hd_assemble", annotations=RO)
    def hd_assemble(assembly: str, ctx: Context, address: str = "0") -> str:
        """Assemble x86-64 instruction(s) at `address` (hex string) to machine-code hex."""
        app = app_ctx(ctx)
        data = app.session.assemble(assembly, resolve_addr(ctx, address))
        app.audit.record("hd_assemble", {"assembly": assembly}, status="ok")
        return data.hex()

    @mcp.tool(name="hd_idt_entries", annotations=RO)
    def hd_idt_entries(ctx: Context) -> str:
        """Dump the 256-entry Interrupt Descriptor Table (handler pointers)."""
        app = app_ctx(ctx)
        r = app.session.get_idt_entries()
        app.audit.record("hd_idt_entries", {}, status="ok")
        lines = [f"kernel_status={r['kernel_status']:#010x}"]
        lines += [f"[{i:#04x}] {v:#018x}" for i, v in enumerate(r["entries"]) if v]
        return "\n".join(lines)

    @mcp.tool(name="hd_apic_local", annotations=RO)
    def hd_apic_local(ctx: Context) -> str:
        """Show the Local APIC of the operating core (xAPIC or x2APIC registers)."""
        return run_text(ctx, "!apic", audit="hd_apic_local", kind="hardware")

    @mcp.tool(name="hd_apic_io", annotations=RO)
    def hd_apic_io(ctx: Context) -> str:
        """Dump the IO APIC redirection table."""
        app = app_ctx(ctx)
        r = app.session.get_io_apic()
        app.audit.record("hd_apic_io", {}, status="ok")
        head = f"base_pa={r['base_pa']:#x} base_va={r['base_va']:#x} id={r['id']:#x}"
        entries = [f"[{i:#04x}] {v:#018x}" for i, v in enumerate(r["entries"]) if v]
        return head + "\n" + "\n".join(entries)

    @mcp.tool(name="hd_smi_count", annotations=RO)
    def hd_smi_count(ctx: Context) -> str:
        """Read the System Management Interrupt (SMI) count."""
        app = app_ctx(ctx)
        n = app.session.smi_count()
        app.audit.record("hd_smi_count", {}, status="ok")
        return f"smi_count={n}"

    @mcp.tool(name="hd_pci_tree", annotations=RO)
    def hd_pci_tree(ctx: Context) -> str:
        """Enumerate the PCI/PCIe devices (bus:device.function, vendor/device ids)."""
        return run_text(ctx, "!pcitree", audit="hd_pci_tree", kind="hardware")

    @mcp.tool(name="hd_pci_cam", annotations=RO)
    def hd_pci_cam(bus: int, device: int, function: int, ctx: Context, raw: bool = False) -> str:
        """Dump a PCI device's configuration space (decoded; raw=True adds a hex dump)."""
        if not (0 <= bus <= 0xFF and 0 <= device <= 0x1F and 0 <= function <= 7):
            raise HyperDbgError("bus 0-0xff, device 0-0x1f, function 0-7")
        cmd = f"!pcicam {bus:x} {device:x} {function:x}" + (" x" if raw else "")
        return run_text(
            ctx, cmd, audit="hd_pci_cam", kind="hardware",
            args={"bus": bus, "device": device, "function": function},
        )
