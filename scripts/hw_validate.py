"""
 * @file hw_validate.py
 * @author munraimix
 * @brief Read-only hardware validation of the new tool surface over the serial rig.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Run on the DEBUGGER host. Connects to the debuggee over a COM port with
 * pause-on-connect (valid CPU context), then exercises the session methods that
 * back a sample of the new tools across every domain - READS ONLY (no hooks,
 * writes, process switches, or continue). Leaves the debuggee paused; resume it
 * with `g` on the debuggee, or just reconnect.
 *
 *   python scripts/hw_validate.py --lib-path C:\\HyperDbg\\release\\libhyperdbg.dll --com com4
"""

from __future__ import annotations

import argparse
import sys


def _step(name, fn):
    print(f"\n=== {name} ===")
    try:
        result = fn()
        text = result if isinstance(result, str) else repr(result)
        print(text if len(text) < 800 else text[:800] + " ...[truncated]")
        return True
    except Exception as exc:  # noqa: BLE001 - diagnostic tool
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only HW validation of the new tool surface")
    ap.add_argument("--lib-path", default=None)
    ap.add_argument("--com", required=True, help="COM port to the debuggee, e.g. com4")
    ap.add_argument("--baudrate", type=int, default=115200)
    args = ap.parse_args()

    from hyperdbg_mcp.ffi import load_libhyperdbg
    from hyperdbg_mcp.session import HyperDbgSession

    print("Loading libhyperdbg...")
    dll = load_libhyperdbg(args.lib_path)
    s = HyperDbgSession(dll=dll)

    results: dict[str, bool] = {}
    results["connect_remote_com"] = _step(
        f"connect_remote_com({args.com}@{args.baudrate}, pause)",
        lambda: s.connect_remote_com(args.com, args.baudrate, pause=True),
    )
    if not results["connect_remote_com"]:
        print("\nAborting: no connection.")
        return 2

    # ---- assembler (no target needed) ----
    results["hd_assemble"] = _step("assemble('mov rax, 1')", lambda: s.assemble("mov rax, 1").hex())

    # ---- Batch B SDK reads ----
    results["hd_cpu_vendor"] = _step("get_processor_vendor", s.get_processor_vendor)
    kbase = {}

    def _kernel_base():
        kbase["v"] = s.get_kernel_base()
        return hex(kbase["v"])

    results["hd_kernel_base"] = _step("get_kernel_base", _kernel_base)

    # ---- existing/registers (re-confirm) ----
    results["hd_reg_read_all"] = _step(
        "read_all_registers", lambda: {k: hex(v) for k, v in s.read_all_registers().items()}
    )

    # ---- memory read at the kernel base (if we got it) ----
    if kbase.get("v"):
        results["hd_mem_read"] = _step(
            f"read_memory({kbase['v']:#x}, 16)", lambda: s.read_memory(kbase["v"], 16).hex()
        )

    # ---- CLI-backed read tools (typed-in / text-out) ----
    results["hd_list_modules"] = _step("run_command('lm')", lambda: s.run_command("lm"))
    results["hd_sym_examine"] = _step("run_command('x nt!NtCreateFile')",
                                      lambda: s.run_command("x nt!NtCreateFile"))
    results["hd_disasm"] = _step("run_command('u @rip l 4')", lambda: s.run_command("u @rip l 4"))
    if kbase.get("v"):
        results["hd_va2pa"] = _step(f"run_command('!va2pa {kbase['v']:#x}')",
                                    lambda: s.run_command(f"!va2pa {kbase['v']:#x}"))

    # ---- Batch C structured hardware reads ----
    results["hd_idt_entries"] = _step(
        "get_idt_entries", lambda: f"kernel_status={s.get_idt_entries()['kernel_status']:#x}, "
        f"first entries: {[hex(e) for e in s.get_idt_entries()['entries'][:4]]}"
    )
    results["hd_apic_io"] = _step(
        "get_io_apic", lambda: {k: (hex(v) if isinstance(v, int) else f"[{len(v)}]")
                                for k, v in s.get_io_apic().items()}
    )
    results["hd_smi_count"] = _step("smi_count", s.smi_count)

    # Leave the debuggee paused; close without continue (continue blocks awaiting
    # the next event - a known design item).
    s.close()

    print("\n================ SUMMARY ================")
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("========================================")
    print("Debuggee left paused. Resume with 'g' on the debuggee if needed.")
    return 1 if any(not ok for ok in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
