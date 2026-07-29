"""
 * @file live_smoke.py
 * @author munraimix
 * @brief Live FFI smoke test against libhyperdbg on a HyperDbg host.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Validates the ctypes <-> libhyperdbg.dll boundary in isolation from MCP.
 *
 * PHASE 1 (default, low-risk): DLL load, VMX detection, module-loaded check,
 * connect_local_debugger, and `.status`. Exercises the whole FFI crux
 * (callback capture, run_command, boolean returns) WITHOUT loading the
 * hypervisor. Reads of registers/memory are NOT attempted here.
 *
 * PHASE 2 (--load-vmm, CONSEQUENTIAL): loads the HyperDbg VMM, i.e. places
 * the running OS under HyperDbg's hypervisor (requires DSE off / test-signing),
 * then attempts register/memory reads. Only runs when you pass --load-vmm.
 * Pass --unload-after to unload the VMM when done.
 *
 * Run on the HyperDbg host, as Administrator:
 *   python scripts/live_smoke.py --lib-path C:\\path\\to\\libhyperdbg.dll
 *   python scripts/live_smoke.py --lib-path ... --load-vmm --unload-after
 """

from __future__ import annotations

import argparse
import sys


def _step(name, fn):
    print(f"\n=== {name} ===")
    try:
        result = fn()
        print(result if result is not None else "(ok)")
        return True
    except Exception as exc:  # noqa: BLE001 - diagnostic tool: report everything
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="libhyperdbg FFI smoke test")
    ap.add_argument("--lib-path", default=None, help="Path to libhyperdbg.dll")
    ap.add_argument(
        "--load-vmm",
        action="store_true",
        help="PHASE 2: load the HyperDbg hypervisor and attempt register/memory reads.",
    )
    ap.add_argument("--unload-after", action="store_true", help="Unload the VMM at the end.")
    ap.add_argument("--read-addr", default=None, help="Hex virtual address to read 16 bytes from")
    args = ap.parse_args()

    from hyperdbg_mcp.ffi import load_libhyperdbg
    from hyperdbg_mcp.session import HyperDbgSession

    results: dict[str, bool] = {}

    print("Loading libhyperdbg (exercises DLL load + prototype config)...")
    try:
        dll = load_libhyperdbg(args.lib_path)
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: could not load libhyperdbg: {exc}")
        return 2
    print("Loaded OK.")

    session = HyperDbgSession(dll=dll)

    # ---- Phase 1: safe, no hypervisor ---- #
    results["detect_vmx_support"] = _step(
        "detect_vmx_support", lambda: f"VMX supported: {session.detect_vmx_support()}"
    )
    results["is_any_module_loaded"] = _step(
        "is_any_module_loaded", lambda: f"module already loaded: {session.is_any_module_loaded()}"
    )
    results["connect_local_debugger"] = _step("connect_local_debugger", session.connect)
    results[".status (run_command + callback capture)"] = _step(
        ".status", lambda: session.run_command(".status")
    )

    # ---- Phase 2: consequential, only with --load-vmm ---- #
    if args.load_vmm:
        print("\n!!! PHASE 2: loading the HyperDbg VMM (hypervisor) !!!")
        results["load_vmm"] = _step("load_vmm", lambda: f"load_vmm returned {session.load_vmm()}")
        results["read_all_registers"] = _step(
            "read_all_registers",
            lambda: "\n".join(f"  {k}={v:#x}" for k, v in session.read_all_registers().items()),
        )
        results["read_target_register(rip)"] = _step(
            "read_target_register(rip)", lambda: f"rip = {session.read_register('rip'):#x}"
        )
        if args.read_addr:
            addr = int(args.read_addr, 16)
            results["read_memory"] = _step(
                f"read_memory({addr:#x}, 16)", lambda: session.read_memory(addr, 16).hex()
            )
        if args.unload_after:
            results["unload_vmm"] = _step(
                "unload_vmm", lambda: f"unload_vmm returned {session.unload_vmm()}"
            )
    else:
        print("\n(Skipping register/memory reads - pass --load-vmm to load the "
              "hypervisor and attempt them. Phase 1 already validates the FFI path.)")

    session.close()

    print("\n================ SUMMARY ================")
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("========================================")
    failed = [n for n, ok in results.items() if not ok]
    if failed:
        print(f"{len(failed)} step(s) failed. If '.status' PASSED, the FFI path is "
              "confirmed working; register/memory FAILs usually mean the VMM isn't "
              "loaded or there's no paused context, not an FFI bug.")
        return 1
    print("All attempted steps passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
