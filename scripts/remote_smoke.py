"""
 * @file remote_smoke.py
 * @author munraimix
 * @brief Debugger-Mode smoke over a serial/COM port. Run on the DEBUGGER host.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Connects to a remote HyperDbg debuggee over a COM port and, because the
 * debuggee is halted on connect (pause=True), attempts the register reads that
 * cannot work in local VMI mode. Run this on the DEBUGGER machine (the one
 * wired to the debuggee's serial cable) - NOT on the debuggee.
 *
 *   python scripts/remote_smoke.py --lib-path C:\\HyperDbg\\release\\libhyperdbg.dll --com com4
 *
 * By default it continues the debuggee and closes cleanly at the end. Pass
 * --leave-paused to keep it halted.
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
    ap = argparse.ArgumentParser(description="HyperDbg Debugger-Mode (serial) smoke test")
    ap.add_argument("--lib-path", default=None, help="Path to libhyperdbg.dll")
    ap.add_argument("--com", required=True, help="COM port to the debuggee, e.g. com4")
    ap.add_argument("--baudrate", type=int, default=115200)
    ap.add_argument("--read-addr", default=None, help="Hex virtual address to read 16 bytes from")
    ap.add_argument("--leave-paused", action="store_true", help="Do not continue the debuggee.")
    args = ap.parse_args()

    from hyperdbg_mcp.ffi import load_libhyperdbg
    from hyperdbg_mcp.session import HyperDbgSession

    results: dict[str, bool] = {}

    print("Loading libhyperdbg...")
    try:
        dll = load_libhyperdbg(args.lib_path)
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: could not load libhyperdbg: {exc}")
        return 2
    print("Loaded OK.")

    session = HyperDbgSession(dll=dll)

    results[f"connect_remote_com({args.com})"] = _step(
        f"connect_remote_com({args.com}@{args.baudrate}, pause=True)",
        lambda: session.connect_remote_com(args.com, args.baudrate, pause=True),
    )
    results[".status"] = _step(".status", lambda: session.run_command(".status"))
    # These should now succeed: the debuggee is halted, so there is a context.
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

    if not args.leave_paused:
        results["continue_debuggee"] = _step("continue_debuggee", session.continue_debuggee)

    session.close()

    print("\n================ SUMMARY ================")
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("========================================")
    return 1 if any(not ok for ok in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
