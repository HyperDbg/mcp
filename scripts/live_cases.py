"""
 * @file live_cases.py
 * @brief Live end-to-end test cases for the whole MCP tool surface.
 * @copyright This project is released under the GNU Public License v3.
 *
 * Drives a running hyperdbg-mcp server (Streamable HTTP) through one case per
 * tool, plus the validation cases and the idempotency cases a real session
 * needs. Each case states what a correct server must answer, so a failure is
 * either a bug in the tool or a change in HyperDbg itself.
 *
 *   python scripts/live_cases.py --url http://127.0.0.1:8765/mcp --token <bearer>
 *   python scripts/live_cases.py --config client/.http.json --report /tmp/live.json
 *
 * Expect kinds:
 *   ok      - no tool error
 *   error   - a tool error (isError true)
 *   any     - recorded as INFO: the answer depends on the machine (module not
 *             loaded, Debugger-Mode-only feature, ...)
 * With "contains", the text must also contain that substring.
 *
 * NOTE: the suite is destructive by design (VMM load/unload, events, memory
 * writes of the bytes it just read). Run it on the test rig only.
"""

# ruff: noqa: E501 - the case table reads better as one line per case
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field

import anyio
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

SYM_PATH = r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
QUERY_PC = "nt!NtQueryPerformanceCounter"
TEST_EXE = r"C:\work\hdtest2\hdtest.exe"
DUMP_FILE = r"C:\work\tc_dump.bin"
OUT_FILE = r"C:\work\tc_out.log"
# HyperDbg cannot delete an output source, so every run needs its own name.
OUT_NAME = "tcr" + str(os.getpid()) + str(int(time.time()) % 100000)


@dataclass
class Case:
    phase: str
    case_id: str
    tool: str
    args: dict = field(default_factory=dict)
    expect: str = "ok"
    contains: str = ""
    note: str = ""


def cases() -> list[Case]:
    c: list[Case] = []

    def add(phase, case_id, tool, args=None, expect="ok", contains="", note=""):
        c.append(Case(phase, case_id, tool, args or {}, expect, contains, note))

    # ----- cold: before the VMM is loaded ---------------------------------- #
    add("cold", "status-cold", "hd_status", {}, "error", "not connected")
    add("cold", "reg-cold", "hd_reg_read", {"name": "rip"}, "error", "not connected")
    add("cold", "disasm-cold", "hd_disasm", {"address": "0x140000000"}, "error", "not connected")
    add("cold", "vmm-status-cold", "hd_vmm_status", {}, "ok")
    add("cold", "conn-cold", "hd_connection_status", {}, "ok")

    # ----- load ------------------------------------------------------------ #
    add("load", "vmm-load", "hd_vmm_load", {}, "ok")
    add("load", "vmm-status", "hd_vmm_status", {}, "ok", "module_loaded=True")
    add("load", "conn-status", "hd_connection_status", {}, "ok", "connected=True")
    add("load", "sym-path", "hd_sym_path", {"path": SYM_PATH}, "ok")
    add("load", "sym-reload", "hd_sym_reload", {}, "ok")
    add("load", "sym-examine", "hd_sym_examine", {"pattern": "NtQueryPerformanceCounter"}, "ok", "nt!")

    # ----- read: one case per read tool ------------------------------------ #
    add("read", "status", "hd_status", {}, "ok")
    add("read", "kernel-base", "hd_kernel_base", {}, "ok", "0x")
    add("read", "cpu-vendor", "hd_cpu_vendor", {}, "ok")
    add("read", "cpu-info", "hd_cpu_info", {}, "ok")
    add("read", "vmx-support", "hd_vmx_support", {}, "ok")
    add("read", "list-modules", "hd_list_modules", {}, "ok", "ntoskrnl")
    add("read", "smi-count", "hd_smi_count", {}, "ok")
    add("read", "idt", "hd_idt_entries", {}, "ok")
    add("read", "apic-local", "hd_apic_local", {}, "ok")
    add("read", "apic-io", "hd_apic_io", {}, "ok")
    add("read", "pci-tree", "hd_pci_tree", {}, "ok")
    add("read", "pci-cam", "hd_pci_cam", {"bus": 0, "device": 0, "function": 0}, "ok")
    add("read", "mem-read-kernel", "hd_mem_read", {"address": QUERY_PC, "size": 16}, "ok", "48895c24")
    add("read", "mem-display", "hd_mem_display", {"address": QUERY_PC, "size": 32, "fmt": "byte"}, "ok")
    add("read", "mem-search", "hd_mem_search", {"address": QUERY_PC, "value": "48895c24", "fmt": "byte", "length": 64}, "any")
    add("read", "disasm-symbol", "hd_disasm", {"address": QUERY_PC, "count": 4}, "ok", "mov")
    add("read", "eval", "hd_eval", {"expression": "1+2"}, "ok")
    add("read", "pte", "hd_pte", {"virtual_address": QUERY_PC}, "ok")
    add("read", "va2pa", "hd_va2pa", {"virtual_address": QUERY_PC}, "ok")
    add("read", "pa2va", "hd_pa2va", {"physical_address": "0x1000"}, "any")
    add("read", "struct-display", "hd_struct_display", {"type_name": "nt!_LIST_ENTRY"}, "any")
    add("read", "struct-export", "hd_struct_export", {"type_name": "nt!_LIST_ENTRY"}, "any")
    add("read", "pe-parse", "hd_pe_parse", {"path": TEST_EXE, "section": ".text"}, "any")
    add("read", "assemble", "hd_assemble", {"assembly": "mov al, 1"}, "ok")
    add("read", "cpuid", "hd_cpuid", {"opcode": 0}, "ok")
    add("read", "msr-read", "hd_msr_read", {"msr_id": "0xC0000082"}, "ok")
    add("read", "stack", "hd_stack", {}, "any")
    add("read", "bp-list", "hd_bp_list", {}, "error", "debugger-mode")
    add("read", "event-list", "hd_event_list", {}, "ok")
    add("read", "output-list", "hd_output_list", {}, "ok")
    add("read", "settings-get", "hd_settings", {"option": "syntax"}, "ok")
    add("read", "lbr-dump", "hd_lbr_dump", {}, "any")
    add("read", "pt-dump", "hd_pt_dump", {}, "any")

    # ----- events / hooks / output ----------------------------------------- #
    add("events", "out-create", "hd_output_create", {"name": OUT_NAME, "output_type": "file", "address": OUT_FILE}, "ok")
    add("events", "out-open", "hd_output", {"action": "open", "name": OUT_NAME}, "ok")
    add("events", "out-open-again", "hd_output", {"action": "open", "name": OUT_NAME}, "ok", "already open")
    add("events", "ept2", "hd_hook_ept2", {"address": QUERY_PC, "script": 'printf("e2\n");', "output": OUT_NAME}, "ok")
    add("events", "ept", "hd_hook_ept", {"address": QUERY_PC, "script": 'printf("e1\n");'}, "ok")
    add("events", "monitor", "hd_hook_monitor", {"attribute": "rwx", "from_address": QUERY_PC, "to_address": QUERY_PC + "+8", "script": 'printf("m\n");'}, "any", note="conflicts with the EPT hook on the same page")
    add("events", "trace-hook", "hd_hook_trace", {"trace_type": "step-in", "script": 'printf("t\n");'}, "ok")
    add("events", "exception-hook", "hd_hook_exception", {"script": 'printf("x\n");'}, "ok")
    add("events", "interrupt-hook", "hd_hook_interrupt", {"idt_index": 46, "script": 'printf("i\n");'}, "ok")
    add("events", "ioin-hook", "hd_hook_ioin", {"port": 96, "script": 'printf("in\n");'}, "ok", note="VMI cannot break, so every event needs a script")
    add("events", "ioout-hook", "hd_hook_ioout", {"port": 128, "script": 'printf("out\n");'}, "ok")
    add("events", "msrread-hook", "hd_hook_msrread", {"msr": 3221225602, "script": 'printf("mr\n");'}, "ok")
    add("events", "msrwrite-hook", "hd_hook_msrwrite", {"msr": 3221225602, "script": 'printf("mw\n");'}, "ok")
    add("events", "syscall-hook", "hd_hook_syscall", {"script": 'printf("sc\n");'}, "ok")
    add("events", "sysret-hook", "hd_hook_sysret", {"script": 'printf("sr\n");'}, "ok")
    add("events", "tsc-hook", "hd_hook_tsc", {"script": 'printf("tsc\n");'}, "ok")
    add("events", "pmc-hook", "hd_hook_pmc", {"script": 'printf("pmc\n");'}, "any")
    add("events", "dr-hook", "hd_hook_dr", {"script": 'printf("dr\n");'}, "any")
    add("events", "crwrite-hook", "hd_hook_crwrite", {"cr": 0, "script": 'printf("cr\n");'}, "ok")
    add("events", "xsetbv-hook", "hd_hook_xsetbv", {"xcr": 0, "script": 'printf("xv\n");'}, "ok")
    add("events", "vmcall-hook", "hd_hook_vmcall", {"script": 'printf("vc\n");'}, "ok")
    add("events", "cpuid-hook", "hd_hook_cpuid", {"eax": 0, "script": 'printf("cp\n");'}, "ok")
    add("events", "preactivate", "hd_preactivate", {"feature": "mode"}, "any")
    add("events", "mode-hook", "hd_hook_mode", {"mode": "user", "pid": 4, "script": 'printf("md\n");'}, "any")
    add("events", "prealloc", "hd_prealloc", {"kind": "epthook", "count": 8}, "any")
    add("events", "event-disable", "hd_event_disable", {"target": "all"}, "ok")
    add("events", "event-enable", "hd_event_enable", {"target": "all"}, "ok")
    add("events", "event-sc", "hd_event_sc", {"state": "on"}, "error", "com port", note="needs a serial debuggee")
    add("events", "event-list-full", "hd_event_list", {}, "ok")
    add("events", "event-clear", "hd_event_clear", {"target": "all"}, "ok")
    add("events", "event-list-empty", "hd_event_list", {}, "ok")
    add("events", "transparent-on", "hd_transparent_enable", {"name": "notepad.exe"}, "any")
    add("events", "transparent-off", "hd_transparent_disable", {}, "any")
    add("events", "settings-set", "hd_settings", {"option": "syntax", "value": "intel"}, "ok")
    add("events", "flush", "hd_flush", {}, "ok")
    add("events", "io-in", "hd_io_in", {"port": 128, "width": "al"}, "ok", note="needs the kd module, which the VMM load installs")
    add("events", "io-out", "hd_io_out", {"port": 128, "value": 0, "width": "al"}, "ok", note="port 0x80 is the POST port")
    add("events", "modules-load", "hd_modules_load_all", {}, "any", note="loads every HyperDbg module")
    add("events", "modules-unload", "hd_modules_unload_all", {}, "any")
    add("events", "sym-reload-after-modules", "hd_sym_reload", {}, "any", note="the module ops drop the symbol tables")
    add("events", "mem-dump", "hd_mem_dump", {"from_address": QUERY_PC, "to_address": QUERY_PC + "+0x10", "path": DUMP_FILE}, "ok")
    add("events", "lbr-disable", "hd_lbr", {"action": "disable"}, "any")
    add("events", "lbr-filter", "hd_lbr_filter", {"exclude": ["kernel", "user"]}, "any")
    add("events", "pt-control", "hd_pt_control", {"action": "disable"}, "any")
    add("events", "pt-filter", "hd_pt_filter", {"modes": ["user"]}, "any")
    add("events", "pt-packets", "hd_pt_packets", {"packets": ["psb", "tip"]}, "any")
    add("events", "pt-enable", "hd_pt_enable", {"buffer_size": 4096}, "any")
    add("events", "exec-command", "hd_exec_command", {"command": ".status"}, "ok")
    add("events", "script-run", "hd_script_run", {"script": 'printf("hi\n");'}, "any")
    add("events", "core-switch", "hd_core_switch", {"core": 0}, "error", note="no cores to switch in VMI mode")
    add("events", "process-list", "hd_process_switch", {"list_only": True}, "any")
    add("events", "thread-list", "hd_thread_switch", {"list_only": True}, "any")
    add("events", "user-thread-list", "hd_user_thread_switch", {}, "any")

    # ----- writes ---------------------------------------------------------- #
    add("write", "mem-write-roundtrip", "hd_mem_write", {"address": QUERY_PC, "data_hex": "48895c2408574883"}, "any", note="writes the bytes it read")
    add("write", "mem-edit-roundtrip", "hd_mem_edit", {"address": QUERY_PC, "value": "0x48", "fmt": "byte"}, "any")
    add("write", "reg-write", "hd_reg_write", {"name": "rip", "value": "0x140000000"}, "any", note="needs a halted context")
    add("write", "msr-write", "hd_msr_write", {"msr_id": "0xC0000082", "value": "0x0"}, "any")
    add("write", "pagein", "hd_pagein", {"address": QUERY_PC}, "error", "debugger mode")
    add("write", "bp-set", "hd_bp_set", {"address": "nt!NtClose"}, "error", "debugger mode")
    add("write", "bp-modify", "hd_bp_modify", {"breakpoint_id": 0, "action": "disable"}, "any")
    add("write", "connect-local", "hd_connect", {"transport": "local"}, "any")

    # ----- user-mode debugger ---------------------------------------------- #
    add("umd", "process-start", "hd_process_start", {"path": TEST_EXE}, "ok")
    add("umd", "process-attach", "hd_process_attach", {"pid": 4}, "any", note="the beta user-mode debugger may refuse")
    add("umd", "umd-reg", "hd_reg_read", {"name": "rip"}, "ok")
    add("umd", "umd-disasm", "hd_disasm", {"address": "@rip", "count": 3}, "ok")
    add("umd", "umd-mem", "hd_mem_read", {"address": "@rip", "size": 8}, "ok")
    add("umd", "umd-modules", "hd_list_modules", {}, "ok", "hdtest.exe")
    add("umd", "umd-continue", "hd_exec_continue", {}, "ok")
    add("umd", "umd-pause", "hd_exec_pause", {}, "ok")
    add("umd", "umd-regs", "hd_reg_read_all", {}, "any")
    add("umd", "umd-step", "hd_exec_step", {"mode": "over"}, "any", note="may wait for a halt that never comes")
    add("umd", "umd-step-out", "hd_step_out", {"max_steps": 1}, "any")
    add("umd", "umd-step-track", "hd_step_track", {}, "any")
    add("umd", "umd-restart", "hd_process_restart", {}, "any")
    add("umd", "umd-kill", "hd_process_kill", {}, "ok")
    add("umd", "umd-detach", "hd_process_detach", {}, "any")

    # ----- negative / validation ------------------------------------------- #
    add("neg", "bad-symbol", "hd_mem_read", {"address": "zzz!nope", "size": 16}, "error", "could not evaluate")
    add("neg", "size-zero", "hd_mem_read", {"address": QUERY_PC, "size": 0}, "error", "out of range")
    add("neg", "size-huge", "hd_mem_read", {"address": QUERY_PC, "size": 0x2000000}, "error", "out of range")
    add("neg", "bad-reg", "hd_reg_read", {"name": "nosuchreg"}, "error", "unknown register")
    add("neg", "bad-reg-write", "hd_reg_write", {"name": "nosuchreg", "value": "1"}, "error", "unknown register")
    add("neg", "bad-msr", "hd_msr_read", {"msr_id": "zz"}, "error")
    add("neg", "bad-setting", "hd_settings", {"option": "nosuch"}, "error", "invalid option")
    add("neg", "bad-setting-value", "hd_settings", {"option": "syntax", "value": "zzz"}, "error", "invalid value")
    add("neg", "bad-output-name", "hd_output_create", {"name": "a,b", "output_type": "file", "address": OUT_FILE}, "error", "one name")
    add("neg", "bad-output-type", "hd_output_create", {"name": "x1", "output_type": "zzz", "address": OUT_FILE}, "error", "output_type")
    add("neg", "bad-output-action", "hd_output", {"action": "zzz", "name": OUT_NAME}, "error", "action")
    add("neg", "no-such-source", "hd_output", {"action": "open", "name": "nope"}, "error", "nope")
    add("neg", "bad-monitor-attr", "hd_hook_monitor", {"attribute": "zzz", "from_address": QUERY_PC, "to_address": QUERY_PC + "+8"}, "error")
    add("neg", "bad-idt-index", "hd_hook_exception", {"idt_index": 4096}, "error")
    add("neg", "bad-ept-address", "hd_hook_ept2", {"address": "0x1"}, "error")
    add("neg", "bad-trace-type", "hd_hook_trace", {"trace_type": "zzz"}, "error")
    add("neg", "bad-mode", "hd_hook_mode", {"mode": "zzz", "pid": 4}, "error")
    add("neg", "bad-pci", "hd_pci_cam", {"bus": -1, "device": 0, "function": 0}, "error")
    add("neg", "bad-port", "hd_io_in", {"port": -1}, "error")
    add("neg", "relative-dump-path", "hd_mem_dump", {"from_address": QUERY_PC, "to_address": QUERY_PC + "+16", "path": "relative.bin"}, "error")
    add("neg", "missing-pe", "hd_pe_parse", {"path": r"C:\no\such.exe"}, "error")
    add("neg", "bad-step-mode", "hd_exec_step", {"mode": "zzz"}, "error")
    add("neg", "bad-prealloc-kind", "hd_prealloc", {"kind": "zzz", "count": 1}, "error")
    add("neg", "bad-preactivate", "hd_preactivate", {"feature": "zzz"}, "error")
    add("neg", "bad-transport", "hd_connect", {"transport": "zzz"}, "error")
    add("neg", "bad-event-sc", "hd_event_sc", {"state": "zzz"}, "error")
    add("neg", "bad-event-target", "hd_event_disable", {"target": "zz"}, "error")
    add("neg", "bad-search-value", "hd_mem_search", {"address": QUERY_PC, "value": "zz"}, "error")

    # ----- cleanup --------------------------------------------------------- #
    add("cleanup", "clear-events", "hd_event_clear", {"target": "all"}, "ok")
    add("cleanup", "close-source", "hd_output", {"action": "close", "name": OUT_NAME}, "ok")
    add("cleanup", "close-again", "hd_output", {"action": "close", "name": OUT_NAME}, "ok", "already closed")
    add("cleanup", "vmm-unload", "hd_vmm_unload", {}, "any", note="modules_unload_all already took the VMM down")
    add("cleanup", "vmm-status-end", "hd_vmm_status", {}, "ok", "module_loaded=False")
    add("cleanup", "disconnect", "hd_disconnect", {}, "any", note="closes the session, so it runs last")
    add("cleanup", "reconnect", "hd_reconnect", {}, "any")
    return c


@dataclass
class Result:
    case: Case
    status: str  # PASS / FAIL / INFO / SKIP
    detail: str = ""


async def call(session: ClientSession, name: str, args: dict, timeout: float = 90.0):
    with anyio.fail_after(timeout):
        res = await session.call_tool(name, args)
    text = " ".join(getattr(part, "text", "") or json.dumps(part, default=str) for part in (res.content or []))
    text = " ".join(text.split())
    return bool(res.is_error), text


async def run(args) -> int:
    cfg = {"url": args.url, "headers": {}}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
    if args.token:
        cfg.setdefault("headers", {})["Authorization"] = "Bearer " + args.token

    all_cases = [c for c in cases() if not args.phase or c.phase in args.phase]
    results: list[Result] = []
    covered: set[str] = set()

    async with httpx2.AsyncClient(headers=cfg.get("headers", {}), timeout=120.0) as http:
        async with streamable_http_client(cfg["url"], http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                print(f"server tools: {len(tools)}; cases: {len(all_cases)}\n")

                err, text = await call(session, "hd_connection_status", {})
                connected = "connected=True" in text
                print(f"session: {text}\n")


                current_phase = None

                async def phase_setup(phase: str) -> None:
                    """VMM + symbols before every phase: an earlier phase may have
                    unloaded the modules (hd_modules_unload_all takes the VMM down too)."""
                    if phase == "cold":
                        return
                    for name, sargs in (
                        ("hd_vmm_load", {}),
                        ("hd_sym_path", {"path": SYM_PATH}),
                        ("hd_sym_reload", {}),
                    ):
                        try:
                            e, t = await call(session, name, sargs, args.timeout)
                            print(f"  [setup] {name}: {'ERR' if e else 'ok'} {t[:70]}")
                        except Exception as exc:  # noqa: BLE001
                            print(f"  [setup] {name}: FAILED {exc}")
                    print()

                for case in all_cases:
                    if case.phase != current_phase:
                        current_phase = case.phase
                        await phase_setup(current_phase)
                    covered.add(case.tool)
                    if case.tool not in tools:
                        results.append(Result(case, "SKIP", "tool not registered"))
                        continue
                    if case.phase == "cold" and connected:
                        results.append(Result(case, "SKIP", "already connected"))
                        continue
                    if args.only and args.only not in case.case_id:
                        results.append(Result(case, "SKIP", "filtered"))
                        continue
                    try:
                        is_err, text = await call(session, case.tool, case.args, args.timeout)
                    except Exception as exc:  # noqa: BLE001 - report and continue
                        results.append(Result(case, "FAIL", f"{type(exc).__name__}: {exc}"))
                        continue

                    if case.expect == "ok":
                        good = not is_err
                    elif case.expect == "error":
                        good = is_err
                    else:
                        results.append(Result(case, "INFO", ("ERR " if is_err else "ok ") + text[:110]))
                        continue
                    if good and case.contains and case.contains.lower() not in text.lower():
                        good = False
                    status = "PASS" if good else "FAIL"
                    results.append(Result(case, status, ("ERR " if is_err else "ok ") + text[:110]))

    width = max(len(r.case.case_id) for r in results) if results else 10
    for r in results:
        print(f"  [{r.status:4}] {r.case.case_id:<{width}}  {r.case.tool:<22} {r.detail}")
    if args.phase is None or "cleanup" in args.phase:
        missing = sorted(tools - covered)
        if missing:
            print("\nUNCOVERED tools (no case): " + ", ".join(missing))

    counts = {k: sum(1 for r in results if r.status == k) for k in ("PASS", "FAIL", "INFO", "SKIP")}
    print(f"\n==== {counts['PASS']} pass, {counts['FAIL']} fail, {counts['INFO']} info, {counts['SKIP']} skip ====")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(
                [
                    {
                        "id": r.case.case_id,
                        "phase": r.case.phase,
                        "tool": r.case.tool,
                        "args": r.case.args,
                        "expect": r.case.expect,
                        "contains": r.case.contains,
                        "status": r.status,
                        "detail": r.detail,
                    }
                    for r in results
                ],
                fh,
                indent=1,
            )
        print(f"report: {args.report}")
    return 1 if counts["FAIL"] else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Live end-to-end cases for the MCP tool surface")
    ap.add_argument("--config", default=None, help="JSON with url + headers (e.g. client/.http.json)")
    ap.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    ap.add_argument("--token", default=None)
    ap.add_argument("--phase", action="append", help="run only this phase (repeatable)")
    ap.add_argument("--only", default=None, help="run only cases whose id contains this")
    ap.add_argument("--timeout", type=float, default=90.0, help="per-call timeout, seconds")
    ap.add_argument("--report", default=None, help="write a JSON report here")
    args = ap.parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
