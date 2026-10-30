"""
* @file live_cases.py
* @brief Live end-to-end test cases for the whole MCP tool surface.
* @copyright This project is released under the GNU Public License v3.
*
* Drives a running hyperdbg-mcp server (Streamable HTTP) through one case per
* tool, plus the validation cases, the regressions of crashes and hangs found
* so far, and checks of what the machine did (hooks fire, writes read back,
* events go away). Each case states what a correct server must answer, so a
* failure is either a bug in the tool or a change in HyperDbg itself.
*
*   python scripts/live_cases.py --config client/.http.json --report /tmp/live.json
*   python scripts/live_cases.py ... --machine "~/git/hdtools/wps" --dangerous
*   python scripts/live_cases.py ... --soak 20 --concurrency 4 --phase read --phase umd
*   python scripts/live_cases.py ... --compare /tmp/live-before.json
*
* Expect kinds:
*   ok      - no tool error
*   error   - a tool error (isError true)
*   any     - recorded as INFO: the answer depends on the machine
* With "contains", the text must also contain that substring; with "match",
* it must match that regular expression. Every case has a time budget: a
* slower answer fails the case (a hang is a bug too).
*
* --machine runs PowerShell on the target (a command that takes the script as
* its last argument). With it, the boot time is checked after every phase,
* every dangerous case and every call that raised: a reboot stops the run with
* the case that caused it and the bugcheck code. The regression phase needs it.
*
* Runner actions are cases whose tool starts with "@":
*   @fired    every marker in "markers" shows up in the output within "within" s;
              the ones in "also" are only reported
*   @quiet    "marker" stops showing up once "settle" s have passed (in at
              most one poll of the "window" after that)
*   @machine  run "ps" on the target
*   @restart  kill the MCP server process and start it again (HyperDbg state
*             and all), then reconnect
*
* NOTE: the suite is destructive by design (VMM load/unload, events, memory
* writes of the bytes it just read, killing the server). Run it on the test
* rig only.
"""

# ruff: noqa: E501 - the case table reads better as one line per case
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import shlex
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import anyio
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

SYM_PATH = r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
QUERY_PC = "nt!NtQueryPerformanceCounter"
QUERY_PC_BYTES = "48895c24"  # mov [rsp+...], rbx: the first bytes of QUERY_PC
TEST_EXE = r"C:\work\hdtest2\hdtest.exe"
DUMP_FILE = r"C:\work\tc_dump.bin"
OUT_FILE = r"C:\work\tc_out.log"
# How the rig runs the server: a scheduled task (see client/ in hdtools).
SERVER_RESTART_PS = (
    "Stop-ScheduledTask hyperdbg-mcp; "
    "Get-Process hyperdbg-mcp,python -ErrorAction SilentlyContinue | Stop-Process -Force; "
    "Start-Sleep 2; Start-ScheduledTask hyperdbg-mcp"
)
# HyperDbg cannot delete an output source, so every run needs its own name.
OUT_NAME = "tcr" + str(os.getpid()) + str(int(time.time()) % 100000)


def mk(name: str) -> str:
    """An event script that prints a marker @fired / @quiet look for."""
    return f'printf("MK_{name}\\n");'


@dataclass
class Case:
    phase: str
    case_id: str
    tool: str
    args: dict = field(default_factory=dict)
    expect: str = "ok"
    contains: str = ""
    note: str = ""
    dangerous: bool = False  # can crash the machine: opt in with --dangerous
    match: str = ""  # regex the answer must match (re.S | re.I)
    budget: float = 20.0  # seconds for all of the case's calls
    repeat: int = 1  # call it this many times; every answer must pass
    soak: bool = False  # order-independent read: shuffled and run concurrently by --soak


def cases() -> list[Case]:
    c: list[Case] = []

    def add(
        phase, case_id, tool, args=None, expect="ok", contains="", note="", dangerous=False, **kw
    ):
        c.append(Case(phase, case_id, tool, args or {}, expect, contains, note, dangerous, **kw))

    def read(case_id, tool, args=None, expect="ok", contains="", **kw):
        add("read", case_id, tool, args, expect, contains, soak=True, **kw)

    # ----- cold: before the VMM is loaded ---------------------------------- #
    add("cold", "status-cold", "hd_status", {}, "error", "not connected")
    add("cold", "reg-cold", "hd_reg_read", {"name": "rip"}, "error", "not connected")
    add("cold", "disasm-cold", "hd_disasm", {"address": "0x140000000"}, "error", "not connected")
    add("cold", "vmm-status-cold", "hd_vmm_status", {}, "ok", "module_loaded=False")
    add("cold", "conn-cold", "hd_connection_status", {}, "ok", "connected=False")

    # ----- load ------------------------------------------------------------ #
    add("load", "vmm-load", "hd_vmm_load", {}, "ok", "connected in local VMI mode", budget=60)
    add("load", "vmm-status", "hd_vmm_status", {}, "ok", "module_loaded=True")
    add("load", "conn-status", "hd_connection_status", {}, "ok", "connected=True")
    add("load", "sym-path", "hd_sym_path", {"path": SYM_PATH}, "ok", budget=120)
    add("load", "sym-reload", "hd_sym_reload", {}, "ok", budget=120)
    add("load", "sym-examine", "hd_sym_examine", {"pattern": "NtQueryPerformanceCounter"}, "ok", "nt!NtQueryPerformanceCounter", budget=60)

    # ----- read: one case per read tool ------------------------------------ #
    read("status", "hd_status", {}, "ok", "vmi mode")
    read("kernel-base", "hd_kernel_base", {}, match=r"^0xfffff[0-9a-f]{11}$")
    read("cpu-vendor", "hd_cpu_vendor", {}, match=r"^(Intel|AMD)$")
    read("cpu-info", "hd_cpu_info", {}, "ok", "brand :")
    read("vmx-support", "hd_vmx_support", {}, "ok", "vmx_supported=True")
    read("list-modules", "hd_list_modules", {}, "ok", "ntoskrnl")
    read("smi-count", "hd_smi_count", {}, match=r"smi_count=\d+")
    read("idt", "hd_idt_entries", {}, match=r"\[0x0e\] 0xfffff")
    read("apic-local", "hd_apic_local", {}, "ok", "LAPIC ID")
    read("apic-io", "hd_apic_io", {}, match=r"base_pa=0x[0-9a-f]+")
    read("pci-tree", "hd_pci_tree", {}, "ok", "8086")
    read("pci-cam", "hd_pci_cam", {"bus": 0, "device": 0, "function": 0}, "ok", "8086")
    read("mem-read-kernel", "hd_mem_read", {"address": QUERY_PC, "size": 16}, "ok", QUERY_PC_BYTES)
    read("mem-display", "hd_mem_display", {"address": QUERY_PC, "size": 32, "fmt": "byte"}, "ok", "48 89 5c 24")
    read("mem-search", "hd_mem_search", {"address": QUERY_PC, "value": "48 89 5c 24", "fmt": "byte", "length": 64}, match=r"fffff[0-9a-f`]+")
    read("disasm-symbol", "hd_disasm", {"address": QUERY_PC, "count": 4}, "ok", "mov")
    read("eval", "hd_eval", {"expression": "1+2"}, match=r"^0x3$")
    read("pte", "hd_pte", {"virtual_address": QUERY_PC}, "ok", "PML4E")
    read("va2pa", "hd_va2pa", {"virtual_address": QUERY_PC}, match=r"(?m)^\s*[0-9a-f]{6,}\s*$")
    read("pa2va", "hd_pa2va", {"physical_address": "0x1000"}, match=r"(?m)^\s*fffff[0-9a-f]{11}\s*$")
    read("struct-display", "hd_struct_display", {"type_name": "nt!_LIST_ENTRY"}, "ok", "Flink")
    read("struct-export", "hd_struct_export", {"type_name": "nt!_LIST_ENTRY"}, "ok", "Flink")
    read("pe-parse", "hd_pe_parse", {"path": TEST_EXE, "section": ".text"}, "ok", "MZ")
    read("assemble", "hd_assemble", {"assembly": "mov al, 1"}, match=r"^b001$")
    read("cpuid", "hd_cpuid", {"opcode": 0}, match=r"Vendor : (GenuineIntel|AuthenticAMD)")
    read("msr-read", "hd_msr_read", {"msr_id": "0xC0000082"}, match=r"core : 0x0 - msr\[c0000082\] = fffff")
    read("stack", "hd_stack", {}, "error", "not possible", note="'k' needs a debuggee")
    read("bp-list", "hd_bp_list", {}, "error", "debugger-mode")
    read("event-list", "hd_event_list", {}, "ok")
    read("output-list", "hd_output_list", {}, "ok")
    read("settings-get", "hd_settings", {"option": "syntax"}, "ok")
    read("pt-dump", "hd_pt_dump", {}, "ok", "PT dump")

    # ----- events / hooks / output ----------------------------------------- #
    # Every hook prints a marker; @fired then checks that the ones the machine
    # runs all the time really fire, and @quiet that a clear really removes them.
    add("events", "out-create", "hd_output_create", {"name": OUT_NAME, "output_type": "file", "address": OUT_FILE}, "ok")
    add("events", "out-open", "hd_output", {"action": "open", "name": OUT_NAME}, "ok")
    add("events", "out-open-again", "hd_output", {"action": "open", "name": OUT_NAME}, "ok", "already open")
    add("events", "output-list-open", "hd_output_list", {}, match=r"opened?\s+tcr\d+")
    add("events", "ept2", "hd_hook_ept2", {"address": QUERY_PC, "script": mk("EPT2"), "output": OUT_NAME}, "ok", note="the trampoline runs the copied prologue: 0x50 when the pool was NX")
    add("events", "ept", "hd_hook_ept", {"address": QUERY_PC, "script": mk("EPT")}, "ok")
    add("events", "monitor", "hd_hook_monitor", {"attribute": "rwx", "from_address": QUERY_PC, "to_address": QUERY_PC + "+8", "script": mk("MON")}, "error", "c0000026", note="the EPT hooks own that page")
    add("events", "trace-hook", "hd_hook_trace", {"trace_type": "step-in", "script": mk("TRACE")}, "ok")
    add("events", "exception-hook", "hd_hook_exception", {"script": mk("EXCEPTION")}, "ok")
    add("events", "interrupt-hook", "hd_hook_interrupt", {"idt_index": 46, "script": mk("INT")}, "ok")
    add("events", "ioin-hook", "hd_hook_ioin", {"port": 96, "script": mk("IOIN")}, "ok", note="VMI cannot break, so every event needs a script")
    add("events", "ioout-hook", "hd_hook_ioout", {"port": 128, "script": mk("IOOUT")}, "ok")
    add("events", "msrread-hook", "hd_hook_msrread", {"msr": 0xC0000082, "script": mk("MSRREAD")}, "ok")
    add("events", "msrwrite-hook", "hd_hook_msrwrite", {"msr": 0xC0000082, "script": mk("MSRWRITE")}, "ok")
    add("events", "syscall-hook", "hd_hook_syscall", {"script": mk("SYSCALL")}, "ok")
    add("events", "sysret-hook", "hd_hook_sysret", {"script": mk("SYSRET")}, "ok")
    add("events", "tsc-hook", "hd_hook_tsc", {"script": mk("TSC")}, "ok", note="also makes TPAUSE/UMWAIT exit")
    add("events", "pmc-hook", "hd_hook_pmc", {"script": mk("PMC")}, "ok")
    add("events", "dr-hook", "hd_hook_dr", {"script": mk("DR")}, "ok", note="0x3B from an IOCTL before the !dr fix")
    add("events", "crwrite-hook", "hd_hook_crwrite", {"cr": 0, "script": mk("CR")}, "ok")
    add("events", "xsetbv-hook", "hd_hook_xsetbv", {"xcr": 0, "script": mk("XSETBV")}, "ok")
    add("events", "vmcall-hook", "hd_hook_vmcall", {"script": mk("VMCALL")}, "ok")
    add("events", "cpuid-hook", "hd_hook_cpuid", {"eax": 0, "script": mk("CPUID")}, "ok")
    add("events", "preactivate", "hd_preactivate", {"feature": "mode"}, "ok", "activated")
    add("events", "mode-hook", "hd_hook_mode", {"mode": "user", "pid": 4, "script": mk("MODE")}, "ok")
    add("events", "prealloc", "hd_prealloc", {"kind": "epthook", "count": 8}, "ok", "allocated")
    add("events", "msr-read-trigger", "hd_msr_read", {"msr_id": "0xC0000082"}, "ok", note="an rdmsr of LSTAR for the msrread hook")
    add("events", "events-fire", "@fired", {"markers": ["SYSCALL", "SYSRET", "EXCEPTION", "TSC"], "also": ["EPT2", "MSRREAD", "CPUID", "CR"], "within": 20}, budget=30, note="also: reported, not required (rare on an idle machine)")
    add("events", "event-list-full", "hd_event_list", {}, match=r"(?=.*!epthook2)(?=.*!syscall)(?=.*!sysret)(?=.*!tsc)(?=.*!cpuid)(?=.*!dr)")
    add("events", "event-disable", "hd_event_disable", {"target": "all"}, "ok")
    add("events", "event-list-disabled", "hd_event_list", {}, match=r"^(?!.*\(enabled\)).*\(disabled\)")
    add("events", "event-enable", "hd_event_enable", {"target": "all"}, "ok")
    add("events", "event-sc", "hd_event_sc", {"state": "on"}, "error", "com port", note="needs a serial debuggee")
    add("events", "event-clear", "hd_event_clear", {"target": "all"}, "ok")
    add("events", "event-list-empty", "hd_event_list", {}, "ok", "no active/disabled events")
    add("events", "events-quiet", "@quiet", {"marker": "SYSCALL", "settle": 8, "window": 4}, budget=20, note="output arrives seconds late, so settle first")
    add("events", "transparent-on", "hd_transparent_enable", {"name": "notepad.exe"}, "ok", "enabled")
    add("events", "transparent-off", "hd_transparent_disable", {}, "ok", "disabled")
    add("events", "settings-set", "hd_settings", {"option": "syntax", "value": "intel"}, "ok")
    add("events", "flush", "hd_flush", {}, "ok")
    add("events", "io-in", "hd_io_in", {"port": 128, "width": "al"}, "ok", note="needs the kd module, which the VMM load installs")
    add("events", "io-out", "hd_io_out", {"port": 128, "value": 0, "width": "al"}, "ok", note="port 0x80 is the POST port")
    add("events", "mem-dump", "hd_mem_dump", {"from_address": QUERY_PC, "to_address": QUERY_PC + "+0x10", "path": DUMP_FILE}, "ok")
    add("events", "exec-command", "hd_exec_command", {"command": ".status"}, "ok", "vmi mode")
    add("events", "script-run", "hd_script_run", {"script": 'printf("hi\\n");'}, "error", "not connected to any debuggee", note="a script needs a halted context")
    add("events", "core-switch", "hd_core_switch", {"core": 0}, "error", note="no cores to switch in VMI mode")
    add("events", "process-list", "hd_process_switch", {"list_only": True}, match=r"Process Id: 0004\s+DirBase.*Image: System")
    add("events", "thread-list", "hd_thread_switch", {"list_only": True}, match=r"THREAD\s+[0-9a-f]{16} \([0-9a-f]+\.[0-9a-f]+\)")
    add("events", "user-thread-list", "hd_user_thread_switch", {}, "ok", "not initialized", note="no user debuggee yet")
    # The module ops last: hd_modules_unload_all takes the VMM down too.
    add("events", "modules-load", "hd_modules_load_all", {}, "ok", "All modules loaded", budget=60)
    add("events", "lbr-disable", "hd_lbr", {"action": "disable"}, "error", "already disabled", note="the trace module is loaded now; nothing turned LBR on")
    add("events", "lbr-dump", "hd_lbr_dump", {}, "error", "already disabled")
    add("events", "lbr-filter", "hd_lbr_filter", {"exclude": ["kernel", "user"]}, "error", "already disabled")
    add("events", "pt-control", "hd_pt_control", {"action": "disable"}, "ok")
    add("events", "pt-filter", "hd_pt_filter", {"modes": ["user"]}, "ok", "PT filter")
    add("events", "pt-packets", "hd_pt_packets", {"packets": ["psb", "tip"]}, match=r"PSB.*TIP")
    add("events", "pt-enable", "hd_pt_enable", {"buffer_size": 4096}, "ok", "PT enable")
    add("events", "modules-unload", "hd_modules_unload_all", {}, "ok", "unloaded", budget=60)
    add("events", "sym-reload-after-modules", "hd_sym_reload", {}, "ok", "updated successfully", note="the module ops drop the symbol tables", budget=120)

    # ----- writes ---------------------------------------------------------- #
    add("write", "mem-write-roundtrip", "hd_mem_write", {"address": QUERY_PC, "data_hex": "echo"}, "ok", note="reads 16 bytes of kernel code, writes them back with compare-and-write, reads them back")
    add("write", "mem-write-stale", "hd_mem_write", {"address": QUERY_PC, "data_hex": "90909090", "expected_current": "cccccccc"}, "error", "nothing written")
    add("write", "mem-edit-roundtrip", "hd_mem_edit", {"address": QUERY_PC, "value": "0x48", "fmt": "byte"}, "ok", note="the byte that is there")
    add("write", "mem-after-edit", "hd_mem_read", {"address": QUERY_PC, "size": 16}, "ok", QUERY_PC_BYTES)
    add("write", "reg-write", "hd_reg_write", {"name": "rip", "value": "0x140000000"}, "error", "not connected to any debuggee", note="needs a halted context")
    # MSR writes: every core is read, then written back with compare-and-write and
    # read again, so a wrong parse can only fail the case, never change a register.
    add("write", "msr-echo-lstar", "hd_msr_write", {"msr_id": "0xC0000082", "value": "echo"}, "ok", note="LSTAR on every core", dangerous=True, budget=60)
    add("write", "msr-echo-tsc-aux", "hd_msr_write", {"msr_id": "0xC0000103", "value": "echo"}, "ok", note="per-core TSC_AUX", dangerous=True, budget=60)
    add("write", "msr-echo-gs-base", "hd_msr_write", {"msr_id": "0xC0000101", "value": "echo"}, "ok", note="per-core GS base (the KPCR)", dangerous=True, budget=60)
    add("write", "msr-kernel-gs-refused", "hd_msr_write", {"msr_id": "0xC0000102", "value": "0x0", "core": 0}, "error", "context switch", note="the running thread's value: refused")
    add("write", "msr-echo-efer", "hd_msr_write", {"msr_id": "0xC0000080", "value": "echo"}, "ok", note="EFER on every core", dangerous=True, budget=60)
    add("write", "msr-echo-pat", "hd_msr_write", {"msr_id": "0x277", "value": "echo"}, "ok", note="PAT on every core", dangerous=True, budget=60)
    add("write", "msr-gs-all-cores", "hd_msr_write", {"msr_id": "0xC0000101", "value": "0x0"}, "error", "every core", note="refused before any write")
    add("write", "msr-stale", "hd_msr_write", {"msr_id": "0xC0000082", "value": "0x0", "core": 0, "expected_current": "0x1"}, "error", "nothing written", note="LSTAR=0 if the guard failed: refused")
    add("write", "pagein", "hd_pagein", {"address": QUERY_PC}, "error", "debugger mode")
    add("write", "bp-set", "hd_bp_set", {"address": "nt!NtClose"}, "error", "debugger mode")
    add("write", "bp-modify", "hd_bp_modify", {"breakpoint_id": 0, "action": "disable"}, "error", "debugger mode")
    add("write", "connect-local", "hd_connect", {"transport": "local"}, "ok", "already connected")

    # ----- user-mode debugger ---------------------------------------------- #
    def umd(case_id, tool, args=None, expect="ok", contains="", soak=False, **kw):
        add("umd", case_id, tool, args, expect, contains, soak=soak, **kw)

    umd("process-attach-system", "hd_process_attach", {"pid": 4}, "error", "32-bit or 64-bit", note="the System process has no user mode")
    umd("process-start", "hd_process_start", {"path": TEST_EXE}, "ok", "Started", budget=30)
    umd("umd-reg", "hd_reg_read", {"name": "rip"}, match=r"^0x7ff[0-9a-f]+$", soak=True)
    umd("umd-disasm", "hd_disasm", {"address": "@rip", "count": 3}, match=r"7ff[0-9a-f`]+", soak=True)
    umd("umd-mem", "hd_mem_read", {"address": "@rip", "size": 8}, match=r'"address": "0x7ff', soak=True)
    umd("umd-modules", "hd_list_modules", {}, "ok", "hdtest.exe", soak=True)
    umd("umd-regs", "hd_reg_read_all", {}, match=r'"rip": "0x7ff', soak=True)
    umd("umd-script", "hd_script_run", {"script": 'printf("%llx\\n", @rip);'}, match=r"7ff[0-9a-f]+", soak=True)
    # Register reads and scripts run in VMX root and complete the IOCTL from there:
    # this bugchecked (0x50, IopProcessBufferedIoCompletion) within a few dozen.
    umd("umd-reg-x60", "hd_reg_read", {"name": "rsp"}, match=r"^0x[0-9a-f]+$", repeat=60, budget=60)
    umd("umd-script-x30", "hd_script_run", {"script": 'printf("%llx\\n", @rsp);'}, match=r"[0-9a-f]+", repeat=30, budget=60)
    umd("umd-continue", "hd_exec_continue", {}, "ok", "Continued")
    umd("umd-pause", "hd_exec_pause", {}, "ok", "Paused")
    umd("umd-step", "hd_exec_step", {"mode": "over"}, "ok", "Stepped", budget=15)
    # A #DB exit advanced RIP by an undefined instruction length: the next step
    # resumed in the middle of an instruction (an access violation in hdtest).
    umd("umd-step-x10", "hd_exec_step", {"mode": "in"}, "ok", "Stepped", repeat=10, budget=30)
    umd("umd-step-rip", "hd_disasm", {"address": "@rip", "count": 1}, match=r"7ff[0-9a-f`]+\s+[0-9A-F]{2}( [0-9A-F]{2})*\s+\w", note="RIP is on an instruction boundary that disassembles")
    # A step over a call set its breakpoint on all cores with a DPC from VMX
    # root-mode: bugcheck 0x1AA (VMRESUME in non-root mode) on the first call.
    umd("umd-step-out", "hd_step_out", {"max_steps": 1}, "ok", budget=30, note="'gu' hung on its first step before the gu fix")
    umd("umd-pause-after-step", "hd_exec_pause", {}, "ok", "Paused", note="takes the session back if the step never halted")
    umd("umd-step-track", "hd_step_track", {}, "any", budget=15)
    umd("umd-restart", "hd_process_restart", {}, "any", budget=30)
    umd("umd-kill", "hd_process_kill", {}, "ok", budget=15)
    umd("umd-threads-gone", "hd_user_thread_switch", {}, "ok", "no active debugging threads", note="the kill left the process attached in the kernel")
    # .start / .kill / .start: the second process stayed unknown to the debugger
    # and the third start hung for good (an unkillable process).
    umd("process-start-2", "hd_process_start", {"path": TEST_EXE}, "ok", "Started", budget=30)
    # A step over a call from the entrypoint (mainCRTStartup: sub rsp / call
    # __security_init_cookie / add rsp): its breakpoint was lost at VM-exit
    # (DR7 = 400H), then, kept set, it broke again on the paused thread and the
    # debuggee got a single-step exception (KiUserExceptionDispatcher).
    umd("umd-continue-2", "hd_exec_continue", {}, "ok", "Continued", note="to the entrypoint breakpoint")
    umd("umd-pause-2", "hd_exec_pause", {}, "ok", "Paused", note="already paused there: not an error")
    umd("umd-step-to-call", "hd_exec_step", {"mode": "in"}, "ok", "Stepped", budget=15)
    umd("umd-step-over-call", "hd_exec_step", {"mode": "over"}, "ok", "Stepped", budget=15)
    umd("umd-step-over-call-rip", "hd_disasm", {"address": "@rip", "count": 1}, match=r"add rsp, 0x28", note="the instruction after the call")
    umd("umd-step-after-call", "hd_exec_step", {"mode": "over"}, "ok", "Stepped", repeat=3, budget=15)
    umd("umd-reg-2", "hd_reg_read", {"name": "rip"}, match=r"^0x7ff[0-9a-f]+$")
    umd("umd-kill-2", "hd_process_kill", {}, "ok", budget=15)
    umd("process-start-3", "hd_process_start", {"path": TEST_EXE}, "ok", "Started", budget=30)
    umd("umd-reg-3", "hd_reg_read", {"name": "rip"}, match=r"^0x7ff[0-9a-f]+$")
    umd("umd-detach", "hd_process_detach", {}, "any")
    umd("umd-kill-3", "hd_process_kill", {}, "any", budget=15)
    # Whatever detach and kill did, the debugger must be off the process now,
    # or every later symbol lookup runs in its (stale) context
    umd("umd-threads-gone-3", "hd_user_thread_switch", {}, "ok", "no active debugging threads")
    umd("umd-nt-symbol", "hd_mem_read", {"address": QUERY_PC, "size": 4}, "ok", "\"hex\"", note="c0000030 (invalid thread debugging token) when the detach did not take")

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

    # ----- regressions that need the machine (--machine) ------------------- #
    # A step in flight when the debuggee dies used to wait forever.
    add("regress", "dead-start", "hd_process_start", {"path": TEST_EXE}, "ok", "Started", budget=30)
    add("regress", "dead-kill-outside", "@machine", {"ps": "Stop-Process -Name hdtest -Force"})
    add("regress", "dead-step", "hd_exec_step", {"mode": "over"}, "error", budget=15, note="fails with the reason instead of hanging")
    add("regress", "dead-session-usable", "hd_status", {}, "ok", "vmi mode")
    add("regress", "dead-cleanup", "hd_process_kill", {}, "any", budget=15)
    # Unload/load cycles: the unload of a VMM that had events walked a list that
    # was never initialized (0x3B).
    for i in range(3):
        add("regress", f"cycle-hooks-{i}", "hd_hook_syscall", {"script": mk("CYCLE")}, "ok", dangerous=True)
        add("regress", f"cycle-unload-{i}", "hd_vmm_unload", {}, "ok", "unloaded", dangerous=True, budget=60)
        add("regress", f"cycle-load-{i}", "hd_vmm_load", {}, "ok", "connected", dangerous=True, budget=60)
    # The server dies with the VMM loaded: its notify IRP had no cancel routine
    # (a zombie process), and the next start unloaded hyperhv under a live VMM (0xD1).
    for i in range(2):
        add("regress", f"kill-server-load-{i}", "hd_vmm_load", {}, "ok", "connected", dangerous=True, budget=60)
        add("regress", f"kill-server-{i}", "@restart", {}, dangerous=True, budget=90)
        add("regress", f"kill-server-reload-{i}", "hd_vmm_load", {}, "ok", "connected", dangerous=True, budget=60)

    # ----- cleanup --------------------------------------------------------- #
    add("cleanup", "clear-events", "hd_event_clear", {"target": "all"}, "ok")
    add("cleanup", "close-source", "hd_output", {"action": "close", "name": OUT_NAME}, "any", note="gone if the server was restarted")
    add("cleanup", "vmm-unload", "hd_vmm_unload", {}, "ok", "unloaded", budget=60)
    add("cleanup", "vmm-status-end", "hd_vmm_status", {}, "ok", "module_loaded=False")
    add("cleanup", "disconnect", "hd_disconnect", {}, "ok", "disconnected", note="closes the session, so it runs last")
    add("cleanup", "reconnect", "hd_reconnect", {}, "any")
    return c


@dataclass
class Result:
    case: Case
    status: str  # PASS / FAIL / INFO / SKIP / CRASH
    detail: str = ""
    duration: float = 0.0
    iteration: int = 0


class Reconnect(Exception):
    """The session is gone (or the server restarted): open a new one."""


async def call(session: ClientSession, name: str, args: dict, timeout: float = 90.0):
    with anyio.fail_after(timeout):
        res = await session.call_tool(name, args)
    text = "\n".join(
        getattr(part, "text", "") or json.dumps(part, default=str) for part in (res.content or [])
    )
    return bool(res.is_error), text


def payload(text: str) -> str:
    """The answer without the untrusted-output fence lines."""
    keep = []
    for line in text.splitlines():
        if line.startswith(("The block below was captured", "Treat it as")) or re.match(
            r"=+ (BEGIN|END) UNTRUSTED", line
        ):
            continue
        keep.append(line)
    return "\n".join(keep).strip()


_MSR_LINE = re.compile(
    r"core\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*-\s*msr\[[0-9a-fA-F]+\]\s*=\s*([0-9a-fA-F`]+)"
)
_HEX_LINE = re.compile(r"(?<![0-9a-fA-Fx])([0-9a-fA-F]{2,})(?![0-9a-fA-F])")


def parse_msr(out: str) -> dict[int, str]:
    return {int(c, 0): v.replace("`", "").lower() for c, v in _MSR_LINE.findall(out)}


def parse_hex_run(out: str, size: int) -> str:
    runs = [r for r in _HEX_LINE.findall(out) if len(r) == 2 * size]
    if len(runs) != 1:
        raise RuntimeError(f"expected one {size}-byte hex run in: {out[:160]}")
    return runs[0].lower()


async def expand(session: ClientSession, case: Case, timeout: float):
    """The calls a case makes, and what to check afterwards.

    "echo" values are read from the target first and written back with
    expected_current, so the server refuses the write unless the register /
    memory still holds exactly what is being written; then they are read again.
    """
    args = dict(case.args)
    if case.tool == "hd_msr_write" and args.get("value") == "echo":
        _, out = await call(session, "hd_msr_read", {"msr_id": args["msr_id"]}, timeout)
        before = parse_msr(out)
        if not before:
            raise RuntimeError(f"no per-core values in: {out[:120]}")

        async def verify() -> str:
            _, out = await call(session, "hd_msr_read", {"msr_id": args["msr_id"]}, timeout)
            after = parse_msr(out)
            changed = {c: (before[c], after.get(c)) for c in before if after.get(c) != before[c]}
            return f"read back differs: {changed}" if changed else ""

        calls = [
            {
                "msr_id": args["msr_id"],
                "value": "0x" + v,
                "core": core,
                "expected_current": "0x" + v,
            }
            for core, v in sorted(before.items())
        ]
        return calls, verify
    if case.tool == "hd_mem_write" and args.get("data_hex") == "echo":
        size = 16
        _, out = await call(
            session, "hd_mem_read", {"address": args["address"], "size": size}, timeout
        )
        before = parse_hex_run(out, size)

        async def verify() -> str:
            _, out = await call(
                session, "hd_mem_read", {"address": args["address"], "size": size}, timeout
            )
            after = parse_hex_run(out, size)
            return f"read back {after}, wrote {before}" if after != before else ""

        return [{**args, "data_hex": before, "expected_current": before}], verify
    return [args] * case.repeat, None


class Machine:
    """PowerShell on the target, through a command that takes the script last."""

    def __init__(self, command: str | None):
        self.argv = [os.path.expanduser(a) for a in shlex.split(command)] if command else None

    async def ps(self, script: str, timeout: float = 90) -> tuple[bool, str]:
        if not self.argv:
            return False, "no --machine"
        try:
            with anyio.fail_after(timeout):
                res = await anyio.run_process([*self.argv, script], check=False)
        except TimeoutError:
            return False, "timed out"
        return res.returncode == 0, res.stdout.decode("utf-8", "replace") + res.stderr.decode(
            "utf-8", "replace"
        )

    async def boot_time(self) -> str | None:
        ok, out = await self.ps("(gcim Win32_OperatingSystem).LastBootUpTime.ToString('o')", 40)
        out = out.strip()
        return out if ok and re.match(r"\d{4}-", out) else None

    async def wait_up(self, seconds: float) -> str | None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            boot = await self.boot_time()
            if boot:
                return boot
            await anyio.sleep(10)
        return None

    async def bugcheck(self) -> str:
        """The bugcheck code and parameters Windows logged at the last boot."""
        script = (
            "$e = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'} "
            "-MaxEvents 1 -ErrorAction SilentlyContinue; if ($e) { $e.TimeCreated.ToString('o') + ' ' + $e.Message }"
        )
        for _ in range(6):  # the event is written once the dump is processed after boot
            _, out = await self.ps(script, 40)
            code = re.search(r"0x[0-9a-fA-F]{8} \([^)]*\)", out)
            if code:
                return f"{out.split()[0]} bugcheck {code.group(0)}"
            await anyio.sleep(15)
        return "no bugcheck logged (a reset, or the dump is still being written)"


@asynccontextmanager
async def open_session(cfg: dict, wait: float = 0):
    """A connected MCP session; retries for `wait` seconds (a restarting server)."""
    deadline = time.monotonic() + wait
    while True:
        entered = False
        try:
            http = httpx2.AsyncClient(headers=cfg.get("headers", {}), timeout=120.0)
            async with http, streamable_http_client(cfg["url"], http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    entered = True
                    yield session
                    return
        except Exception:
            if entered or time.monotonic() >= deadline:
                raise
            await anyio.sleep(3)


def flatten(exc: BaseException) -> list[BaseException]:
    """The leaf exceptions of an exception group (task groups wrap them)."""
    inner = getattr(exc, "exceptions", None)
    return [leaf for e in inner for leaf in flatten(e)] if inner else [exc]


class Runner:
    def __init__(self, args, cfg: dict, machine: Machine):
        self.args = args
        self.cfg = cfg
        self.machine = machine
        self.results: list[Result] = []
        self.transcript: list[str] = []  # every answer, for @fired / @quiet
        self.phase_mark = 0
        self.boot0: str | None = None
        self.tools: set[str] = set()
        self.covered: set[str] = set()
        self.crashed = False

    # ----- crash detection ------------------------------------------------- #
    async def check_machine(self, case: Case, iteration: int) -> bool:
        """False (and a CRASH result) if the target rebooted or went away."""
        if not self.machine.argv or self.boot0 is None or self.crashed:
            return not self.crashed
        boot = await self.machine.boot_time()
        if boot == self.boot0:
            return True
        print(
            f"\n  !!! the target {'did not answer' if boot is None else 'rebooted'} after {case.case_id}; waiting for it ..."
        )
        boot = boot or await self.machine.wait_up(self.args.reboot_wait)
        if boot is None:
            detail = "the target went away and did not come back"
        elif boot == self.boot0:
            return True  # it only missed a beat
        else:
            detail = f"rebooted (boot {boot}); " + await self.machine.bugcheck()
        self.results.append(Result(case, "CRASH", detail, iteration=iteration))
        self.crashed = True
        return False

    # ----- one case -------------------------------------------------------- #
    async def action(self, session: ClientSession, case: Case) -> tuple[bool, str]:
        """Run an @ action; (passed, detail)."""
        a = case.args
        if case.tool == "@fired":
            want = {"MK_" + m for m in a["markers"]}
            deadline = time.monotonic() + a["within"]
            while True:
                seen = set(re.findall(r"MK_\w+", "\n".join(self.transcript[self.phase_mark :])))
                missing = want - seen
                if not missing or time.monotonic() > deadline:
                    break
                _, text = await call(
                    session, "hd_exec_command", {"command": ".status"}, self.args.timeout
                )
                self.transcript.append(text)
                await anyio.sleep(0.5)
            also = sorted(m for m in a.get("also", ()) if "MK_" + m in seen)
            detail = ("missing " + ", ".join(sorted(missing))) if missing else "fired"
            return not missing, detail + (" (also " + ", ".join(also) + ")" if also else "")
        if case.tool == "@quiet":
            # A live hook prints on every poll; the kernel's last, partly filled
            # message buffer can still arrive once, so one poll with hits is not
            # a failure.
            marker = "MK_" + a["marker"]
            hits = polls = 0
            for until, counting in ((a["settle"], False), (a["window"], True)):
                end = time.monotonic() + until
                while time.monotonic() < end:
                    _, text = await call(
                        session, "hd_exec_command", {"command": ".status"}, self.args.timeout
                    )
                    if counting and marker in text:
                        hits += text.count(marker)
                        polls += 1
                    await anyio.sleep(0.5)
            detail = f"{marker} printed {hits} time(s) in {polls} poll(s) after the clear"
            return polls <= 1, detail if hits else "quiet"
        if case.tool == "@machine":
            ok, out = await self.machine.ps(a["ps"])
            return ok, payload(out)[:110]
        if case.tool == "@restart":
            ok, out = await self.machine.ps(SERVER_RESTART_PS)
            if not ok:
                return False, "restart failed: " + out[:100]
            raise Reconnect
        raise ValueError(case.tool)

    def skip_reason(self, case: Case) -> str:
        a = self.args
        if not case.tool.startswith("@") and case.tool not in self.tools:
            return "tool not registered"
        if (
            case.tool in ("@machine", "@restart") or case.phase == "regress"
        ) and not self.machine.argv:
            return "needs --machine"
        if a.only and a.only not in case.case_id:
            return "filtered"
        if case.dangerous and not a.dangerous:
            return "dangerous: pass --dangerous"
        return ""

    async def run_case(self, session: ClientSession, case: Case, iteration: int) -> None:
        a = self.args
        self.covered.add(case.tool)
        skip = self.skip_reason(case)
        if skip:
            self.results.append(Result(case, "SKIP", skip, iteration=iteration))
            return

        start = time.monotonic()
        if case.tool.startswith("@"):
            try:
                good, detail = await self.action(session, case)
            except Reconnect:
                self.results.append(
                    Result(case, "PASS", "server restarted", time.monotonic() - start, iteration)
                )
                raise
            self.results.append(
                Result(
                    case, "PASS" if good else "FAIL", detail, time.monotonic() - start, iteration
                )
            )
            return

        try:
            calls, verify = await expand(session, case, a.timeout)
        except Exception as exc:  # noqa: BLE001
            self.results.append(
                Result(case, "FAIL", f"echo read failed: {exc}", iteration=iteration)
            )
            return
        texts, errs, bad = [], [], []
        try:
            for call_args in calls:
                is_err, text = await call(session, case.tool, call_args, a.timeout)
                texts.append(text)
                errs.append(is_err)
                self.transcript.append(text)
                why = self.judge(case, is_err, text)
                if why:
                    bad.append(why)
            if verify and not bad:
                why = await verify()
                if why:
                    bad.append(why)
        except Exception as exc:  # noqa: BLE001 - report and continue
            self.results.append(
                Result(
                    case,
                    "FAIL",
                    f"{type(exc).__name__}: {exc}",
                    time.monotonic() - start,
                    iteration,
                )
            )
            if await self.check_machine(case, iteration):
                raise Reconnect from exc  # the machine is up: the session may not be
            return
        took = time.monotonic() - start
        if a.record:
            os.makedirs(a.record, exist_ok=True)
            # The shape tests/data/live fixtures have: the answers, replayable offline.
            with open(os.path.join(a.record, case.case_id + ".json"), "w", encoding="utf-8") as fh:
                json.dump(
                    {"case": case.case_id, "tool": case.tool, "answers": [{"is_error": e, "text": t} for e, t in zip(errs, texts, strict=True)]},
                    fh,
                    indent=1,
                )

        shown = payload(texts[-1]).replace("\n", " | ")[:110] if texts else ""
        if len(calls) > 1:
            shown = f"[{len(calls)} calls] " + shown
        if case.expect == "any":
            status, detail = "INFO", shown
        elif bad:
            status, detail = (
                "FAIL",
                (f"{len(bad)}/{len(calls)} bad: " if len(calls) > 1 else "") + bad[0],
            )
        elif took > case.budget:
            status, detail = "FAIL", f"over budget ({took:.1f}s > {case.budget:.0f}s): {shown}"
        else:
            status, detail = "PASS", shown
        self.results.append(Result(case, status, detail, took, iteration))
        if case.dangerous:
            await self.check_machine(case, iteration)

    @staticmethod
    def judge(case: Case, is_err: bool, text: str) -> str:
        """Why the answer is wrong, or "" if it is right."""
        if case.expect == "any":
            return ""
        body = payload(text)
        if case.expect == "ok" and is_err:
            return "ERR " + body.replace("\n", " | ")[:110]
        if case.expect == "error" and not is_err:
            return "expected an error, got: " + body.replace("\n", " | ")[:100]
        if case.contains and case.contains.lower() not in text.lower():
            return f"no {case.contains!r} in: " + body.replace("\n", " | ")[:100]
        if case.match and not re.search(case.match, body, re.S | re.I):
            return f"no match for /{case.match}/ in: " + body.replace("\n", " | ")[:100]
        return ""

    # ----- the run --------------------------------------------------------- #
    def schedule(self, all_cases: list[Case]) -> list[tuple[int, list[Case]]]:
        """(iteration, batch) in run order. A batch of soak cases runs concurrently."""
        out: list[tuple[int, list[Case]]] = []
        rng = random.Random(self.args.seed)
        for it in range(max(1, self.args.soak)):
            todo = [c for c in all_cases if it == 0 or c.phase != "cold"]
            i = 0
            while i < len(todo):
                if self.args.soak and todo[i].soak:
                    j = i
                    while j < len(todo) and todo[j].soak and todo[j].phase == todo[i].phase:
                        j += 1
                    block = todo[i:j]
                    rng.shuffle(block)
                    k = max(1, self.args.concurrency)
                    out.extend((it, block[n : n + k]) for n in range(0, len(block), k))
                    i = j
                else:
                    out.append((it, [todo[i]]))
                    i += 1
        return out

    async def setup_phase(self, session: ClientSession, phase: str) -> None:
        """VMM + symbols before every phase: an earlier phase may have unloaded
        the modules (hd_modules_unload_all takes the VMM down too)."""
        self.phase_mark = len(self.transcript)
        if phase == "cold":
            return
        for name, sargs in (
            ("hd_vmm_load", {}),
            ("hd_sym_path", {"path": SYM_PATH}),
            ("hd_sym_reload", {}),
        ):
            try:
                e, t = await call(session, name, sargs, self.args.timeout)
                print(f"  [setup] {name}: {'ERR' if e else 'ok'} {payload(t)[:70]}")
            except Exception as exc:  # noqa: BLE001
                print(f"  [setup] {name}: FAILED {exc}")

    async def run_plan(self, session: ClientSession, plan, pos: int, state: dict) -> None:
        _, text = await call(session, "hd_connection_status", {})
        connected = "connected=True" in text
        while pos < len(plan) and not self.crashed:
            it, batch = plan[pos]
            if batch[0].phase != state["phase"]:
                if state["phase"] is not None and not await self.check_machine(batch[0], it):
                    return
                state["phase"] = batch[0].phase
                await self.setup_phase(session, state["phase"])
                connected = connected or state["phase"] != "cold"
            pos += 1
            state["pos"] = pos
            if batch[0].phase == "cold" and connected:
                self.results.extend(
                    Result(c, "SKIP", "already connected", iteration=it) for c in batch
                )
                continue
            if len(batch) == 1:
                await self.run_case(session, batch[0], it)
            else:
                async with anyio.create_task_group() as tg:
                    for case in batch:
                        tg.start_soon(self.run_case, session, case, it)

    async def run(self, all_cases: list[Case]) -> None:
        plan = self.schedule(all_cases)
        if self.machine.argv:
            self.boot0 = await self.machine.boot_time()
            print(f"target boot: {self.boot0}")
        state = {"pos": 0, "phase": None}
        first = True
        while state["pos"] < len(plan) and not self.crashed:
            try:
                async with open_session(self.cfg, wait=0 if first else 120) as session:
                    if first:
                        self.tools = {t.name for t in (await session.list_tools()).tools}
                        print(f"server tools: {len(self.tools)}; cases: {len(all_cases)}\n")
                        first = False
                    await self.run_plan(session, plan, state["pos"], state)
            except Exception as exc:  # noqa: BLE001 - the session broke, or a case asked for a new one
                state["phase"] = None  # set up again: a restarted server has no VMM
                leaves = flatten(exc)
                if any(isinstance(e, Reconnect) for e in leaves):
                    print("  [session] reconnecting")
                    continue
                if first:
                    raise
                print(f"  [session] lost: {leaves[0]!r}")
                it, batch = plan[max(state["pos"] - 1, 0)]
                if not await self.check_machine(batch[0], it):
                    break


def compare(old_path: str, results: list[Result]) -> None:
    with open(old_path, encoding="utf-8") as fh:
        old = {(r["id"], r.get("iteration", 0)): r for r in json.load(fh)}
    new = {(r.case.case_id, r.iteration): r for r in results}
    bad = ("FAIL", "CRASH")
    lines = []
    for key, r in new.items():
        o = old.get(key)
        if o is None:
            lines.append(f"  new      {key[0]}: {r.status}")
        elif o["status"] not in bad and r.status in bad:
            lines.append(f"  REGRESS  {key[0]}: {o['status']} -> {r.status} {r.detail[:80]}")
        elif o["status"] in bad and r.status == "PASS":
            lines.append(f"  fixed    {key[0]}: {o['status']} -> PASS")
        elif (
            o.get("duration") and r.duration > 2 * o["duration"] and r.duration - o["duration"] > 1
        ):
            lines.append(f"  slower   {key[0]}: {o['duration']:.1f}s -> {r.duration:.1f}s")
    lines += [f"  gone     {k[0]}" for k in old if k not in new]
    print(f"\ncompared with {old_path}:")
    print("\n".join(sorted(lines)) if lines else "  no change")


async def main_async(args) -> int:
    cfg = {"url": args.url, "headers": {}}
    if args.config:
        with open(args.config, encoding="utf-8") as fh:
            cfg = json.load(fh)
    if args.token:
        cfg.setdefault("headers", {})["Authorization"] = "Bearer " + args.token

    all_cases = [c for c in cases() if not args.phase or c.phase in args.phase]
    runner = Runner(args, cfg, Machine(args.machine))
    await runner.run(all_cases)
    results = runner.results

    width = max((len(r.case.case_id) for r in results), default=10)
    for r in results:
        tag = r.case.case_id + (f"#{r.iteration}" if r.iteration else "")
        print(
            f"  [{r.status:5}] {tag:<{width + 4}} {r.case.tool:<22} {r.duration:5.1f}s {r.detail}"
        )
    if not args.phase and not args.only and not runner.crashed:
        missing = sorted(runner.tools - runner.covered)
        if missing:
            print("\nUNCOVERED tools (no case): " + ", ".join(missing))

    counts = {
        k: sum(1 for r in results if r.status == k)
        for k in ("PASS", "FAIL", "INFO", "SKIP", "CRASH")
    }
    print(
        f"\n==== {counts['PASS']} pass, {counts['FAIL']} fail, {counts['INFO']} info, {counts['SKIP']} skip, {counts['CRASH']} crash ===="
    )
    if args.compare:
        compare(args.compare, results)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(
                [
                    {
                        "id": r.case.case_id,
                        "iteration": r.iteration,
                        "phase": r.case.phase,
                        "tool": r.case.tool,
                        "args": r.case.args,
                        "expect": r.case.expect,
                        "contains": r.case.contains,
                        "match": r.case.match,
                        "status": r.status,
                        "detail": r.detail,
                        "duration": round(r.duration, 3),
                    }
                    for r in results
                ],
                fh,
                indent=1,
            )
        print(f"report: {args.report}")
    return 3 if counts["CRASH"] else 1 if counts["FAIL"] else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Live end-to-end cases for the MCP tool surface")
    ap.add_argument(
        "--config", default=None, help="JSON with url + headers (e.g. client/.http.json)"
    )
    ap.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    ap.add_argument("--token", default=None)
    ap.add_argument("--phase", action="append", help="run only this phase (repeatable)")
    ap.add_argument("--only", default=None, help="run only cases whose id contains this")
    ap.add_argument("--timeout", type=float, default=90.0, help="per-call timeout, seconds")
    ap.add_argument("--report", default=None, help="write a JSON report here")
    ap.add_argument(
        "--record", default=None, help="save every case's full answers in this directory"
    )
    ap.add_argument(
        "--compare", default=None, help="a previous --report: list regressions, fixes and slowdowns"
    )
    ap.add_argument(
        "--machine",
        default=None,
        help="command running a PowerShell script on the target, e.g. ~/git/hdtools/wps",
    )
    ap.add_argument(
        "--reboot-wait",
        type=float,
        default=600,
        help="how long to wait for a rebooting target, seconds",
    )
    ap.add_argument(
        "--soak",
        type=int,
        default=0,
        help="run the selected cases this many times, soak cases shuffled",
    )
    ap.add_argument("--concurrency", type=int, default=1, help="soak cases run this many at once")
    ap.add_argument(
        "--seed",
        type=int,
        default=None,
        help="shuffle seed (printed cases are reproducible with it)",
    )
    ap.add_argument(
        "--dangerous", action="store_true", help="also run the cases that can crash the machine"
    )
    args = ap.parse_args()
    if args.soak and args.seed is None:
        args.seed = random.randrange(1 << 30)
        print(f"soak seed: {args.seed}")
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
