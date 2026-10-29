# hyperdbg-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes [HyperDbg](https://hyperdbg.org)
- the hypervisor-assisted, ring-0 debugger - to LLM agents.

> **Status:** early development (v0.0.1). The design is documented in
> [`docs/DESIGN.md`](docs/DESIGN.md). End-to-end operation requires a Windows host with
> HyperDbg installed and its driver loaded. The FFI layer is validated against a live
> `libhyperdbg.dll` from HyperDbg v0.25.0 (local VMI mode: VMM load/unload, symbols, memory
> reads, disassembly), and `tests/test_ffi_signatures.py` checks every ctypes prototype
> against that release's SDK header.

## How it works

The server loads `libhyperdbg.dll` via `ctypes` (there is no HTTP API) and registers a set
of MCP tools that map to HyperDbg's command surface. Command text output is captured through
HyperDbg's message callback (see [`docs/DESIGN.md`](docs/DESIGN.md) §2).

```
MCP client ──stdio / Streamable HTTP──► hyperdbg-mcp (Python) ──ctypes──► libhyperdbg.dll ──► driver + VMM
```

## Transports

The server runs on the Windows host next to the driver; the MCP client can live elsewhere.

**stdio** (default) - one server per client process; the debugger session ends with it.
From another machine, bridge it over SSH (`-T`: no TTY, so the JSON-RPC stream stays clean):

```yaml
command: ssh
args: ["-T", "-o", "BatchMode=yes", "user@windows-host",
       "C:\\hyperdbg-mcp\\.venv\\Scripts\\hyperdbg-mcp.exe --lib-path C:\\HyperDbg\\libhyperdbg.dll"]
```

**Streamable HTTP** (`--transport http`) - one long-lived server at `/mcp` whose debugger
session (loaded VMM, symbols, a halted debuggee) outlives client restarts and reconnects.
It always requires a bearer token in `$HYPERDBG_MCP_TOKEN` (32+ characters; requests without
it get 401) and binds `127.0.0.1:8765` by default. Reach it from another machine through an
SSH tunnel rather than binding a LAN address:

```powershell
# Windows host, as Administrator: token file readable by Administrators only
scripts\windows\start-http.ps1 -TokenFile C:\ProgramData\hyperdbg-mcp\token `
    --lib-path C:\HyperDbg\libhyperdbg.dll --audit-log C:\ProgramData\hyperdbg-mcp\audit.jsonl
```

```bash
# client machine
ssh -N -L 8765:127.0.0.1:8765 user@windows-host
# MCP client: url http://127.0.0.1:8765/mcp, header "Authorization: Bearer <token>"
```

Start it from a scheduled task (or another service host) rather than an SSH session:
Windows' sshd ends every process of a session when the session closes.

## Safety

HyperDbg operates at ring-0; a bad write can bugcheck the host, and **memory/disassembly read
back from the target may be adversarial (you may be debugging malware)**. The server therefore:

- annotates read-only vs destructive tools (`ToolAnnotations`);
- requires per-call **confirmation** (MCP elicitation) for destructive tools;
- fails such calls **closed** when the client advertises no elicitation - use
  **`--assume-consent`** to pre-approve them for such clients;
- supports a hard **`--read-only`** mode that does not register write/script tools at all;
- wraps all debuggee-sourced data in an **untrusted-data envelope** so it is treated as inert;
- writes an **append-only audit log** of every call.

```bash
# read-only, safest
hyperdbg-mcp --read-only

# full access (destructive tools gated behind confirmation)
hyperdbg-mcp --lib-path C:\path\to\libhyperdbg.dll --audit-log audit.jsonl

# full access for a client without elicitation support (confirmation is skipped)
hyperdbg-mcp --lib-path C:\path\to\libhyperdbg.dll --assume-consent

# mock backend - exercise the full tool surface with no HyperDbg / DLL
hyperdbg-mcp --mock

# Debugger Mode - connect to a remote debuggee over serial (halts it on connect)
hyperdbg-mcp --remote-com com4 --baudrate 115200
```

**Modes.** Default is **local VMI** (single machine, debug via the local hypervisor).
**Debugger Mode** (`--remote-com` / `--remote-pipe` / `--remote-net`) connects to a separate
debuggee machine and, by default, halts it on connect - which is what gives a valid CPU context
for register/memory reads and stepping. (Register reads are not meaningful in local VMI mode
with nothing paused.)

## Tools

**Read (always available):** `hd_mem_read`, `hd_reg_read_all`, `hd_reg_read`, `hd_eval`,
`hd_disasm`, `hd_list_modules`, `hd_status`.
**Execution control (available in `--read-only`):** `hd_exec_continue`, `hd_exec_pause`,
`hd_exec_step`.
**Target-mutating (full mode only, confirmation-gated):** `hd_exec_command`, `hd_bp_set`,
`hd_mem_write`, `hd_reg_write`, `hd_script_run`.

The domain modules (`tools_<domain>.py`) bring it to 92 tools (43 under `--read-only`): memory (incl. `dps/dqs` symbolized
dumps, `.pagein`), symbols, paging, cores (`~`), process/thread switching and user-mode
`.attach/.detach/.kill/.restart`, every event type (`!epthook` ... `!mode`, `!trace`,
`!crwrite`, `!xsetbv`) with `pid/core/stage/sc/script` options, `prealloc/preactivate`,
APIC/IDT/SMI, and `.pe`. Free-text arguments must be a single token and event scripts
are checked against HyperDbg's `{}` tokenizer, so a value can't smuggle in extra options;
confirmations show the exact command that will run.

Address arguments take hex/decimal or a symbol with optional offsets
(`nt!KdDebuggerEnabled`, `nt!PsLoadedModuleList+0x8`, `@rip-10`), resolved through
HyperDbg's symbols (load them with `hd_sym_path` + `hd_sym_reload`). Nothing else is
passed to the script engine, so read-only tools stay read-only.

Confirmation uses MCP elicitation. At protocol 2026-07-28 it rides `InputRequiredResult`
(the client retries the call with the answer); older revisions use `elicitation/create`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Roadmap

- Validate Debugger Mode (serial / pipe / net) end-to-end against v0.25.0.
- Progress streaming for long Intel-PT / LBR traces.
- Symbol-aware helpers; richer structured outputs.

## License

GPL-3.0-or-later, matching the HyperDbg project.
