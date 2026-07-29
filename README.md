# hyperdbg-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes [HyperDbg](https://hyperdbg.org)
- the hypervisor-assisted, ring-0 debugger - to LLM agents.

> **Status:** early development (v0.0.1). The design is documented in
> [`docs/DESIGN.md`](docs/DESIGN.md). End-to-end operation requires a Windows host with
> HyperDbg installed and its driver loaded; the FFI layer has not yet been validated
> against a live `libhyperdbg.dll`.

## How it works

The server loads `libhyperdbg.dll` via `ctypes` (there is no HTTP API) and registers a set
of MCP tools that map to HyperDbg's command surface. Command text output is captured through
HyperDbg's message callback (see [`docs/DESIGN.md`](docs/DESIGN.md) §2).

```
MCP client ──stdio──► hyperdbg-mcp (Python) ──ctypes──► libhyperdbg.dll ──► driver + VMM
```

## Safety

HyperDbg operates at ring-0; a bad write can bugcheck the host, and **memory/disassembly read
back from the target may be adversarial (you may be debugging malware)**. The server therefore:

- annotates read-only vs destructive tools (`ToolAnnotations`);
- requires per-call **confirmation** (MCP elicitation) for destructive tools;
- supports a hard **`--read-only`** mode that does not register write/script tools at all;
- wraps all debuggee-sourced data in an **untrusted-data envelope** so it is treated as inert;
- writes an **append-only audit log** of every call.

```bash
# read-only, safest
hyperdbg-mcp --read-only

# full access (destructive tools gated behind confirmation)
hyperdbg-mcp --lib-path C:\path\to\libhyperdbg.dll --audit-log audit.jsonl

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

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Roadmap

- Validate FFI against a live HyperDbg host.
- Streamable-HTTP transport + progress streaming for long Intel-PT / LBR traces.
- Symbol-aware helpers; richer structured outputs.

## License

GPL-3.0-or-later, matching the HyperDbg project.
