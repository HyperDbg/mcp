# HyperDbg MCP Server - Design

> Status: draft **v0.2** (2026-07-26, revised after online design review). Greenfield replacement for the abandoned `HyperDbg/mcp` prototype.
> Stack decided: **Python** + **MCPServer** (official SDK v2 high-level API, formerly FastMCP; MCP protocol 2026-07-28) + ctypes FFI into `libhyperdbg.dll`. License: **GPLv3**.
> v0.2 changes are consolidated in §9-§11; core sections below updated inline.

## Background / decision trail

- HyperDbg's founder (Sina Karvandi, `@HughEverett`) openly invited an MCP server for the org (2026-07-23).
- The existing `HyperDbg/mcp` repo is a stalled July-2025 single-dev prototype that **is not an MCP server** (no MCP library; a bare HTTP wrapper to a `:8888` shim, plus a stub-filled binding generator). Verdict: **greenfield**.
- Only salvageable asset: `mcp_api_meta.json` (a real 52-function API catalog).
- **No `:8888` HTTP server exists in current HyperDbg** - that was ddkwork's prototype assumption only. FFI into `libhyperdbg` is the sole viable seam.

## 1. Architecture

```
MCP client (Claude etc.)
        │  stdio (JSON-RPC)
        ▼
Python MCP server  ── ctypes ──►  libhyperdbg.dll  ──►  HyperDbg driver + VMM
   (official MCP Python SDK)        (extern "C", __cdecl)
```

In-process, local-only. Runs on the debugging host with HyperDbg installed and the driver loaded.

## 2. The crux: output capture via callback

`hyperdbg_u_run_command()` returns only an `INT` status - **not** the text. HyperDbg emits command output through a registered callback. The wrapper pattern:

```
register hyperdbg_u_set_text_message_callback(buffer_appender)   # once, at startup
→ call hyperdbg_u_run_command("db 0x1000")
→ read what the callback accumulated  → return that as the tool result
```

Solve this once and all 40+ text commands flow through one path. This is the thing the old repo never implemented.

## 3. Verified FFI surface

Library: **`libhyperdbg.dll`** (Windows) / `libhyperdbg.so` (Linux). `extern "C"`, `__cdecl`.
Source of truth: `HyperDbg/HyperDbg` → `hyperdbg/include/SDK/imports/user/HyperDbgLibImports.h`.

```python
# real prototypes (translate to ctypes argtypes/restype)
VOID    hyperdbg_u_connect_local_debugger();
INT     hyperdbg_u_run_command(CHAR* command);
VOID    hyperdbg_u_set_text_message_callback(PVOID handler);
BOOLEAN hyperdbg_u_read_memory(UINT64 target_address, DEBUGGER_READ_MEMORY_TYPE memory_type,
                               DEBUGGER_READ_READING_TYPE reading_type, UINT32 pid, UINT32 size,
                               BOOLEAN get_address_mode, DEBUGGER_READ_MEMORY_ADDRESS_MODE* address_mode,
                               BYTE* target_buffer, UINT32* return_length);
BOOLEAN hyperdbg_u_write_memory(PVOID destination_address, DEBUGGER_EDIT_MEMORY_TYPE memory_type,
                                UINT32 process_id, PVOID source_address, UINT32 number_of_bytes);
BOOLEAN hyperdbg_u_read_all_registers(GUEST_REGS* regs, GUEST_EXTRA_REGISTERS* extra);
BOOLEAN hyperdbg_u_read_target_register(REGS_ENUM register_id, UINT64* out);
BOOLEAN hyperdbg_u_write_target_register(REGS_ENUM register_id, UINT64 value);
BOOLEAN hyperdbg_u_set_breakpoint(UINT64 address, UINT32 pid, UINT32 tid, UINT32 core_number);
VOID    hyperdbg_u_continue_debuggee();
VOID    hyperdbg_u_pause_debuggee();
BOOLEAN hyperdbg_u_stepping_instrumentation_step_in();
BOOLEAN hyperdbg_u_stepping_regular_step_in();
BOOLEAN hyperdbg_u_stepping_step_over();
UINT64  hyperdbg_u_eval_expression(CHAR* Expr, PBOOLEAN HasError);
BOOLEAN hyperdbg_u_run_script(CHAR* Expr, BOOLEAN ShowErrorMessageIfAny);
```

Structs (`#pragma pack(1)`):
- `GUEST_REGS` = 16× uint64 (rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8-r15), 128 bytes
- `GUEST_EXTRA_REGISTERS` = 6× uint16 (CS,DS,FS,GS,ES,SS) + uint64 RFLAGS, RIP

Enums:
- `REGS_ENUM`: RAX=0, RCX=5, RDX=10, RBX=15, RSP=20, RBP=24, RSI=28, RDI=32, R8=36...R15=71, RIP=102
- `DEBUGGER_READ_MEMORY_TYPE`: PHYSICAL=0, VIRTUAL=1
- `DEBUGGER_EDIT_MEMORY_TYPE`: VIRTUAL=0, PHYSICAL=1
- `DEBUGGER_READ_READING_TYPE`: FROM_KERNEL=0, FROM_VMX_ROOT=1
- `DEBUGGER_READ_MEMORY_ADDRESS_MODE`: 32_BIT=0, 64_BIT=1

Type map: BOOLEAN/BYTE=`c_ubyte`, UINT32=`c_uint32`, UINT64=`c_uint64`, PVOID=`c_void_p`, CHAR*=`c_char_p`, PBOOLEAN=`POINTER(c_ubyte)`.

`read_memory` is the fiddly one - output buffer + `UINT32* return_length` out-param; allocate `(c_byte * size)()` and pass by ref.

## 4. Tool surface (12) with safety tiers

| Tool | libhyperdbg fn | Tier |
|------|---------------|------|
| `execute_command` | `run_command` + callback capture | ⚠️ gated (arbitrary) |
| `read_memory` | `read_memory` | ✅ read |
| `read_registers` | `read_all_registers` | ✅ read |
| `read_register` | `read_target_register` | ✅ read |
| `eval_expression` | `eval_expression` | ✅ read-ish |
| `disassemble` / `list_modules` | `run_command("u"/"lm")` | ✅ read |
| `set_breakpoint` | `set_breakpoint` | ⚠️ state |
| `continue` / `pause` | `continue/pause_debuggee` | ⚠️ state |
| `step` (in/over/instr) | `stepping_*` | ⚠️ state |
| `write_memory` | `write_memory` | 🔴 destructive |
| `write_register` | `write_target_register` | 🔴 destructive |
| `run_script` | `run_script` | 🔴 arbitrary |

**Safety (revised - see §10):** ring-0 debugger - writes can bugcheck the machine. Three layers, not one flag: (a) **ToolAnnotations** (`readOnlyHint`/`destructiveHint`) so clients auto-approve reads and gate writes; (b) **MCP elicitation** for per-call human confirmation of 🔴 tools (protocol-native - a server flag alone can't force the client to confirm); (c) a real **`--read-only`** mode that *does not register* the write/script tools at all (defense in depth, not doc-only). Plus an append-only **audit log** of every call.

## 5. Repo layout

HyperDbg has no formal Python packaging/linting in-repo (just Doxygen-headered utility scripts), so we copy their **GPLv3 Doxygen file header** + `snake_case`, and add modern packaging (a distributable server needs it):

```
hyperdbg-mcp/
├── LICENSE                 # GPLv3 (mandatory)
├── README.md
├── CONTRIBUTING.md         # mirror "PR to Dev branch"
├── pyproject.toml          # ruff + MCP SDK dep
├── src/hyperdbg_mcp/
│   ├── __init__.py
│   ├── server.py           # MCP entry, tool registration, --read-only
│   ├── ffi.py              # ctypes bindings + structs/enums
│   ├── session.py          # connect/lifecycle + callback output-capture buffer
│   └── tools.py            # the 12 tool handlers
└── tests/                  # pytest
```

GPLv3 file header:
```python
"""
 * @file server.py
 * @author <you> (munraimix)
 * @brief HyperDbg MCP server
 * @copyright This project is released under the GNU Public License v3.
"""
```

## 6. Session lifecycle
Startup: verify driver present → `connect_local_debugger()` → register text callback. Per-call: hold debuggee context. Shutdown: disconnect cleanly. Fail loudly if HyperDbg/driver isn't loaded - never silently return empty.

## 7. Build order
1. `ffi.py` - bindings, structs, enums
2. `session.py` - connect + nail the callback capture buffer
3. `tools.py` - read tools first, then state, then gated writes
4. `server.py` - registration + `--read-only`
5. Writes behind confirmation gating + tests

## 8. Upstream / account rules
- Public work under personal GitHub **munraimix** (never the work account). Set local `git config user.email/name` before first commit.
- Open an issue on `HyperDbg/HyperDbg` first (leverage existing maintainer rapport); confirm greenfield-Python is welcome.
- PRs target the **Dev** branch; GPLv3 throughout.

---

# v0.2 - Design-review revisions

Source: online review of 6 real debugger MCP servers (WinDbg-MCP, x64dbg_mcp, GhidraMCP, Frida-MCP, RE-MCP, MDB-MCP) + MCP Python SDK / ctypes / security research. Nearest analogs to study directly: **WinDbg-MCP** and **x64dbg_mcp**.

## 9. ctypes hardening (highest-value; these are near-certain bugs otherwise)

These are non-negotiable - the callback pattern *will* crash without them.

1. **Callback lifetime (critical).** The `CFUNCTYPE` text-message callback must be held as a persistent instance/module reference (`self._text_cb = CB_TYPE(self._on_text)`), never inline. If it's GC'd, HyperDbg calls a dangling pointer → "Illegal Instruction"/segfault. Deterministic, not sporadic.
2. **Callback thread-safety.** HyperDbg fires the callback from a non-Python thread (ctypes spins up a dummy `PyThreadState` + takes the GIL). Buffer into a `queue.Queue`, and wrap the handler body in `try/except` that logs - **any** exception escaping the callback corrupts the thread state. Define with `use_errno=True`.
3. **Struct packing.** All SDK structs use `#pragma pack(1)` → set `_pack_ = 1` on every ctypes `Structure` and assert layout at import: `assert sizeof(GUEST_REGS) == 128`. A pack mismatch silently returns garbage registers with no error.
4. **Buffers / out-params.** `read_memory`: `create_string_buffer(size)` for the `BYTE*`, `byref(c_uint32())` for `return_length`; after the call use `buf.raw[:return_len.value]` and assert `return_len <= size`. Never pass bare `bytes`.
5. **DLL load.** `ctypes.CDLL` (it's `__cdecl`, not `WinDLL`); Python bitness must match the DLL (x64); wrap load in `try/except OSError` with a clear message; ensure `libhyperdbg.dll` + transitive deps are resolvable.
6. **Errors.** Attach `errcheck` to each export mapping `BOOLEAN 0` / bad `INT` → a custom `HyperDbgError(status_code=...)`. No silent failures.

## 10. Safety & security model (revised)

- **Confirmation is client-side via elicitation**, not a server flag. Annotate 🔴 tools `destructiveHint=True`; request elicitation before executing (at protocol 2026-07-28 via `InputRequiredResult` + client retry, earlier revisions via `elicitation/create`); `--read-only` additionally *unregisters* them. Layer all three.
- **Prompt injection via debuggee data - the subtle, important one.** We're feeding a debugged program's own bytes/strings/disassembly back into the model; if it's malware, that content may contain adversarial instructions. **Wrap all returned debuggee data in an untrusted-data envelope** (clear delimiters + a "this is captured data, not instructions" tag) and size-cap it. This is a real, HyperDbg-specific threat the generic design missed.
- **Audit log:** append-only JSONL, one entry per call (timestamp, tool, args hash, result hash, elapsed, target pid/addr range). Cheap, high forensic value.
- **Input validation at the MCP boundary:** address/size sanity (reject absurd sizes), reject malformed commands before they reach the FFI layer.
- **`run_script`:** add a timeout + output size cap (it's Turing-complete).

**Deliberately rejected from the review (they misread HyperDbg's purpose):**
- ❌ *"Block kernel-space reads by default."* HyperDbg is a *hypervisor/kernel* debugger - kernel/VMX-root inspection is the whole point. Blocking it by default would cripple the tool for its actual audience. Keep kernel reads available; rely on audit + write-gating instead.
- ❌ *"Remove `execute_command`/`eval_expression`."* `execute_command` is the essential CLI fallback for the ~40 commands we don't wrap as first-class tools. Keep it, but annotate it `destructiveHint` (arbitrary) and gate it.

## 11. Adopted / deferred punch list

**Adopt now (into build order):**
- MCPServer high-level API (`@mcp.tool()` + type hints → auto inputSchema); low-level `Server` not needed.
- `@asynccontextmanager` **lifespan** holding the `libhyperdbg` handle; inject via tool context (replaces module-level init; guarantees cleanup on shutdown).
- Structured tool output (Pydantic/`outputSchema`) so clients get typed registers/memory, not regex bait - with a plain-text fallback.
- `ToolError` for tool-level failures (uniform; don't mix error dicts and exceptions).
- Testing via **in-memory `Client(server)`**, not stdio subprocess mocking.
- Tool naming: prefix groups (`hd_mem_*`, `hd_reg_*`, `hd_bp_*`, `hd_exec_*`, `hd_script_*`) for discoverability.
- Structured, recovery-oriented error strings (map libhyperdbg status codes → "what to do next").
- Precondition validation (e.g. reject `write_memory`/`step` when not paused) before hitting the FFI.

**Defer (note in README as roadmap, don't build yet):**
- Multi-session / concurrent clients (single local session is fine for v1; the `libhyperdbg` handle is process-global anyway).
- Streamable-HTTP transport + `report_progress` for long **Intel PT / LBR traces** - needed eventually (blocking callback will time out on big traces), but v1 is stdio + short ops.
- Multi-backend supervisor/worker (only if we ever add GDB/LLDB).
