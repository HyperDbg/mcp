"""
* @file session.py
* @author munraimix
* @brief Long-lived libhyperdbg session: connection + command output capture.
* @copyright This project is released under the GNU Public License v3.
*
* The crux (DESIGN §2): hyperdbg_u_run_command() returns only a status code;
* the textual output arrives via the registered text-message callback. We
* register one callback for the session lifetime, buffer everything it emits
* into a thread-safe queue, and drain that queue after each (synchronous)
* command call.
*
* Hardening (DESIGN §9):
*   - self._text_cb holds the CFUNCTYPE for the session lifetime. If it were
*     GC'd, HyperDbg would call a dangling pointer and crash.
*   - The callback fires from a HyperDbg-owned thread; ctypes gives it a
*     transient PyThreadState. We only touch a queue.Queue and swallow every
*     exception - anything escaping the callback corrupts that thread state.
"""

from __future__ import annotations

import logging
import queue
import sys
import threading
import time
from ctypes import (
    CDLL,
    POINTER,
    byref,
    c_ubyte,
    c_uint32,
    c_uint64,
    c_void_p,
    cast,
    create_string_buffer,
)

from . import ffi
from .errors import HyperDbgError, NotConnectedError, PreconditionError
from .safety import wrap_untrusted

_log = logging.getLogger(__name__)


def _is_error_status(status: int) -> bool:
    """True if a libhyperdbg run_command INT status denotes failure.

    Verified on hardware: run_command returns 0 on success (`.status` succeeds
    with a 0 return). Failures are NTSTATUS-style 0xC0000xxx codes
    (SDK ErrorCodes.h). The earlier assumption that success == 0xFFFFFFFF was
    wrong for run_command, so we only treat the explicit error range as failure.
    """
    return 0xC0000000 <= (status & 0xFFFFFFFF) <= 0xCFFFFFFF


# libhyperdbg installs its console CTRL+C handler on the first interpreter call
# (process-global, like the library itself); the console must not change after.
_interpreter_used = False


def _mark_interpreter_used() -> None:
    global _interpreter_used
    _interpreter_used = True


def _console_is_private(k32) -> bool:
    import ctypes

    pids = (ctypes.c_uint32 * 8)()
    return k32.GetConsoleProcessList(pids, 8) == 1


def _ensure_private_console() -> None:
    """Give this process a console of its own, hidden. Windows only; idempotent.

    Pausing a serial/pipe debuggee means raising CTRL+BREAK, and that reaches
    every process on the console (an MCP client's CREATE_NO_WINDOW console is
    shared with the venv launcher chain; a terminal with the shell). It must run
    BEFORE libhyperdbg installs its handler: AllocConsole drops every console
    handler registered earlier. stdio is piped under MCP, so leaving is harmless.
    """
    if sys.platform != "win32":
        return
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if _console_is_private(k32):
        return
    k32.FreeConsole()
    if k32.AllocConsole():
        hwnd = k32.GetConsoleWindow()
        if hwnd:
            ctypes.WinDLL("user32").ShowWindow(hwnd, 0)  # SW_HIDE


def _console_break() -> None:
    """Deliver CTRL+BREAK to this process only, so libhyperdbg's handler pauses the debuggee.

    libhyperdbg's handler returns TRUE for it, so Python never sees the signal.
    Refuses on a shared console rather than signal other processes.
    """
    if sys.platform != "win32":
        raise HyperDbgError("pausing a serial/pipe debuggee needs Windows console events")
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not _console_is_private(k32):
        raise HyperDbgError("cannot pause: this process shares its console with others")
    # CTRL+BREAK, not CTRL+C: a process can inherit "ignore CTRL+C" from its
    # parent, and libhyperdbg's handler treats both the same.
    if not k32.GenerateConsoleCtrlEvent(1, 0):  # CTRL_BREAK_EVENT to this console
        raise HyperDbgError(f"GenerateConsoleCtrlEvent failed (error {ctypes.get_last_error()})")


def _pipe_hint(named_pipe: str) -> str:
    """Why a named pipe can't be opened, in terms the caller can act on (Windows only).

    A VM serial port backed by a pipe (VMware/Hyper-V) has a single instance,
    so a second debugger gets ERROR_PIPE_BUSY instead of a connection.
    """
    if sys.platform != "win32":
        return ""
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    if k32.WaitNamedPipeW(named_pipe, 1):
        return ""  # an instance is free now: the failure was further along the handshake
    err = ctypes.get_last_error()
    if err in (2, 3, 161):  # FILE_NOT_FOUND, PATH_NOT_FOUND, BAD_PATHNAME
        return (
            r"pipe not found: check the name (\\.\pipe\<name>) and that the VM is running "
            "with a serial port backed by this pipe"
        )
    if err in (121, 231):  # SEM_TIMEOUT, PIPE_BUSY
        return (
            "pipe busy: another client already holds its only instance "
            "(hyperdbg-cli, WinDbg or another hyperdbg-mcp); disconnect it first"
        )
    return f"pipe unavailable (Windows error {err})"


class HyperDbgSession:
    """Owns the libhyperdbg handle and serializes access to it.

    libhyperdbg is process-global (a single kernel debug connection), so all
    command execution is guarded by a lock; this server targets one local
    session. Multi-session support is explicitly out of scope for v1
    (see DESIGN §11).
    """

    def __init__(self, dll: CDLL | None = None) -> None:
        self._dll = dll or ffi.load_libhyperdbg()
        self._output: queue.Queue[str] = queue.Queue()
        self._lock = threading.Lock()
        self._connected = False
        self._mode: str | None = None  # "local" | "remote"
        # Remote debuggee resumed: libhyperdbg's continue blocks until the next
        # halt, so it runs on this thread and the session refuses target calls.
        self._run_thread: threading.Thread | None = None
        # Persistent reference - MUST outlive every callback invocation.
        self._text_cb = ffi.TextMessageCallback(self._on_text)

    # ----- state ----------------------------------------------------------- #
    @property
    def is_connected(self) -> bool:
        """True while attached to a target (local VMI or a remote debuggee)."""
        return self._connected

    @property
    def mode(self) -> str | None:
        """'local', 'remote', or None when not attached."""
        return self._mode

    @property
    def is_running(self) -> bool:
        """True while a remote debuggee runs (resumed and not yet halted again)."""
        return self._run_thread is not None and self._run_thread.is_alive()

    # ----- lifecycle ------------------------------------------------------- #
    def connect(self) -> None:
        """Backward-compatible alias for connect_local()."""
        self.connect_local()

    def connect_local(self) -> None:
        """Local VMI mode (single machine; debug via the local hypervisor)."""
        self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
        self._dll.hyperdbg_u_connect_local_debugger()
        self._mode = "local"
        self._connected = True
        _log.info("connected to local HyperDbg debugger (VMI mode)")

    def connect_remote_com(
        self, port_name: str, baudrate: int = 115200, pause: bool = True
    ) -> None:
        """Debugger Mode over a serial/COM port to a remote debuggee.

        pause=True halts the debuggee on connect, giving a valid CPU context
        for register/memory reads and stepping.
        """
        self._prepare_remote()
        self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
        ok = self._dll.hyperdbg_u_connect_remote_debugger_using_com_port(
            port_name.encode("utf-8"), int(baudrate), 1 if pause else 0
        )
        if not ok:
            raise self._connect_error(f"failed to connect over COM port {port_name!r} @ {baudrate}")
        self._mode = "remote"
        self._connected = True
        _log.info("connected to remote HyperDbg debuggee over %s", port_name)

    def connect_remote_pipe(self, named_pipe: str, pause: bool = True) -> None:
        """Debugger Mode over a named pipe to a remote debuggee."""
        self._prepare_remote()
        self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
        self._drain()
        ok = self._dll.hyperdbg_u_connect_remote_debugger_using_named_pipe(
            named_pipe.encode("utf-8"), 1 if pause else 0
        )
        if not ok:
            raise self._connect_error(
                f"failed to connect over named pipe {named_pipe!r}", _pipe_hint(named_pipe)
            )
        self._mode = "remote"
        self._connected = True

    def connect_remote_net(self, ip: str, port: str) -> None:
        """Debugger Mode over TCP to a remote debuggee."""
        self._prepare_remote()
        self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
        ok = self._dll.hyperdbg_u_connect_remote_debugger(
            ip.encode("utf-8"), str(port).encode("utf-8")
        )
        if not ok:
            raise self._connect_error(f"failed to connect to remote debugger {ip}:{port}")
        self._mode = "remote"
        self._connected = True

    def _prepare_remote(self) -> None:
        """Before a Debugger-Mode connect: a private console, so pause can work."""
        # Only for the real library (fakes must not touch the test runner's
        # console), and only while libhyperdbg's CTRL+C handler is not yet
        # installed - swapping the console would drop it.
        if isinstance(self._dll, CDLL) and not _interpreter_used:
            _ensure_private_console()

    def _connect_error(self, message: str, hint: str = "") -> HyperDbgError:
        """Build a connect failure that carries HyperDbg's own explanation.

        libhyperdbg returns only FALSE; the reason is printed through the text
        callback. In Debugger Mode part of it may come from the debuggee, so it
        is fenced like any other untrusted output.
        """
        if hint:
            message += f": {hint}"
        output = self._drain_settled()
        if output.strip():
            message += "\n" + wrap_untrusted(output, "connect-output")
        return HyperDbgError(message)

    def close(self) -> None:
        """Graceful teardown. Idempotent.

        Root cause of the debuggee 'buffer exceeds the buffer limitation' flood
        (HyperDbg hyperkd SerialConnectionRecvBuffer): delimiter-only framing
        with no resync + a blind retry loop. If the debugger drops the link
        while the debuggee is paused mid-frame, the debuggee is stranded and
        floods. So for a remote session we (1) resume the debuggee off any
        mid-transaction state, then (2) send the proper disconnect - never just
        drop the port. Local VMI has no remote debuggee to strand.
        """
        if not self._connected and self._mode is None:
            return  # already closed
        mode = self._mode
        self._connected = False
        self._mode = None
        try:
            self._dll.hyperdbg_u_unset_text_message_callback()
        except Exception:  # pragma: no cover - best-effort; fake dlls lack it
            pass
        if mode == "local":
            self._release_local_modules()
        if mode == "remote":
            if not self.is_running:  # already resumed: a second continue is a no-op
                self._graceful_resume(timeout=2.0)
            self._run_thread = None
            try:
                self._dll.hyperdbg_u_debug_close_remote_debugger()
            except Exception:  # pragma: no cover - best-effort
                pass

    def _release_local_modules(self) -> None:
        """Best-effort unload of what a local session loaded, so the process can exit."""
        try:
            if self._dll.hyperdbg_u_is_any_module_loaded():
                self._dll.hyperdbg_u_unload_vmm()  # 1 if no VMM: fine
                self._dll.hyperdbg_u_unload_kd()
        except Exception:  # pragma: no cover - best-effort; fake dlls lack them
            pass

    def _graceful_resume(self, timeout: float) -> None:
        """Send continue so the debuggee isn't stranded, bounded by timeout.

        continue_debuggee can block awaiting the next debug event, so run it in
        a daemon thread and proceed to disconnect whether or not it returns.
        """
        def _cont() -> None:
            try:
                self._dll.hyperdbg_u_continue_debuggee()
            except Exception:  # pragma: no cover - best-effort
                pass

        t = threading.Thread(target=_cont, daemon=True)
        t.start()
        t.join(timeout)

    # ----- module / VMM lifecycle (pre-connect diagnostics are safe) ------- #
    def detect_vmx_support(self) -> bool:
        """True if the CPU supports VMX (safe; no hypervisor loaded)."""
        return bool(self._dll.hyperdbg_u_detect_vmx_support())

    def is_any_module_loaded(self) -> bool:
        """True if a HyperDbg module (e.g. the VMM) is already loaded."""
        return bool(self._dll.hyperdbg_u_is_any_module_loaded())

    def _module_op(self, what: str, *steps) -> None:
        """Run libhyperdbg module calls in order; each returns 0 on success, 1 on failure."""
        with self._lock:
            self._drain()
            for step in steps:
                rc = int(step())
                if rc != 0:
                    raise self._connect_error(f"{what} failed (rc={rc})")

    def load_vmm(self) -> None:
        """Load the HyperDbg hypervisor (VMM), installing the kd driver first.

        CONSEQUENTIAL: this places the running OS under HyperDbg's hypervisor
        and requires driver loading (DSE off / test-signing). Not called
        implicitly anywhere - the operator must invoke it deliberately. Mirrors
        the CLI's `load vmm`: hyperdbg_u_load_vmm alone fails without the driver.
        """
        self._module_op(
            "load vmm", self._dll.hyperdbg_u_install_kd_driver, self._dll.hyperdbg_u_load_vmm
        )

    def unload_vmm(self) -> None:
        """Unload the HyperDbg hypervisor (VMM) and the kd module, like the CLI's `unload vmm`.

        Unloading kd hands back the driver's pending IRPs; without it a
        libhyperdbg thread stays blocked in the driver and the process can't exit.
        """
        self._module_op(
            "unload vmm", self._dll.hyperdbg_u_unload_vmm, self._dll.hyperdbg_u_unload_kd
        )

    def load_all_modules(self) -> None:
        self._module_op(
            "load all modules",
            self._dll.hyperdbg_u_install_kd_driver,
            self._dll.hyperdbg_u_load_all_modules,
        )

    def unload_all_modules(self) -> None:
        self._module_op("unload all modules", self._dll.hyperdbg_u_unload_all_modules)

    # ----- Batch B: simple SDK-typed operations ---------------------------- #
    def get_processor_vendor(self) -> str:
        v = int(self._dll.hyperdbg_u_get_processor_vendor())
        return {0: "Intel", 1: "AMD"}.get(v, "Other")

    def get_kernel_base(self) -> int:
        self._require_connected()
        with self._lock:
            return int(self._dll.hyperdbg_u_get_kernel_base())

    def enable_transparent_mode(
        self, *, pid: int = 0, name: str = "", evade_mask: int = 0x1F
    ) -> None:
        self._require_connected()
        name_b = name.encode("utf-8") if name else None
        with self._lock:
            ok = self._dll.hyperdbg_u_enable_transparent_mode_ex(
                c_uint32(pid), name_b, c_ubyte(1 if pid else 0), c_uint32(evade_mask)
            )
        if not ok:
            raise HyperDbgError("enable_transparent_mode failed", status_code=ok)

    def disable_transparent_mode(self) -> None:
        self._require_connected()
        with self._lock:
            ok = self._dll.hyperdbg_u_disable_transparent_mode()
        if not ok:
            raise HyperDbgError("disable_transparent_mode failed", status_code=ok)

    def start_process(self, path: str, args: str = "") -> None:
        self._require_connected()
        with self._lock:
            if args:
                ok = self._dll.hyperdbg_u_start_process_with_args(path, args)
            else:
                ok = self._dll.hyperdbg_u_start_process(path)
        if not ok:
            raise HyperDbgError(f"start_process({path!r}) failed", status_code=ok)

    def step_out(self, last_instruction: bool = False) -> None:
        self._require_connected()
        with self._lock:
            self._dll.hyperdbg_u_stepping_step_over_for_gu(c_ubyte(1 if last_instruction else 0))

    def step_track(self) -> None:
        self._require_connected()
        with self._lock:
            self._dll.hyperdbg_u_stepping_instrumentation_step_in_for_tracking()

    # ----- Batch C: assembler ---------------------------------------------- #
    def assemble(self, code: str, address: int = 0) -> bytes:
        """Encode x86-64 assembly to machine-code bytes (two-step: length then fill)."""
        code_b = code.encode("utf-8")
        length = c_uint32(0)
        with self._lock:
            if not self._dll.hyperdbg_u_assemble_get_length(
                code_b, c_uint64(address), byref(length)
            ):
                raise HyperDbgError(f"assemble_get_length failed for {code!r}")
            n = length.value
            if n <= 0 or n > 0x1000:
                raise HyperDbgError(f"assembled length out of range: {n}")
            buf = create_string_buffer(n)
            if not self._dll.hyperdbg_u_assemble(code_b, c_uint64(address), cast(buf, c_void_p), n):
                raise HyperDbgError(f"assemble failed for {code!r}")
        return buf.raw[:n]

    # ----- Batch C: structured hardware reads ------------------------------ #
    def get_idt_entries(self) -> dict:
        self._require_connected()
        pkt = ffi.INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS()
        with self._lock:
            self._dll.hyperdbg_u_get_idt_entry(byref(pkt))
        return {"kernel_status": pkt.KernelStatus, "entries": list(pkt.IdtEntry)}

    def get_io_apic(self) -> dict:
        self._require_connected()
        pkt = ffi.IO_APIC_ENTRY_PACKETS()
        with self._lock:
            self._dll.hyperdbg_u_get_io_apic(byref(pkt))
        return {
            "base_pa": pkt.ApicBasePa,
            "base_va": pkt.ApicBaseVa,
            "id": pkt.IoIdReg,
            "entries": list(pkt.LlLhData),
        }

    def smi_count(self) -> int:
        self._require_connected()
        pkt = ffi.SMI_OPERATION_PACKETS()
        pkt.SmiOperationType = ffi.SMI_READ_COUNT
        with self._lock:
            self._dll.hyperdbg_u_perform_smi_operation(byref(pkt))
        return int(pkt.SmiCount)

    def _require_connected(self) -> None:
        if not self._connected:
            raise NotConnectedError("HyperDbg session is not connected")
        if self.is_running:
            # A halted context is required; a DLL call now would block behind
            # the running debuggee or act on stale state.
            raise PreconditionError(
                "debuggee is running: wait for a breakpoint/event to halt it, or hd_exec_pause"
            )

    # ----- callback -------------------------------------------------------- #
    def _on_text(self, text: bytes) -> int:
        # Runs on a HyperDbg-owned thread. Never raise; never do real work here.
        try:
            if text:
                self._output.put(text.decode("utf-8", errors="replace"))
        except Exception:  # pragma: no cover - defensive
            _log.exception("text-message callback failed")
        return 0

    def _drain(self) -> str:
        parts: list[str] = []
        while True:
            try:
                parts.append(self._output.get_nowait())
            except queue.Empty:
                break
        return "".join(parts)

    def _drain_settled(self, quiet_s: float = 0.02, max_s: float = 0.25) -> str:
        """Drain with a short quiescence window.

        The text callback fires from a HyperDbg-owned thread with no
        end-of-output barrier, so trailing output can land just after
        run_command returns. Best-effort: drain, wait, drain again until a
        wait yields nothing or we hit ``max_s``. The residual race is
        documented (DESIGN §11 / review M1); a proper fix needs an
        end-of-output sentinel from libhyperdbg.
        """
        deadline = time.monotonic() + max_s
        parts: list[str] = [self._drain()]
        while time.monotonic() < deadline:
            time.sleep(quiet_s)
            extra = self._drain()
            if not extra:
                break
            parts.append(extra)
        return "".join(parts)

    # ----- commands -------------------------------------------------------- #
    def run_command(self, command: str) -> str:
        """Run a HyperDbg CLI command and return its captured text output."""
        self._require_connected()
        with self._lock:
            self._drain()  # discard anything stale before we start
            _mark_interpreter_used()
            status = self._dll.hyperdbg_u_run_command(command.encode("utf-8"))
            output = self._drain_settled()
        if _is_error_status(status):
            # Debuggee output is attacker-controlled even on failure; fence it
            # so it can never reach the model as unmarked text (review H2).
            raise HyperDbgError(
                f"run_command({command!r}) failed (status=0x{status & 0xFFFFFFFF:08X}).\n"
                + wrap_untrusted(output, "command-output"),
                status_code=status,
            )
        return output

    def read_all_registers(self) -> dict[str, int]:
        self._require_connected()
        regs = ffi.GUEST_REGS()
        extra = ffi.GUEST_EXTRA_REGISTERS()
        with self._lock:
            self._dll.hyperdbg_u_read_all_registers(byref(regs), byref(extra))
        out = {name: getattr(regs, name) for name, _ in regs._fields_}
        out.update({name: getattr(extra, name) for name, _ in extra._fields_})
        return out

    def read_register(self, name: str) -> int:
        self._require_connected()
        reg_id = ffi.REGS_ENUM.get(name.lower())
        if reg_id is None:
            raise HyperDbgError(f"unknown register {name!r}")
        value = c_uint64()
        with self._lock:
            self._dll.hyperdbg_u_read_target_register(reg_id, byref(value))
        return value.value

    def write_register(self, name: str, value: int) -> None:
        self._require_connected()
        reg_id = ffi.REGS_ENUM.get(name.lower())
        if reg_id is None:
            raise HyperDbgError(f"unknown register {name!r}")
        with self._lock:
            self._dll.hyperdbg_u_write_target_register(reg_id, value)

    def read_memory(
        self,
        address: int,
        size: int,
        *,
        pid: int = 0,
        virtual: bool = True,
    ) -> bytes:
        self._require_connected()
        if size <= 0 or size > 0x1000000:  # 16 MiB boundary guard
            raise HyperDbgError(f"read size out of range: {size}")
        buf = create_string_buffer(size)
        ret_len = c_uint32(0)
        mem_type = ffi.ReadMemoryType.VIRTUAL if virtual else ffi.ReadMemoryType.PHYSICAL
        with self._lock:
            self._dll.hyperdbg_u_read_memory(
                c_uint64(address),
                mem_type,
                ffi.ReadingType.FROM_VMX_ROOT,
                c_uint32(pid),
                c_uint32(size),
                c_ubyte(0),  # get_address_mode = false
                None,  # address_mode out (unused)
                cast(buf, POINTER(c_ubyte)),
                byref(ret_len),
            )
        n = min(ret_len.value, size)
        return buf.raw[:n]

    def write_memory_bytes(
        self, address: int, data: bytes, *, pid: int = 0, virtual: bool = True
    ) -> None:
        self._require_connected()
        if not data:
            raise HyperDbgError("write payload is empty")
        buf = create_string_buffer(bytes(data), len(data))
        mem_type = ffi.EditMemoryType.VIRTUAL if virtual else ffi.EditMemoryType.PHYSICAL
        with self._lock:
            self._dll.hyperdbg_u_write_memory(
                c_void_p(address),
                mem_type,
                c_uint32(pid),
                cast(buf, c_void_p),
                c_uint32(len(data)),
            )

    def set_breakpoint(self, address: int, *, pid: int = 0, tid: int = 0, core: int = 0) -> None:
        self._require_connected()
        with self._lock:
            self._dll.hyperdbg_u_set_breakpoint(address, pid, tid, core)

    def continue_debuggee(self) -> bool:
        """Resume the debuggee. Returns True if it is still running afterwards.

        In Debugger Mode libhyperdbg's continue blocks until the debuggee halts
        again (breakpoint, event, pause) - like `g` in the CLI - so it runs on a
        daemon thread and this returns at once. Local VMI continue returns.
        """
        self._require_connected()
        if self._mode != "remote":
            with self._lock:
                self._dll.hyperdbg_u_continue_debuggee()
            return False
        t = threading.Thread(target=self._dll.hyperdbg_u_continue_debuggee, daemon=True)
        self._run_thread = t
        t.start()
        t.join(0.3)  # an immediate halt (e.g. a bp at the current rip) shows up here
        return t.is_alive()

    def pause_debuggee(self, timeout: float = 10.0) -> None:
        """Halt the debuggee and wait until libhyperdbg reports it halted."""
        if not self._connected:
            raise NotConnectedError("HyperDbg session is not connected")
        if self._mode != "remote" or not self.is_running:
            with self._lock:
                self._dll.hyperdbg_u_pause_debuggee()
            return
        # hyperdbg_u_pause_debuggee is a no-op over serial/pipe (it only handles
        # `.connect` and user-mode targets); the CLI pauses through its console
        # CTRL+C handler, which libhyperdbg also installs in this process.
        self._dll.hyperdbg_u_pause_debuggee()
        self._run_thread.join(0.5)
        if self.is_running:
            # An empty command makes libhyperdbg install its CTRL+C handler if no
            # command has run yet in this process (it does so on first use).
            _mark_interpreter_used()
            self._dll.hyperdbg_u_run_command(b"")
            _console_break()
            self._run_thread.join(timeout)
        if self.is_running:
            raise HyperDbgError(f"debuggee did not halt within {timeout:.0f}s")

    def step(self, mode: str = "over") -> None:
        self._require_connected()
        fn = {
            "over": self._dll.hyperdbg_u_stepping_step_over,
            "in": self._dll.hyperdbg_u_stepping_regular_step_in,
            "instr": self._dll.hyperdbg_u_stepping_instrumentation_step_in,
        }.get(mode)
        if fn is None:
            raise HyperDbgError(f"unknown step mode {mode!r} (use over|in|instr)")
        with self._lock:
            fn()

    def eval_expression(self, expr: str) -> int:
        self._require_connected()
        has_error = c_ubyte(0)
        with self._lock:
            value = self._dll.hyperdbg_u_eval_expression(expr.encode("utf-8"), byref(has_error))
        if has_error.value:
            raise HyperDbgError(f"eval_expression({expr!r}) reported an error")
        return value

    def run_script(self, script: str) -> None:
        self._require_connected()
        with self._lock:
            self._dll.hyperdbg_u_run_script(script.encode("utf-8"), c_ubyte(0))
