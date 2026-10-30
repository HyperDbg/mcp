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
import os
import queue
import sys
import threading
import time
from contextlib import contextmanager
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
    string_at,
)

from . import ffi
from .errors import HyperDbgError, NotConnectedError, PreconditionError
from .safety import wrap_untrusted
from .script import format_parse_error, needs_target_context

_log = logging.getLogger(__name__)

# libhyperdbg's message when the previous hyperkd service is still marked for
# deletion (see HyperDbgSession._install_kd_driver).
_DRIVER_PENDING_DELETE = "not fully deleted"


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


#: How long a tool waits for another command before it reports the session busy.
_OPS_TIMEOUT_S = 60.0

# Transparent-mode (!hide) evade techniques. The syscall hook puts an EPT hook
# on the one global syscall entry (KiSystemCall64); in local VMI mode a core
# then spins in the hypervisor on the next syscalls and the machine bugchecks
# (0x101 CLOCK_WATCHDOG_TIMEOUT), so we leave it out of the default and refuse
# it below. The other four techniques are stable.
_TRANSPARENT_EVADE_SYSCALL_HOOK = 0x01
_TRANSPARENT_EVADE_MASK_SAFE = 0x1E


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


def _wait_for_pipe(named_pipe: str, timeout: float = 3.0) -> None:
    """Wait for a VM to re-create its pipe instance after a client closed it.

    For ~0.2 s the pipe does not exist at all, and WaitNamedPipe returns at once
    for a missing pipe instead of waiting, so poll it.
    """
    if sys.platform != "win32":
        return
    import ctypes

    k32 = ctypes.WinDLL("kernel32")
    k32.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    deadline = time.monotonic() + timeout
    while not k32.WaitNamedPipeW(named_pipe, 50) and time.monotonic() < deadline:
        time.sleep(0.05)


# Printed asynchronously by libhyperdbg's event forwarding (forwarding.cpp) when
# an event's output source fails, e.g. a closed `output` file; it lands in the
# output of whatever command runs at that time and says nothing about it.
_ASYNC_ERRORS = ("err, there was an error transferring the message to the remote sources",)


# libhyperdbg's ASSERT_MESSAGE_* (header/common/common.h): a command that needs
# a module which is not loaded prints one of these and does nothing.
_FAILURE_PREFIXES = (
    "incorrect use of",
    "err,",
    "please specify",
    "please choose",
    "please enter",
    "couldn't resolve",
    "unknown parameter",
    "unable to attach",
    "handle of the driver not found",
    "the kd (kernel debugger) module is not loaded",
    "the vmm (virtualization) module is not loaded",
    "the trace (hypertrace) module is not loaded",
)

# HyperDbg also refuses by *explaining* that it did nothing while returning
# success ("the .pagein command can be used ONLY in the debugger mode").
_FAILURE_MARKERS = (
    "can be used only in the debugger mode",
    "is not yet supported in vmi mode",
)


def _reports_failure(output: str) -> bool:
    """HyperDbg commands return success and print why they did nothing.

    Their first line is then `incorrect use of the '<cmd>'` (followed by the
    help text), `err, ...` or that a needed module is not loaded. Only the
    first line counts: some commands print a non-fatal `err,` between valid
    results (`!pcitree` without pci.ids). A progress line ("Attaching to
    process 0x4 (4)...") comes before the verdict and is skipped.
    """
    lines = (line.strip() for line in output.splitlines())
    first = next(
        (ln for ln in lines if ln and not ln.startswith(_ASYNC_ERRORS) and not ln.endswith("...")),
        "",
    )
    if first.startswith(_FAILURE_PREFIXES):
        return True
    low = first.lower()
    return any(marker in low for marker in _FAILURE_MARKERS)


_FAILURE_HINTS = (
    (
        "demand paging",
        "HyperDbg could not translate that address in the page tables it checks: a "
        "user-mode address that is not resident (or belongs to another process while "
        "VMI mode looks at the caller) fails this way. Let the debuggee run that code "
        "once and retry, or hook the kernel-side function (nt!...) instead; '.pagein' "
        "exists only in Debugger Mode.",
    ),
    (
        "only valid if you connected to a debuggee in debugger-mode",
        "This command needs Debugger Mode (serial/pipe/net). Set the same event with "
        "the VMI-mode equivalents: hd_hook_ept2 instead of hd_bp_set, hd_hook_monitor, ...",
    ),
    (
        "breaking to the debugger is not possible",
        "In VMI mode an event must carry a script: HyperDbg's default action is to break "
        "into the debugger, which VMI cannot do. Pass script: 'printf(\"hit\\n\");' (or "
        "use Debugger Mode).",
    ),
    (
        "not yet supported in vmi mode",
        "This part of HyperDbg is Debugger-Mode only; nothing in VMI mode can do it.",
    ),
)


def _failure_hint(output: str) -> str:
    """Turn the usual HyperDbg dead ends into what to do instead."""
    low = output.lower()
    if "exclude it from this release" in low:
        return (
            "This libhyperdbg was built with the user-mode debugger disabled "
            "(ActivateUserModeDebugger FALSE): .start/.attach do nothing. Rebuild "
            "HyperDbg with include/config/Configuration.h: ActivateUserModeDebugger TRUE, "
            "or use Debugger Mode."
        )
    for marker, hint in _FAILURE_HINTS:
        if marker in low:
            return hint
    return ""


class HyperDbgSession:
    """Owns the libhyperdbg handle and serializes access to it.

    libhyperdbg is process-global (a single kernel debug connection), so all
    command execution is guarded by a lock; this server targets one local
    session. Multi-session support is explicitly out of scope for v1
    (see DESIGN §11).
    """

    # How long load_vmm waits for a previous hyperkd service to finish deleting.
    driver_reinstall_timeout = 15.0

    def __init__(self, dll: CDLL | None = None) -> None:
        self._dll = dll or ffi.load_libhyperdbg()
        self._output: queue.Queue[str] = queue.Queue()
        self._lock = threading.Lock()
        self._connected = False
        self._mode: str | None = None  # "local" | "remote"
        # Remote debuggee resumed: libhyperdbg's continue blocks until the next
        # halt, so it runs on this thread and the session refuses target calls.
        self._run_thread: threading.Thread | None = None
        # Debugger-Mode connect still waiting for the debuggee's handshake.
        self._connect_thread: threading.Thread | None = None
        self._connect_failure: BaseException | None = None
        self._reattached = False  # last connect took over a debuggee instead of a handshake
        # Symbol path to re-apply after a VMM (re)load; set by hd_sym_path.
        self.symbol_path: str = ""
        # Persistent reference - MUST outlive every callback invocation.
        self._text_cb = ffi.TextMessageCallback(self._on_text)
        self._script_engine: CDLL | None | bool = False  # False = not looked up yet

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
        # Before the first command (libhyperdbg installs its CTRL+C handler on
        # first use, and swapping the console would drop it): pausing a stepping
        # user-mode thread needs a console to raise CTRL+BREAK on, see
        # pause_debuggee.
        if isinstance(self._dll, CDLL) and not _interpreter_used:
            _ensure_private_console()
        self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
        self._dll.hyperdbg_u_connect_local_debugger()
        self._mode = "local"
        self._connected = True
        _log.info("connected to local HyperDbg debugger (VMI mode)")

    def connect_remote_com(
        self,
        port_name: str,
        baudrate: int = 115200,
        pause: bool = True,
        wait: float | None = None,
        reattach: str = "auto",
    ) -> bool:
        """Debugger Mode over a serial/COM port to a remote debuggee.

        pause=True leaves the debuggee halted on connect, giving a valid CPU
        context for register/memory reads and stepping. See _connect_debugger_mode
        for `wait` and the return value, connect_remote_pipe for `reattach`.
        """
        port, baud = port_name.encode("utf-8"), int(baudrate)
        reattach_fn = getattr(self._dll, "hyperdbg_u_reattach_remote_debugger_using_com_port", None)
        return self._connect_debugger_mode(
            self._reattach_or_handshake(
                lambda: reattach_fn(port, baud, 1),
                lambda: self._dll.hyperdbg_u_connect_remote_debugger_using_com_port(port, baud, 1),
                use_reattach=reattach_fn is not None and reattach != "never",
            ),
            pause,
            wait,
            f"failed to connect over COM port {port_name!r} @ {baudrate}",
        )

    def connect_remote_pipe(
        self,
        named_pipe: str,
        pause: bool = True,
        wait: float | None = None,
        reattach: str = "auto",
    ) -> bool:
        """Debugger Mode over a named pipe to a remote debuggee (e.g. a VM serial port).

        reattach (needs a libhyperdbg with `.debug remote ... reattach`): a
        debuggee sends its handshake once per `.debug prepare`, so after its
        debugger died (e.g. this server was restarted) only a takeover reaches it.
        libhyperdbg's reattach takes a debuggee over or, if it is still waiting
        for a debugger, finishes the handshake, telling the two apart from what
        the debuggee sends - without closing the pipe, which would end a waiting
        debuggee's `.debug prepare`. "auto"/"always" use it when the library
        has it, then fall back to a plain handshake; "never" skips it.
        """
        name = named_pipe.encode("utf-8")
        reattach_fn = getattr(
            self._dll, "hyperdbg_u_reattach_remote_debugger_using_named_pipe", None
        )

        return self._connect_debugger_mode(
            self._reattach_or_handshake(
                lambda: reattach_fn(name, 1),
                lambda: self._dll.hyperdbg_u_connect_remote_debugger_using_named_pipe(name, 1),
                use_reattach=reattach_fn is not None and reattach != "never",
                after_failed_reattach=lambda: _wait_for_pipe(named_pipe),
            ),
            pause,
            wait,
            f"failed to connect over named pipe {named_pipe!r}",
            lambda: _pipe_hint(named_pipe),
        )

    def _reattach_or_handshake(
        self, reattach, handshake, *, use_reattach, after_failed_reattach=lambda: None
    ):
        """The connect step: take over the debuggee if asked to, else (or then) handshake.

        Runs on the connect thread, so the takeover counts against hd_connect's
        wait like the handshake itself.
        """

        def connect() -> int:
            self._reattached = False
            if use_reattach:
                if reattach():
                    # libhyperdbg's reattach also completes a plain handshake when
                    # the debuggee was still waiting; only a takeover says this.
                    self._reattached = "reattached to the debuggee" in self._peek()
                    return 1
                self._discard()  # the failed takeover's messages are not this connect's
                after_failed_reattach()
            return handshake()

        return connect

    @property
    def reattached(self) -> bool:
        """True if the current connection took over a debuggee left by an earlier debugger."""
        return self._connected and self._reattached

    @property
    def is_connecting(self) -> bool:
        """True while a Debugger-Mode connect waits for the debuggee's handshake."""
        return self._connect_thread is not None and self._connect_thread.is_alive()

    @property
    def last_connect_error(self) -> str | None:
        """Why the last background connect failed, if it did (cleared on the next one)."""
        return None if self._connect_failure is None else str(self._connect_failure)

    def _connect_debugger_mode(self, dll_connect, pause, wait, failure, hint=lambda: "") -> bool:
        """Run a serial/pipe connect; True once connected, False if still waiting.

        libhyperdbg blocks until the debuggee's handshake arrives, which takes
        ~1 min on the first connect and never comes if the debuggee is still bound
        to an earlier debugger (it sends its handshake once per `.debug prepare`).
        With `wait` set, the connect runs on a daemon thread and this returns
        after `wait` seconds at most; a late handshake still completes it.

        Always connects with pause: with pause=0 libhyperdbg's connect does not
        return while the debuggee runs (it waits for the next halt, like `g`). A
        no-pause connect is that plus the non-blocking continue_debuggee().
        """
        if self.is_connecting:
            raise PreconditionError(
                "a connect is already waiting for the debuggee's handshake (hd_connection_status)"
            )
        self._prepare_remote()
        self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
        self._discard()
        self._connect_failure = None

        def run() -> None:
            try:
                if not dll_connect():
                    self._connect_failure = self._connect_error(failure, hint())
                    return
                self._mode = "remote"
                self._connected = True
                _log.info("connected to remote HyperDbg debuggee")
                if not pause:
                    self.continue_debuggee()
            except Exception as exc:  # surfaced via last_connect_error / the caller
                self._connect_failure = exc

        if wait is None:
            run()
        else:
            self._connect_thread = threading.Thread(target=run, daemon=True)
            self._connect_thread.start()
            self._connect_thread.join(wait)
            if self._connect_thread.is_alive():
                return False
        if self._connect_failure is not None:
            raise self._connect_failure
        return True

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
        output = self._drain_settled()
        if "unable to attach to the target process" in output:
            # Only one user-mode debuggee can be attached at a time.
            hint = (
                "a user-mode debuggee is already attached: hd_process_kill or "
                "hd_process_detach first"
            )
        if "already connected to remote machine" in output:
            # libhyperdbg in *this* process is still attached, e.g. an earlier
            # connect that completed after its tool call was given up on.
            hint = "this server is already attached to a debuggee; use hd_disconnect first"
        if hint:
            message += f": {hint}"
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
                _log.info("session closing: unloading the VMM and kd driver")
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
        with self._ops():
            # Before any connect too: the reason for a failure is only printed.
            self._dll.hyperdbg_u_set_text_message_callback(self._text_cb)
            self._discard()
            for step in steps:
                rc = int(step())
                if rc != 0:
                    raise self._connect_error(f"{what} failed (rc={rc})")

    def _install_kd_driver(self) -> int:
        """Install the kd driver, riding out a service still pending deletion.

        Verified on hardware: the SCM keeps a deleted service until its last
        handle closes, so a server started right after another one released the
        driver (an MCP client's probe process, a reconnect, a restart) finds
        hyperkd "not fully deleted" and libhyperdbg gives up at once. Retry
        until the old instance is gone instead of failing the load.
        """
        deadline = time.monotonic() + self.driver_reinstall_timeout
        while True:
            rc = int(self._dll.hyperdbg_u_install_kd_driver())
            if rc == 0 or time.monotonic() >= deadline:
                return rc
            if _DRIVER_PENDING_DELETE not in self._peek():
                return rc
            self._discard()  # this attempt's failure is not the caller's to report
            time.sleep(0.5)

    def load_vmm(self) -> None:
        """Load the HyperDbg hypervisor (VMM), installing the kd driver first.

        CONSEQUENTIAL: this places the running OS under HyperDbg's hypervisor
        and requires driver loading (DSE off / test-signing). Not called
        implicitly anywhere - the operator must invoke it deliberately. Mirrors
        the CLI's `load vmm`: hyperdbg_u_load_vmm alone fails without the driver.
        """
        self._module_op("load vmm", self._install_kd_driver, self._dll.hyperdbg_u_load_vmm)
        self._attach_local()
        self._restore_symbols()

    def _restore_symbols(self) -> None:
        """Reload symbols after a VMM load: the tables do not survive it.

        Every address argument resolves through them, so without this the first
        tool call after a reload fails with a syntax error from the evaluator.
        """
        if not self.symbol_path:
            return
        try:
            self.run_command(f".sympath {self.symbol_path}")
            self.run_command(".sym reload")
        except HyperDbgError as exc:
            _log.info("could not restore symbols after the VMM load: %s", exc)

    def _attach_local(self) -> None:
        """After loading the VMM here, debug this machine (local VMI mode).

        With the VMM loaded, libhyperdbg refuses Debugger-Mode connects (its
        device is open), so local is the only mode left; without this the
        session would report "not connected" for a working debugger.
        """
        if not self._connected:
            self.connect_local()

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
            "load all modules", self._install_kd_driver, self._dll.hyperdbg_u_load_all_modules
        )
        self._attach_local()

    def unload_all_modules(self) -> None:
        self._module_op("unload all modules", self._dll.hyperdbg_u_unload_all_modules)

    # ----- Batch B: simple SDK-typed operations ---------------------------- #
    def get_processor_vendor(self) -> str:
        v = int(self._dll.hyperdbg_u_get_processor_vendor())
        return {0: "Intel", 1: "AMD"}.get(v, "Other")

    def get_kernel_base(self) -> int:
        self._require_connected()
        with self._ops():
            return int(self._dll.hyperdbg_u_get_kernel_base())

    def enable_transparent_mode(
        self, *, pid: int = 0, name: str = "", evade_mask: int = _TRANSPARENT_EVADE_MASK_SAFE
    ) -> None:
        # libhyperdbg takes the name when the pid flag is off and strlen()s it:
        # no name there is a NULL dereference in this process.
        if bool(pid) == bool(name):
            raise HyperDbgError("give exactly one of pid or name (the process to hide from)")
        if evade_mask & _TRANSPARENT_EVADE_SYSCALL_HOOK:
            raise HyperDbgError(
                "the syscall-hook technique (evade_mask bit 0x1) hangs the machine in "
                "local VMI mode: it EPT-hooks the global syscall entry, and a core then "
                "spins in the hypervisor on the next syscalls (bugcheck 0x101). Pass an "
                "evade_mask without bit 0x1 (0x1e is every other technique)."
            )
        self._require_connected()
        name_b = name.encode("utf-8") if name else None
        with self._ops():
            self._discard()
            ok = self._dll.hyperdbg_u_enable_transparent_mode_ex(
                c_uint32(pid), name_b, c_ubyte(1 if pid else 0), c_uint32(evade_mask)
            )
            output = self._drain_settled() if not ok else ""
        if not ok:
            raise self._failure("enable_transparent_mode failed", output)

    def disable_transparent_mode(self) -> None:
        self._require_connected()
        with self._ops():
            self._discard()
            ok = self._dll.hyperdbg_u_disable_transparent_mode()
            output = self._drain_settled() if not ok else ""
        if not ok:
            raise self._failure("disable_transparent_mode failed", output)

    @staticmethod
    def _failure(message: str, output: str) -> HyperDbgError:
        """A failed SDK call with HyperDbg's printed reason, fenced as target output."""
        if output.strip():
            message += "\n" + wrap_untrusted(output, "command-output")
        return HyperDbgError(message)

    def start_process(self, path: str, args: str = "") -> None:
        self._require_connected()
        with self._ops():
            self._discard()
            if args:
                ok = self._dll.hyperdbg_u_start_process_with_args(path, args)
            else:
                ok = self._dll.hyperdbg_u_start_process(path)
            output = self._drain_settled() if not ok else ""
        if not ok:
            raise HyperDbgError(
                f"start_process({path!r}) failed"
                + (("\n" + wrap_untrusted(output, "command-output")) if output.strip() else ""),
                status_code=ok,
            )

    def step_out(self, max_steps: int = 0) -> str:
        """Step until the current function returns (the CLI's `gu`).

        hyperdbg_u_stepping_step_over_for_gu is only one step of that loop: the
        CLI checks for `ret` after each step, which the SDK leaves to the caller.
        """
        return self.run_command("gu" + (f" {max_steps:x}" if max_steps else ""))

    def step_track(self) -> None:
        self._require_connected()
        with self._ops():
            self._dll.hyperdbg_u_stepping_instrumentation_step_in_for_tracking()

    # ----- Batch C: assembler ---------------------------------------------- #
    def assemble(self, code: str, address: int = 0) -> bytes:
        """Encode x86-64 assembly to machine-code bytes (two-step: length then fill)."""
        code_b = code.encode("utf-8")
        length = c_uint32(0)
        with self._ops():
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
        with self._ops():
            self._dll.hyperdbg_u_get_idt_entry(byref(pkt))
        return {"kernel_status": pkt.KernelStatus, "entries": list(pkt.IdtEntry)}

    def get_io_apic(self) -> dict:
        self._require_connected()
        pkt = ffi.IO_APIC_ENTRY_PACKETS()
        with self._ops():
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
        with self._ops():
            self._dll.hyperdbg_u_perform_smi_operation(byref(pkt))
        return int(pkt.SmiCount)

    def _require_connected(self) -> None:
        # The connect thread itself may act on the fresh session (pause=False resume).
        if self.is_connecting and threading.current_thread() is not self._connect_thread:
            raise NotConnectedError(
                "still connecting: waiting for the debuggee's handshake (hd_connection_status)"
            )
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

    def _discard(self) -> None:
        """Drop queued output that is not this command's, keeping it in the log.

        It is mostly HyperDbg's messages from between commands (e.g. an error
        the driver logged while the debuggee ran), which nothing else shows.
        """
        text = self._drain()
        if text.strip():
            _log.info("output between commands: %s", text[-4000:].rstrip())

    def _peek(self) -> str:
        """The output queued so far, left in place for whoever drains it."""
        text = self._drain()
        if text:
            self._output.put(text)
        return text

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
    @contextmanager
    def _ops(self, timeout: float | None = None):
        """Serialize a libhyperdbg call, giving up instead of hanging forever.

        A step or gu can wait for a halt that never comes (the thread was in a
        kernel wait, or the debuggee exited mid-step): that thread holds this
        lock for the rest of the process's life, and every other tool used to
        block on it with no way out but a server restart. Waiting is bounded so
        the client gets an error it can act on.
        """
        timeout = _OPS_TIMEOUT_S if timeout is None else timeout
        if not self._lock.acquire(timeout=timeout):
            raise HyperDbgError(
                f"another command has held the session for {timeout:.0f}s: it is most "
                "likely a step waiting for a thread that will never halt (the debuggee "
                "exited mid-step, or is blocked in the kernel). Try hd_exec_pause; if "
                "that does not bring the tools back, restart the server."
            )
        try:
            yield
        finally:
            self._lock.release()

    def run_command(self, command: str) -> str:
        """Run a HyperDbg CLI command and return its captured text output."""
        self._require_connected()
        with self._ops():
            self._discard()  # discard anything stale before we start
            _mark_interpreter_used()
            status = self._dll.hyperdbg_u_run_command(command.encode("utf-8"))
            output = self._drain_settled()
        if not _is_error_status(status):
            # The event forwarder complains asynchronously when a source it writes
            # to disappears; that is noise for the command the caller ran.
            output = "\n".join(
                line for line in output.splitlines() if not line.startswith(_ASYNC_ERRORS)
            )
        if _is_error_status(status) or _reports_failure(output):
            # Debuggee output is attacker-controlled even on failure; fence it
            # so it can never reach the model as unmarked text (review H2).
            hint = _failure_hint(output)
            raise HyperDbgError(
                f"run_command({command!r}) failed (status=0x{status & 0xFFFFFFFF:08X})."
                + (f"\n{hint}" if hint else "")
                + "\n"
                + wrap_untrusted(output, "command-output"),
                status_code=status,
            )
        return output

    def read_all_registers(self) -> dict[str, int]:
        self._require_connected()
        regs = ffi.GUEST_REGS()
        extra = ffi.GUEST_EXTRA_REGISTERS()
        with self._ops():
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
        with self._ops():
            self._dll.hyperdbg_u_read_target_register(reg_id, byref(value))
        return value.value

    def write_register(self, name: str, value: int) -> None:
        self._require_connected()
        reg_id = ffi.REGS_ENUM.get(name.lower())
        if reg_id is None:
            raise HyperDbgError(f"unknown register {name!r}")
        if self._mode == "local":
            # hyperdbg_u_write_target_register only reaches a serial debuggee;
            # the CLI's `r` sets a user-debugger thread's register through the
            # script engine instead (`@reg=value;` run in the paused thread).
            self.run_command(f"r {name.lower()} = {value:#x}")
            return
        with self._ops():
            self._dll.hyperdbg_u_write_target_register(reg_id, value)

    def _target_pid(self, pid: int) -> int:
        """The process a local (VMI) memory access defaults to, like the CLI.

        hyperkd reads/writes in the context of the given pid; the CLI's d*/u*/e*
        commands substitute their own process for pid 0 in VMI mode, but the
        SDK exports don't. Passing 0 through made every local hd_mem_read fail
        (verified on hardware). Kernel addresses read the same from any process.
        In Debugger Mode the debuggee uses its halted context and pid stays 0.
        """
        if pid == 0 and self._mode == "local":
            return os.getpid()
        return pid

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
        # The CLI's own d*/u* always read through the kernel (READ_FROM_KERNEL);
        # READ_FROM_VMX_ROOT is for a debugger running inside the hypervisor and
        # silently returns nothing from a local session (verified on hardware).
        reading_type = (
            ffi.ReadingType.FROM_VMX_ROOT if self._mode == "remote" else ffi.ReadingType.FROM_KERNEL
        )
        with self._ops():
            self._dll.hyperdbg_u_read_memory(
                c_uint64(address),
                mem_type,
                reading_type,
                c_uint32(self._target_pid(pid)),
                c_uint32(size),
                c_ubyte(0),  # get_address_mode = false
                None,  # address_mode out (unused)
                cast(buf, POINTER(c_ubyte)),
                byref(ret_len),
            )
        n = min(ret_len.value, size)
        if n == 0:
            # libhyperdbg reports a failure through the length only; an empty
            # result must not look like "the memory is empty".
            raise HyperDbgError(
                f"memory at {address:#x} could not be read (pid {self._target_pid(pid):#x}): "
                "the page is not mapped in that process, or it is paged out (try hd_pagein)"
            )
        return buf.raw[:n]

    def write_memory_bytes(
        self, address: int, data: bytes, *, pid: int = 0, virtual: bool = True
    ) -> None:
        self._require_connected()
        if not data:
            raise HyperDbgError("write payload is empty")
        buf = create_string_buffer(bytes(data), len(data))
        mem_type = ffi.EditMemoryType.VIRTUAL if virtual else ffi.EditMemoryType.PHYSICAL
        with self._ops():
            self._dll.hyperdbg_u_write_memory(
                c_void_p(address),
                mem_type,
                c_uint32(self._target_pid(pid)),
                cast(buf, c_void_p),
                c_uint32(len(data)),
            )

    def set_breakpoint(self, address: int, *, pid: int = 0, tid: int = 0, core: int = 0) -> None:
        self._require_connected()
        if self._mode == "local":
            # The SDK export needs a debuggee attached the Debugger-Mode way; in
            # VMI mode HyperDbg answers "bl" with the same explanation.
            raise PreconditionError(
                "software breakpoints need Debugger Mode: in VMI mode use an EPT hook "
                "instead (hd_hook_ept2 on the code address, hd_hook_monitor on the data)"
            )
        with self._ops():
            self._dll.hyperdbg_u_set_breakpoint(address, pid, tid, core)

    def continue_debuggee(self) -> bool:
        """Resume the debuggee. Returns True if it is still running afterwards.

        In Debugger Mode libhyperdbg's continue blocks until the debuggee halts
        again (breakpoint, event, pause) - like `g` in the CLI - so it runs on a
        daemon thread and this returns at once. Local VMI continue returns.
        """
        self._require_connected()
        if self._mode != "remote":
            with self._ops():
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
        if self._mode == "local":
            # Not under the lock: a user-debugger step or `gu` holds it while it
            # waits for the thread to halt.
            if self._lock.locked():
                # A `gu` loop stops only when libhyperdbg's instrumenting flag is
                # cleared, and only its CTRL+C handler clears it (gu.cpp), so do
                # what the CLI's CTRL+C does. Best effort: without a console of
                # our own the event cannot be raised.
                try:
                    _mark_interpreter_used()
                    _console_break()
                except HyperDbgError as exc:
                    _log.info("cannot interrupt the running step: %s", exc)
            self._dll.hyperdbg_u_pause_debuggee()
            return
        if not self.is_running:
            with self._ops():
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
        with self._ops():
            self._discard()
            try:
                fn()
            except HyperDbgError as exc:
                # libhyperdbg prints the reason it refused ("the debuggee process
                # is not alive anymore", no halted context) instead of returning
                # it, and the caller needs that far more than "returned FALSE".
                output = self._drain_settled()
                if output.strip():
                    raise HyperDbgError(
                        f"{exc}\n" + wrap_untrusted(output, "step-output")
                    ) from None
                raise

    # ----- script engine ---------------------------------------------------- #
    def check_script(self, script: str) -> str | None:
        """Parse a script with HyperDbg's parser; its error message, or None.

        Only parses (symbols are resolved, nothing runs), so it is safe for any
        script and works with no debuggee at all. None also when the parser
        library can't be found: the engine then reports errors itself.
        """
        if self._script_engine is False:
            self._script_engine = ffi.load_script_engine()
        lib = self._script_engine
        if lib is None:
            return None
        with self._ops():
            self._discard()
            buf = lib.ScriptEngineParse(script.encode("utf-8"))
            try:
                if not buf:
                    return None
                msg = buf.contents.Message
                return string_at(msg).decode("utf-8", "replace") if msg else None
            finally:
                if buf:
                    lib.RemoveSymbolBuffer(buf)
                self._discard()

    def engine_context(self) -> str:
        """Where a script would run: 'target', 'running' or 'simulated'.

        Debugger Mode, or local VMI mode with a paused user-mode process, runs
        scripts on the target ('target'). A local process that is not paused
        refuses them ('running'). With no process at all HyperDbg only simulates
        the engine with zeroed registers ('simulated'). libhyperdbg exports no
        flag for this, so ask the engine with a script that cannot parse: it
        checks the debuggee before parsing, and a parse error means it got that
        far without running anything.
        """
        self._require_connected()
        if self._mode != "local":
            return "target"
        with self._ops():
            self._discard()
            try:
                self._dll.hyperdbg_u_run_script(b")", c_ubyte(1))
            except HyperDbgError:
                pass
            said = self._drain_settled()
        if "not connected to any debuggee" in said:
            return "simulated"
        if "NOT paused" in said:
            return "running"
        return "target"

    def _require_target_context(self, script: str, what: str) -> None:
        """Refuse a script that reads registers/memory where it would read zeros."""
        if self._mode != "local":
            return
        reads = needs_target_context(script)
        if not reads:
            return
        context = self.engine_context()
        if context == "simulated":
            raise HyperDbgError(
                f"{what} reads {', '.join(reads)}, but in local VMI mode with no paused "
                "process HyperDbg only simulates the script engine: every register is 0 "
                "and target memory is not read, so the result would be meaningless. "
                "Pause a user-mode process first (hd_process_start or attach), or use "
                "hd_reg_read / hd_mem_read. Symbols and arithmetic work as they are."
            )
        if context == "running":
            raise HyperDbgError(
                f"{what} reads {', '.join(reads)} from the debugged process, which is "
                "running: pause it first (hd_exec_pause)."
            )

    def eval_expression(self, expr: str) -> int:
        self._require_connected()
        self._require_target_context(expr, "the expression")
        has_error = c_ubyte(0)
        with self._ops():
            self._discard()
            value = self._dll.hyperdbg_u_eval_expression(expr.encode("utf-8"), byref(has_error))
            output = self._drain()
        if has_error.value:
            # An unknown symbol is the usual cause: say how to fix it, and keep
            # HyperDbg's own explanation (fenced: it may echo target data).
            raise HyperDbgError(
                f"could not evaluate {expr!r}. If it names a symbol, make sure symbols "
                "are loaded (hd_sym_path + hd_sym_reload)."
                + (("\n" + wrap_untrusted(output, "eval-output")) if output.strip() else ""),
                status_code=has_error.value,
            )
        return value

    def run_script(self, script: str) -> str:
        """Run a script on the target; return what it printed.

        The parser checks it first (line/column/hint on a syntax error). It
        needs Debugger Mode or a paused user-mode process; the error says which
        is missing.
        """
        self._require_connected()
        error = self.check_script(script)
        if error:
            raise HyperDbgError(format_parse_error(error, script))
        with self._ops():
            self._discard()
            try:
                self._dll.hyperdbg_u_run_script(script.encode("utf-8"), c_ubyte(1))
            except HyperDbgError as exc:
                output = self._drain_settled()
                raise HyperDbgError(
                    _script_failure(exc, output, script), status_code=exc.status_code
                ) from None
            return self._drain_settled()


def _script_failure(exc: HyperDbgError, output: str, script: str) -> str:
    """A failed run_script, said in terms of what to do about it."""
    if "not connected to any debuggee" in output:
        return (
            "scripts run in a debuggee: in local VMI mode that means a paused user-mode "
            "process (hd_process_start, or attach and hd_exec_pause); otherwise connect "
            "in Debugger Mode. For expressions on symbols use hd_eval; to run a script "
            "on every hit of an event, pass it as script= to a hook tool."
        )
    if "NOT paused" in output:
        return "the debugged process is running: pause it first (hd_exec_pause)."
    if "Line " in output and "^" in output:
        return format_parse_error(output, script)
    return f"{exc}\n" + wrap_untrusted(output, "script-output")
