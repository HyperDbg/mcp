"""
* @file test_running_state.py
* @brief Debugger-Mode continue/pause: continue returns while the debuggee runs,
*        target calls refuse until it halts, pause falls back to CTRL+C.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import threading

import pytest

from hyperdbg_mcp import session as session_mod
from hyperdbg_mcp.errors import HyperDbgError, PreconditionError
from hyperdbg_mcp.session import HyperDbgSession


class RunningDll:
    """continue blocks until `halt` is set, like libhyperdbg in Debugger Mode."""

    def __init__(self):
        self.halt = threading.Event()
        self.continues = 0
        self.commands: list[bytes] = []

    def hyperdbg_u_set_text_message_callback(self, cb):
        self._cb = cb

    def hyperdbg_u_unset_text_message_callback(self):
        pass

    def hyperdbg_u_connect_remote_debugger_using_named_pipe(self, name, pause):
        return 1

    def hyperdbg_u_continue_debuggee(self):
        self.continues += 1
        self.halt.clear()
        self.halt.wait(5)

    def hyperdbg_u_pause_debuggee(self):
        pass  # the real export is a no-op over serial/pipe

    def hyperdbg_u_run_command(self, cmd):
        self.commands.append(cmd)
        return 0

    def hyperdbg_u_debug_close_remote_debugger(self):
        self.halt.set()


def _remote():
    dll = RunningDll()
    s = HyperDbgSession(dll=dll)
    s.connect_remote_pipe(r"\\.\pipe\x")
    return s, dll


def test_continue_returns_while_running_and_tools_refuse(monkeypatch):
    s, dll = _remote()
    assert s.continue_debuggee() is True
    assert s.is_running
    with pytest.raises(PreconditionError, match="running"):
        s.run_command("r")

    breaks = []
    monkeypatch.setattr(session_mod, "_console_break", lambda: (breaks.append(1), dll.halt.set()))
    s.pause_debuggee()
    assert breaks == [1] and not s.is_running
    assert dll.commands[-1] == b""  # makes libhyperdbg install its CTRL+C handler
    assert s.run_command(".status") == ""


def test_breakpoint_halt_ends_running_without_pause():
    s, dll = _remote()
    s.continue_debuggee()
    dll.halt.set()  # the debuggee hit a breakpoint/event
    s._run_thread.join(1)
    assert not s.is_running


def test_pause_times_out_with_a_clear_error(monkeypatch):
    s, dll = _remote()
    s.continue_debuggee()
    monkeypatch.setattr(session_mod, "_console_break", lambda: None)
    with pytest.raises(HyperDbgError, match="did not halt"):
        s.pause_debuggee(timeout=0.2)
    dll.halt.set()


def test_close_while_running_does_not_continue_again():
    s, dll = _remote()
    s.continue_debuggee()
    s.close()
    assert dll.continues == 1 and not s.is_connected


@pytest.mark.skipif(sys.platform != "win32", reason="Windows console control events")
def test_console_break_reaches_only_this_process():
    # Run in a child: _console_break may swap the console, which must not touch
    # pytest's own. The child installs a stand-in for libhyperdbg's handler.
    child = textwrap.dedent(
        """
        import ctypes, time
        from hyperdbg_mcp.session import _console_break, _ensure_private_console
        _ensure_private_console()  # done before connect, i.e. before libhyperdbg's handler
        got = []
        HANDLER = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint32)
        h = HANDLER(lambda ev: (got.append(ev), 1)[1])
        ctypes.windll.kernel32.SetConsoleCtrlHandler(h, 1)
        _console_break()
        time.sleep(1)
        print("events", got)
        """
    )
    out = subprocess.run([sys.executable, "-c", child], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert "events [1]" in out.stdout  # exactly one CTRL_BREAK_EVENT, and we survived it


@pytest.mark.skipif(sys.platform != "win32", reason="Windows console control events")
def test_console_break_refuses_on_a_shared_console():
    import ctypes

    k32 = ctypes.WinDLL("kernel32")
    if session_mod._console_is_private(k32):
        pytest.skip("test runner owns its console; the refusal path needs a shared one")
    with pytest.raises(HyperDbgError, match="shares its console"):
        session_mod._console_break()


class ModuleDll:
    def __init__(self, install_rc=0, load_rc=0):
        self.calls: list[str] = []
        self.install_rc, self.load_rc = install_rc, load_rc

    def hyperdbg_u_install_kd_driver(self):
        self.calls.append("install")
        return self.install_rc

    def hyperdbg_u_load_vmm(self):
        self.calls.append("load_vmm")
        return self.load_rc

    def hyperdbg_u_unload_vmm(self):
        self.calls.append("unload_vmm")
        return 0

    def hyperdbg_u_unload_kd(self):
        self.calls.append("unload_kd")
        return 0

    def hyperdbg_u_is_any_module_loaded(self):
        return 1

    def hyperdbg_u_set_text_message_callback(self, cb):
        pass

    def hyperdbg_u_unset_text_message_callback(self):
        pass

    def hyperdbg_u_connect_local_debugger(self):
        pass


def test_load_vmm_installs_driver_first_and_reports_failure():
    ok = ModuleDll()
    HyperDbgSession(dll=ok).load_vmm()
    assert ok.calls == ["install", "load_vmm"]  # like the CLI's `load vmm`

    bad = ModuleDll(install_rc=1)
    with pytest.raises(HyperDbgError, match=r"load vmm failed \(rc=1\)"):
        HyperDbgSession(dll=bad).load_vmm()
    assert bad.calls == ["install"]  # no VMM load on a missing driver


def test_unload_vmm_also_unloads_kd_and_local_close_releases_modules():
    dll = ModuleDll()
    s = HyperDbgSession(dll=dll)
    s.unload_vmm()
    assert dll.calls == ["unload_vmm", "unload_kd"]  # like the CLI's `unload vmm`

    dll.calls.clear()
    s.connect_local()
    s.close()  # a leftover kd module would keep a thread blocked in the driver
    assert dll.calls == ["unload_vmm", "unload_kd"]
