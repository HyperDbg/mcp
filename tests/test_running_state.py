"""
* @file test_running_state.py
* @brief Debugger-Mode continue/pause: continue returns while the debuggee runs,
*        target calls refuse until it halts, pause falls back to CTRL+C.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import asyncio
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

    def hyperdbg_u_pause_debuggee(self):
        self.calls.append("pause")


def test_load_vmm_installs_driver_first_and_reports_failure():
    ok = ModuleDll()
    session = HyperDbgSession(dll=ok)
    session.load_vmm()
    assert ok.calls == ["install", "load_vmm"]  # like the CLI's `load vmm`
    # the VMM now runs here: the session debugs this machine
    assert session.is_connected and session.mode == "local"

    bad = ModuleDll(install_rc=1)
    with pytest.raises(HyperDbgError, match=r"load vmm failed \(rc=1\)"):
        HyperDbgSession(dll=bad).load_vmm()
    assert bad.calls == ["install"]  # no VMM load on a missing driver


def test_load_vmm_waits_out_a_driver_service_pending_deletion(monkeypatch):
    # Found live: a server started right after another released hyperkd (an MCP
    # client's probe process) sees the old service still marked for deletion.
    monkeypatch.setattr(session_mod.time, "sleep", lambda _s: None)
    dll = ModuleDll()
    session = HyperDbgSession(dll=dll)
    pending = iter([1, 1, 0])

    def install():
        dll.calls.append("install")
        rc = next(pending)
        if rc:
            session._on_text(b"err, previous instance of the service is not fully deleted")
        return rc

    dll.hyperdbg_u_install_kd_driver = install
    session.load_vmm()
    assert dll.calls == ["install", "install", "install", "load_vmm"]


def test_load_vmm_does_not_retry_other_driver_failures():
    dll = ModuleDll(install_rc=1)
    with pytest.raises(HyperDbgError, match=r"load vmm failed \(rc=1\)"):
        HyperDbgSession(dll=dll).load_vmm()
    assert dll.calls == ["install"]


def test_unload_vmm_also_unloads_kd_and_local_close_releases_modules():
    dll = ModuleDll()
    s = HyperDbgSession(dll=dll)
    s.unload_vmm()
    assert dll.calls == ["unload_vmm", "unload_kd"]  # like the CLI's `unload vmm`

    dll.calls.clear()
    s.connect_local()
    s.close()  # a leftover kd module would keep a thread blocked in the driver
    assert dll.calls == ["unload_vmm", "unload_kd"]


class HandshakeDll(RunningDll):
    """Named-pipe connect that blocks until the debuggee's handshake (`arrive`)."""

    def __init__(self, output=b""):
        super().__init__()
        self.arrive = threading.Event()
        self.pause_args: list[int] = []
        self.output = output

    def hyperdbg_u_connect_remote_debugger_using_named_pipe(self, name, pause):
        self.pause_args.append(pause)
        if self.output:
            self._cb(self.output)
            return 0
        self.arrive.wait(5)
        return 1


def test_connect_always_pauses_then_continues_for_pause_false():
    # libhyperdbg's connect with pause=0 never returns while the debuggee runs.
    dll = HandshakeDll()
    dll.arrive.set()
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe(r"\.\pipe\x", pause=False) is True
    assert dll.pause_args == [1]
    assert s.is_connected and s.is_running  # resumed with the non-blocking continue
    dll.halt.set()


def test_connect_waiting_for_handshake_returns_and_completes_later():
    dll = HandshakeDll()
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe(r"\.\pipe\x", wait=0.2) is False
    assert s.is_connecting and not s.is_connected
    with pytest.raises(HyperDbgError, match="still connecting"):
        s.run_command("r")
    with pytest.raises(HyperDbgError, match="already waiting"):
        s.connect_remote_pipe(r"\.\pipe\x", wait=0.1)
    dll.arrive.set()  # e.g. the VM was rebooted and its `.debug prepare` pinged
    s._connect_thread.join(2)
    assert s.is_connected and not s.is_connecting


def test_already_attached_in_this_process_is_named_as_such():
    msg = b"err, the current system is already connected to remote machine (debuggee)\n"
    s = HyperDbgSession(dll=HandshakeDll(output=msg))
    with pytest.raises(HyperDbgError, match="this server is already attached"):
        s.connect_remote_pipe(r"\.\pipe\x")


async def test_hd_connect_returns_while_the_handshake_is_pending(tmp_path):
    from mcp import Client

    from hyperdbg_mcp import server

    dll = HandshakeDll()
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: HyperDbgSession(dll=dll),
    )
    async with Client(srv) as client:
        args = {"transport": "pipe", "pipe": r"\.\pipe\x", "wait_seconds": 1}
        out = (await client.call_tool("hd_connect", args)).content[0].text
        assert out.startswith("connecting:")
        status = (await client.call_tool("hd_connection_status", {})).content[0].text
        assert "connecting=True" in status
        disc = (await client.call_tool("hd_disconnect", {})).content[0].text
        assert "cannot abort" in disc
        dll.arrive.set()
        for _ in range(50):
            status = (await client.call_tool("hd_connection_status", {})).content[0].text
            if "connected=True" in status:
                break
            await asyncio.sleep(0.05)
        assert "connected=True" in status


def test_background_connect_with_pause_false_resumes_the_debuggee():
    # The resume runs on the connect thread, which must not trip "still connecting".
    dll = HandshakeDll()
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe("pipe-x", pause=False, wait=0.2) is False
    dll.arrive.set()
    s._connect_thread.join(2)
    assert s.is_connected and s.is_running and s.last_connect_error is None
    dll.halt.set()


class MemoryDll(ModuleDll):
    def __init__(self):
        super().__init__()
        self.pids: list[int] = []

    def hyperdbg_u_read_memory(self, address, mem_type, reading, pid, size, *rest):
        self.pids.append(pid.value)
        rest[-1]._obj.value = size.value
        return 1

    def hyperdbg_u_write_memory(self, dest, mem_type, pid, src, size):
        self.pids.append(pid.value)
        return 1


def test_local_memory_access_defaults_to_own_process():
    # Found live: the SDK exports pass pid 0 straight to hyperkd, which then has
    # no process to read in; the CLI substitutes its own pid in VMI mode.
    import os

    dll = MemoryDll()
    session = HyperDbgSession(dll=dll)
    session.connect_local()
    session.read_memory(0xFFFFF80000000000, 1)
    session.write_memory_bytes(0xFFFFF80000000000, b"\x90")
    session.read_memory(0x1000, 1, pid=4)
    assert dll.pids == [os.getpid(), os.getpid(), 4]


@pytest.mark.parametrize(("pid", "name"), [(0, ""), (0x1234, "ping.exe")])
def test_transparent_mode_needs_exactly_one_target(pid, name):
    # libhyperdbg strlen()s a NULL name when there is no pid: refuse before the call
    with pytest.raises(HyperDbgError, match="exactly one of pid or name"):
        HyperDbgSession(dll=ModuleDll()).enable_transparent_mode(pid=pid, name=name)


def test_local_pause_does_not_wait_for_a_blocked_step():
    # A user-debugger step holds the session lock while it waits for the thread;
    # only a pause releases that wait, so the pause must not queue behind it.
    s = HyperDbgSession(dll=ModuleDll())
    s.connect_local()
    with s._lock:
        t = threading.Thread(target=s.pause_debuggee)
        t.start()
        t.join(2.0)
        assert not t.is_alive()


def test_local_register_write_goes_through_the_r_command():
    # the SDK export only reaches a serial debuggee; locally the CLI's `r` works
    dll = ModuleDll()
    dll.commands = []
    dll.hyperdbg_u_run_command = lambda cmd: dll.commands.append(cmd) or 0
    s = HyperDbgSession(dll=dll)
    s.connect_local()
    s.write_register("R12", 0x1)
    assert dll.commands == [b"r r12 = 0x1"]
