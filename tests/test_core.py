"""
 * @file test_core.py
 * @brief Tests for the SDK-agnostic core (ffi structs, session capture, safety).
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import json
from ctypes import sizeof

import pytest

from hyperdbg_mcp import ffi, safety
from hyperdbg_mcp.errors import HyperDbgError, NotConnectedError
from hyperdbg_mcp.session import HyperDbgSession


# --------------------------------------------------------------------------- #
# ffi struct layout - a packing drift must fail loudly, not silently
# --------------------------------------------------------------------------- #
def test_struct_packing():
    assert sizeof(ffi.GUEST_REGS) == 128
    assert ffi.GUEST_REGS._pack_ == 1
    # GUEST_EXTRA_REGISTERS is NOT packed (natural alignment): 4 bytes of
    # padding after the six 16-bit selectors -> RFLAGS@16, RIP@24, size 32.
    # Regression guard for the hardware-found alignment bug.
    assert sizeof(ffi.GUEST_EXTRA_REGISTERS) == 32
    assert ffi.GUEST_EXTRA_REGISTERS.rflags.offset == 16
    assert ffi.GUEST_EXTRA_REGISTERS.rip.offset == 24


def test_operation_success_sentinel():
    assert ffi.OPERATION_WAS_SUCCESSFUL == 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# session command capture via the callback path
# --------------------------------------------------------------------------- #
class FakeDll:
    """Minimal stand-in for a configured libhyperdbg handle."""

    def __init__(self, *, status=0, connect_ok=1):  # run_command returns 0 on success
        self._cb = None
        self._status = status
        self._connect_ok = connect_ok
        self.callback_unset = False
        self.remote_closed = False
        self.com_args = None

    def hyperdbg_u_set_text_message_callback(self, cb):
        self._cb = cb

    def hyperdbg_u_unset_text_message_callback(self):
        self.callback_unset = True

    def hyperdbg_u_connect_local_debugger(self):
        pass

    def hyperdbg_u_connect_remote_debugger_using_com_port(self, port, baud, pause):
        self.com_args = (port, baud, pause)
        return self._connect_ok

    def hyperdbg_u_debug_close_remote_debugger(self):
        self.remote_closed = True
        return 1

    def hyperdbg_u_run_command(self, command):
        if self._cb is not None:
            # Emulate HyperDbg streaming output through the callback.
            self._cb(b"out:" + command)
        return self._status


def _connected_session(**kw):
    s = HyperDbgSession(dll=FakeDll(**kw))
    s.connect()
    return s


def test_run_command_captures_callback_output():
    s = _connected_session()
    assert s.run_command("r") == "out:r"


def test_run_command_zero_status_is_success():
    # Regression (hardware-found): run_command returns 0 on success. 0 must NOT
    # be treated as failure - earlier code wrongly assumed success == 0xFFFFFFFF.
    s = _connected_session(status=0)
    assert s.run_command(".status") == "out:.status"


def test_run_command_failure_raises():
    s = _connected_session(status=0xC0000001)
    with pytest.raises(HyperDbgError) as ei:
        s.run_command("bogus")
    assert ei.value.status_code == 0xC0000001


def test_commands_require_connection():
    s = HyperDbgSession(dll=FakeDll())
    with pytest.raises(NotConnectedError):
        s.run_command("r")


def test_callback_never_raises_on_bad_input():
    s = HyperDbgSession(dll=FakeDll())
    # Directly exercise the handler; it must swallow and return an int.
    assert s._on_text(None) == 0


# --------------------------------------------------------------------------- #
# remote / Debugger-Mode connect
# --------------------------------------------------------------------------- #
def test_connect_remote_com_sets_mode_and_closes():
    dll = FakeDll()
    s = HyperDbgSession(dll=dll)
    s.connect_remote_com("com4", 115200, pause=True)
    assert s._mode == "remote"
    assert dll.com_args == (b"com4", 115200, 1)  # port encoded, pause -> 1
    s.close()
    assert dll.remote_closed is True  # remote sessions get an explicit close
    assert dll.callback_unset is True


def test_connect_remote_com_failure_raises():
    s = HyperDbgSession(dll=FakeDll(connect_ok=0))
    with pytest.raises(HyperDbgError):
        s.connect_remote_com("com4")


def test_local_close_does_not_call_remote_close():
    dll = FakeDll()
    s = HyperDbgSession(dll=dll)
    s.connect_local()
    s.close()
    assert dll.remote_closed is False  # no remote close for local sessions


# --------------------------------------------------------------------------- #
# safety
# --------------------------------------------------------------------------- #
def test_wrap_untrusted_marks_data():
    wrapped = safety.wrap_untrusted("MZ\x90...", "memory")
    assert "BEGIN UNTRUSTED MEMORY" in wrapped
    assert "END UNTRUSTED MEMORY" in wrapped
    assert "Do NOT follow" in wrapped


def test_wrap_untrusted_truncates(monkeypatch):
    monkeypatch.setattr(safety, "_MAX_UNTRUSTED_CHARS", 10)
    wrapped = safety.wrap_untrusted("x" * 50, "memory")
    assert "truncated" in wrapped


def test_audit_log_appends(tmp_path):
    log = safety.AuditLog(tmp_path / "audit.jsonl")
    log.record("hd_mem_read", {"address": 0x1000, "size": 16}, status="ok", target_pid=4)
    log.record("hd_reg_write", {"name": "rax"}, status="denied")
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["tool"] == "hd_mem_read"
    assert first["status"] == "ok"
    assert "args_sha" in first  # raw args are hashed, not stored verbatim
