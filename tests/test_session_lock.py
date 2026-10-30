"""
* @file test_session_lock.py
* @brief A command stuck in libhyperdbg must not hang every other tool.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import threading

import pytest

from hyperdbg_mcp import session as session_mod
from hyperdbg_mcp.errors import HyperDbgError
from hyperdbg_mcp.session import HyperDbgSession


class IdleDll:
    """Just enough of libhyperdbg to have a connected local session."""

    def hyperdbg_u_set_text_message_callback(self, cb):
        self._cb = cb

    def hyperdbg_u_connect_local_debugger(self):
        pass

    def hyperdbg_u_run_command(self, command):
        return 0


def test_a_wedged_command_reports_the_session_busy(monkeypatch):
    # A step that waits for a halt that never comes holds the lock forever; the
    # next tool must fail instead of blocking for the rest of the session.
    monkeypatch.setattr(session_mod, "_OPS_TIMEOUT_S", 0.2)
    s = HyperDbgSession(dll=IdleDll())
    s.connect_local()

    held, release = threading.Event(), threading.Event()

    def wedge():
        with s._ops():
            held.set()
            release.wait(5)

    t = threading.Thread(target=wedge, daemon=True)
    t.start()
    assert held.wait(5)
    try:
        with pytest.raises(HyperDbgError, match="held the session"):
            s.read_register("rip")
    finally:
        release.set()
        t.join(5)

    # The lock is free again, so the next call goes through.
    assert s.run_command("lm") == ""
