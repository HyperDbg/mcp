"""
* @file test_reattach.py
* @brief Taking over a debuggee left by a debugger that died (`.debug remote ... reattach`)
*        instead of waiting for a handshake it sends only once per `.debug prepare`.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import threading

import pytest

from hyperdbg_mcp import session as session_mod
from hyperdbg_mcp.session import HyperDbgSession

TAKEOVER = b"reattaching to the debuggee...\nreattached to the debuggee\n"
HANDSHAKE = b"the debuggee is waiting for a debugger, continuing with the handshake...\n"


@pytest.fixture(autouse=True)
def _no_real_pipes(monkeypatch):
    monkeypatch.setattr(session_mod, "_wait_for_pipe", lambda *a, **k: None)


class ReattachDll:
    """libhyperdbg with the reattach export; the plain handshake never comes unless `arrive`."""

    def __init__(self, reattach_rc=1, reattach_says=TAKEOVER, has_reattach=True):
        self.calls: list[str] = []
        self.arrive = threading.Event()
        self.reattach_rc, self.reattach_says = reattach_rc, reattach_says
        if not has_reattach:
            self.hyperdbg_u_reattach_remote_debugger_using_named_pipe = None

    def hyperdbg_u_set_text_message_callback(self, cb):
        self._cb = cb

    def hyperdbg_u_unset_text_message_callback(self):
        pass

    def hyperdbg_u_reattach_remote_debugger_using_named_pipe(self, name, pause):
        self.calls.append(f"reattach pause={pause}")
        self._cb(self.reattach_says)
        return self.reattach_rc

    def hyperdbg_u_connect_remote_debugger_using_named_pipe(self, name, pause):
        self.calls.append(f"handshake pause={pause}")
        self.arrive.wait(5)
        return 1

    def hyperdbg_u_continue_debuggee(self):
        self.calls.append("continue")

    def hyperdbg_u_debug_close_remote_debugger(self):
        self.arrive.set()


def test_debuggee_left_by_a_dead_debugger_is_taken_over():
    dll = ReattachDll()
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe("pipe-x", wait=2) is True
    assert dll.calls == ["reattach pause=1"]  # no handshake, which would never come
    assert s.is_connected and s.reattached


def test_waiting_debuggee_is_connected_but_not_reported_as_taken_over():
    # libhyperdbg's reattach finishes the handshake itself for a debuggee that waits
    dll = ReattachDll(reattach_says=HANDSHAKE)
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe("pipe-x", wait=2) is True
    assert dll.calls == ["reattach pause=1"]
    assert s.is_connected and not s.reattached


def test_failed_takeover_falls_back_to_the_handshake():
    dll = ReattachDll(reattach_rc=0, reattach_says=b"err, the debuggee did not respond\n")
    dll.arrive.set()
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe("pipe-x", wait=2) is True
    assert dll.calls == ["reattach pause=1", "handshake pause=1"]
    assert s.is_connected and not s.reattached


@pytest.mark.parametrize(
    ("dll", "mode"),
    [
        (ReattachDll(has_reattach=False), "auto"),  # a libhyperdbg without the export
        (ReattachDll(), "never"),
    ],
)
def test_plain_handshake_without_reattach(dll, mode):
    dll.arrive.set()
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe("pipe-x", wait=2, reattach=mode) is True
    assert dll.calls == ["handshake pause=1"] and not s.reattached


def test_pause_false_resumes_after_a_takeover():
    dll = ReattachDll()
    dll.hyperdbg_u_continue_debuggee = lambda: (dll.calls.append("continue"), dll.arrive.wait(5))
    s = HyperDbgSession(dll=dll)
    assert s.connect_remote_pipe("pipe-x", pause=False, wait=2) is True
    assert dll.calls[0] == "reattach pause=1" and s.reattached
    s._run_thread.join(0.2)
    assert "continue" in dll.calls and s.is_running
    dll.arrive.set()


async def test_hd_connect_reports_the_takeover(tmp_path):
    from mcp import Client

    from hyperdbg_mcp import server

    dll = ReattachDll()
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=lambda: HyperDbgSession(dll=dll),
    )
    async with Client(srv) as client:
        args = {"transport": "pipe", "pipe": "pipe-x", "wait_seconds": 2}
        out = (await client.call_tool("hd_connect", args)).content[0].text
        assert "reattached to a debuggee left by an earlier debugger" in out
        status = (await client.call_tool("hd_connection_status", {})).content[0].text
        assert "reattached=True" in status
        await client.call_tool("hd_disconnect", {})
        bad = await client.call_tool("hd_connect", {"transport": "pipe", "reattach": "maybe"})
        assert bad.is_error and "invalid reattach" in bad.content[0].text
