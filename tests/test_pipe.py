"""
* @file test_pipe.py
* @brief Named-pipe connect failures explain themselves (missing vs busy pipe,
*        plus HyperDbg's own output).
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import os
import sys

import pytest

from hyperdbg_mcp.errors import HyperDbgError
from hyperdbg_mcp.session import HyperDbgSession, _pipe_hint

win_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes")


class PipeFailDll:
    def hyperdbg_u_set_text_message_callback(self, cb):
        self._cb = cb

    def hyperdbg_u_connect_remote_debugger_using_named_pipe(self, name, pause):
        self._cb(b"err, the pipe is busy\n")  # what libhyperdbg prints on failure
        return 0


def test_pipe_connect_error_carries_hyperdbg_output():
    s = HyperDbgSession(dll=PipeFailDll())
    with pytest.raises(HyperDbgError) as ei:
        s.connect_remote_pipe(r"\\.\pipe\hd-mcp-test-missing-" + str(os.getpid()))
    msg = str(ei.value)
    assert "BEGIN UNTRUSTED CONNECT-OUTPUT" in msg and "the pipe is busy" in msg
    assert not s.is_connected


@win_only
def test_pipe_hint_missing_then_busy():
    import ctypes
    from ctypes import wintypes as w

    name = r"\\.\pipe\hd-mcp-test-" + str(os.getpid())
    assert "not found" in _pipe_hint(name)

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateNamedPipeW.restype = w.HANDLE
    k32.CreateNamedPipeW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        w.DWORD,
        w.DWORD,
        w.DWORD,
        w.DWORD,
        w.DWORD,
        w.LPVOID,
    ]
    k32.CreateFileW.restype = w.HANDLE
    k32.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    # One instance only, like a VMware/Hyper-V serial-port pipe.
    server = k32.CreateNamedPipeW(name, 3, 0, 1, 4096, 4096, 0, None)
    client = k32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
    try:
        assert server not in (None, w.HANDLE(-1).value)
        assert client not in (None, w.HANDLE(-1).value)
        assert "pipe busy" in _pipe_hint(name)
    finally:
        k32.CloseHandle(client)
        k32.CloseHandle(server)
