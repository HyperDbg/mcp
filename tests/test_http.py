"""
* @file test_http.py
* @brief --transport http: bearer auth, and one session shared across clients.
* @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

pytest.importorskip("mcp")
uvicorn = pytest.importorskip("uvicorn")
httpx2 = pytest.importorskip("httpx2")

from mcp import Client  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

from hyperdbg_mcp import server  # noqa: E402
from hyperdbg_mcp.transport_http import build_http_app, check_token  # noqa: E402

TOKEN = "t" * 40


class CountingSession:
    created = 0

    def __init__(self):
        CountingSession.created += 1
        self.statuses = 0

    def close(self):
        pass

    def run_command(self, command):
        self.statuses += 1
        return f"status #{self.statuses}"


@pytest.fixture
def http_server(tmp_path):
    CountingSession.created = 0
    srv = server.build_server(
        read_only=True,
        lib_path=None,
        audit_path=str(tmp_path / "audit.jsonl"),
        session_factory=CountingSession,
    )
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    app = build_http_app(srv, host="127.0.0.1", token=TOKEN)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not uv.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    uv.should_exit = True
    thread.join(10)


def _client(url, token=TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return Client(streamable_http_client(url, http_client=httpx2.AsyncClient(headers=headers)))


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")


@pytest.mark.parametrize("token", [None, "wrong-" + TOKEN])
def test_requests_without_the_token_are_rejected(http_server, token):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    r = httpx2.post(http_server, json=body, headers=headers)
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")


async def test_debugger_session_outlives_client_reconnects(http_server):
    # The point of HTTP mode: client restarts don't restart the debugger.
    for expected in ("status #1", "status #2"):
        async with _client(http_server) as client:
            result = await client.call_tool("hd_status", {})
        assert expected in _text(result)
    assert CountingSession.created == 1


@pytest.mark.parametrize("token", [None, "", "short"])
def test_http_mode_refuses_to_start_without_a_real_token(token):
    with pytest.raises(SystemExit):
        check_token(token)


def test_log_file_captures_native_output(tmp_path):
    # Run in a child: the option redirects the process's own fds.
    import subprocess
    import sys

    log = tmp_path / "server.log"
    code = (
        "import os, sys; from hyperdbg_mcp.server import _log_to_file; "
        f"_log_to_file({str(log)!r}, stdout_too=True); "
        "os.write(1, b'native stdout\\n'); os.write(2, b'native stderr\\n')"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
    text = log.read_text()
    assert "hyperdbg-mcp starting" in text
    assert "native stdout" in text and "native stderr" in text
