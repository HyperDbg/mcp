"""Replay answers recorded from a live run (scripts/live_cases.py --record).

tests/data/live holds what the server answered on the test rig (Windows 11,
local VMI mode). Replaying them checks, without a machine, that the parsers
read real HyperDbg output and that every case's expectation in the live suite
still accepts a correct answer, so editing either can't silently break the
live run.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import live_cases  # noqa: E402

from hyperdbg_mcp.session import _reports_failure  # noqa: E402
from hyperdbg_mcp.tools import _first_instructions  # noqa: E402
from hyperdbg_mcp.tools_system import _parse_msr_values  # noqa: E402

FIXTURES = ROOT / "tests" / "data" / "live"
CASES = {c.case_id: c for c in live_cases.cases()}


def _fixture(case_id: str) -> dict:
    path = FIXTURES / f"{case_id}.json"
    if not path.exists():
        pytest.skip(f"no recorded answer for {case_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def _text(case_id: str) -> str:
    return _fixture(case_id)["answers"][-1]["text"]


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.json")), ids=lambda p: p.stem)
def test_recorded_answers_pass_their_case(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    case = CASES.get(data["case"])
    if case is None:
        pytest.skip(f"{data['case']} is no longer a case")
    for answer in data["answers"]:
        assert live_cases.Runner.judge(case, answer["is_error"], answer["text"]) == ""
        # payload() strips the fence around the answer; a JSON answer keeps its
        # own inside a value (e.g. the "hex" of a memory read)
        text = live_cases.payload(answer["text"])
        assert "UNTRUSTED" not in text or text.lstrip().startswith("{")


def test_msr_values_of_every_core():
    text = live_cases.payload(_text("msr-read"))
    values = _parse_msr_values(text)
    assert sorted(values) == list(range(len(values))) and len(values) > 1
    # LSTAR holds the same handler on every core, in kernel space
    assert len(set(values.values())) == 1
    assert next(iter(values.values())) >= 0xFFFFF80000000000
    # the suite's own parser reads the same values
    assert {c: int(v, 16) for c, v in live_cases.parse_msr(text).items()} == values


def test_memory_echo_finds_the_bytes():
    hex_run = live_cases.parse_hex_run(_text("mem-read-kernel"), 16)
    assert hex_run.startswith(live_cases.QUERY_PC_BYTES)


def test_disassembly_cut_keeps_the_label():
    listing = live_cases.payload(_text("disasm-symbol"))
    cut = _first_instructions(listing, 2)
    assert cut.splitlines()[0].endswith("NtQueryPerformanceCounter:")
    assert sum(1 for line in cut.splitlines() if "`" in line.split()[0]) == 2


def test_attach_failure_is_an_error():
    answer = _fixture("process-attach-system")["answers"][-1]
    assert answer["is_error"]
    # the server judged it from HyperDbg's own output, after the progress line
    assert _reports_failure(live_cases.payload(answer["text"]).split("\n", 1)[1])
