"""
* @file mock.py
* @author munraimix
* @brief In-process mock backend implementing the HyperDbgSession interface.
* @copyright This project is released under the GNU Public License v3.
*
* Lets `hyperdbg-mcp --mock` run end-to-end with no libhyperdbg / driver, so
* the MCP tool surface can be exercised by a real client during development.
* Values are deterministic and clearly marked as mock.
"""

from __future__ import annotations

from .errors import HyperDbgError

_REG_DEFAULTS = {
    "rax": 0x1,
    "rcx": 0x2,
    "rdx": 0x3,
    "rbx": 0x4,
    "rsp": 0x7FFFFFFFE000,
    "rbp": 0x7FFFFFFFE100,
    "rsi": 0x5,
    "rdi": 0x6,
    "r8": 0x8,
    "r9": 0x9,
    "r10": 0xA,
    "r11": 0xB,
    "r12": 0xC,
    "r13": 0xD,
    "r14": 0xE,
    "r15": 0xF,
    "rip": 0x140001000,
}


class MockSession:
    """Deterministic stand-in for HyperDbgSession (no native calls)."""

    def __init__(self) -> None:
        self.connected = False
        self._mode: str | None = None
        self._regs = dict(_REG_DEFAULTS)
        self._mem: dict[int, int] = {}

    @property
    def is_connected(self) -> bool:
        return self.connected

    @property
    def mode(self) -> str | None:
        return self._mode

    def connect(self) -> None:
        self.connect_local()

    def connect_local(self) -> None:
        self.connected = True
        self._mode = "local"

    def connect_remote_com(
        self, port_name: str, baudrate: int = 115200, pause: bool = True
    ) -> None:
        self.connected = True
        self._mode = "remote"

    def connect_remote_pipe(self, named_pipe: str, pause: bool = True) -> None:
        self.connected = True
        self._mode = "remote"

    def connect_remote_net(self, ip: str, port: str) -> None:
        self.connected = True
        self._mode = "remote"

    def close(self) -> None:
        self.connected = False
        self._mode = None

    def read_all_registers(self) -> dict[str, int]:
        extra = {"cs": 0x33, "ss": 0x2B, "ds": 0, "es": 0, "fs": 0, "gs": 0, "rflags": 0x202}
        return {**self._regs, **extra}

    def read_register(self, name: str) -> int:
        try:
            return self._regs[name.lower()]
        except KeyError as exc:
            raise HyperDbgError(f"unknown register {name!r}") from exc

    def write_register(self, name: str, value: int) -> None:
        if name.lower() not in self._regs:
            raise HyperDbgError(f"unknown register {name!r}")
        self._regs[name.lower()] = value

    def read_memory(self, address: int, size: int, *, pid: int = 0, virtual: bool = True) -> bytes:
        # Deterministic pattern derived from the address.
        return bytes((address + i) & 0xFF for i in range(size))

    def write_memory_bytes(
        self, address: int, data: bytes, *, pid: int = 0, virtual: bool = True
    ) -> None:
        for i, b in enumerate(data):
            self._mem[address + i] = b

    def run_command(self, command: str) -> str:
        return f"[mock] executed: {command}"

    def run_script(self, script: str) -> None:
        return None

    def eval_expression(self, expr: str) -> int:
        return len(expr)

    def set_breakpoint(self, address: int, *, pid: int = 0, tid: int = 0, core: int = 0) -> None:
        return None

    def continue_debuggee(self) -> None:
        return None

    def pause_debuggee(self) -> None:
        return None

    def step(self, mode: str = "over") -> None:
        if mode not in ("over", "in", "instr"):
            raise HyperDbgError(f"unknown step mode {mode!r}")

    # ----- Batch B / lifecycle surface (so --mock exercises every tool) ---- #
    def detect_vmx_support(self) -> bool:
        return True

    def is_any_module_loaded(self) -> bool:
        return True

    def load_vmm(self) -> None:
        return None

    def unload_vmm(self) -> None:
        return None

    def load_all_modules(self) -> None:
        return None

    def unload_all_modules(self) -> None:
        return None

    def get_processor_vendor(self) -> str:
        return "Intel"

    def get_kernel_base(self) -> int:
        return 0xFFFFF80000000000

    def enable_transparent_mode(
        self, *, pid: int = 0, name: str = "", evade_mask: int = 0x1F
    ) -> None:
        return None

    def disable_transparent_mode(self) -> None:
        return None

    def start_process(self, path: str, args: str = "") -> None:
        return None

    def step_out(self, last_instruction: bool = False) -> None:
        return None

    def step_track(self) -> None:
        return None

    def assemble(self, code: str, address: int = 0) -> bytes:
        return b"\x90"  # nop

    def get_idt_entries(self) -> dict:
        return {"kernel_status": 0, "entries": [0xFFFFF80000001000 + i for i in range(4)]}

    def get_io_apic(self) -> dict:
        return {"base_pa": 0xFEC00000, "base_va": 0xFFFFF80000FEC000, "id": 0, "entries": [0x10000]}

    def smi_count(self) -> int:
        return 42
