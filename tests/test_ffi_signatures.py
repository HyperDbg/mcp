"""
* @file test_ffi_signatures.py
* @brief Every ctypes prototype in ffi.py must match libhyperdbg's SDK header.
* @copyright This project is released under the GNU Public License v3.

tests/data/HyperDbgLibImports.h is hyperdbg/include/SDK/imports/user/
HyperDbgLibImports.h from HyperDbg v0.25.0, the release ffi.py was validated
against on hardware. Refresh it when moving to a newer HyperDbg: a changed
export then fails here instead of corrupting the stack at runtime.
"""

from __future__ import annotations

import ctypes
import re
from pathlib import Path

import pytest

from hyperdbg_mcp import ffi

_HEADER = Path(__file__).parent / "data" / "HyperDbgLibImports.h"

_SCALARS = {
    "BOOLEAN": ctypes.c_ubyte,
    "INT": ctypes.c_int,
    "UINT32": ctypes.c_uint32,
    "DWORD": ctypes.c_uint32,
    "UINT64": ctypes.c_uint64,
    "VOID": None,
}
# C enums are int-sized under MSVC.
_ENUMS = {
    "GENERIC_PROCESSOR_VENDOR",
    "DEBUGGER_READ_MEMORY_TYPE",
    "DEBUGGER_READ_READING_TYPE",
    "DEBUGGER_EDIT_MEMORY_TYPE",
    "DEBUGGER_SHOW_MEMORY_STYLE",
    "REGS_ENUM",
}


def _sdk_prototypes() -> dict[str, tuple[str, list[str]]]:
    src = _HEADER.read_text(encoding="utf-8")
    src = re.sub(r"/\*.*?\*/", "", re.sub(r"//.*", "", src), flags=re.S)
    protos = {}
    pattern = r"IMPORT_EXPORT_LIBHYPERDBG\s+(\w+)\s+(hyperdbg_u_\w+)\s*\(([^)]*)\)\s*;"
    for ret, name, params in re.findall(pattern, src):
        params = " ".join(params.split())
        types = [] if params in ("", "VOID") else [_param_type(p) for p in params.split(",")]
        protos[name] = (ret, types)
    return protos


def _param_type(param: str) -> str:
    """`const CHAR * name` -> `CHAR*`; `UINT32 size` -> `UINT32`; `CHAR * argv[]` -> `CHAR**`."""
    param = param.replace("const ", "").strip()
    stars = param.count("*") + param.count("[]")
    base = param.replace("*", " ").replace("[]", " ").split()[0]
    return base + "*" * stars


def _matches(c_type: str, actual) -> bool:
    if c_type in _ENUMS:
        return actual is ctypes.c_int
    if c_type in _SCALARS:
        return actual is _SCALARS[c_type]
    if c_type == "CHAR*":
        return actual is ctypes.c_char_p
    if c_type == "WCHAR*":
        return actual is ctypes.c_wchar_p
    if c_type.endswith("*") or c_type.startswith("P"):  # PVOID, PBOOLEAN, T*
        return (
            actual is ctypes.c_void_p
            or actual is ffi.TextMessageCallback
            or (isinstance(actual, type) and issubclass(actual, ctypes._Pointer))
        )
    return False


class _RecordingFn:
    def __init__(self, name):
        self.__name__ = name
        self.restype = self.argtypes = self.errcheck = None
        self.configured = False

    def __setattr__(self, key, value):
        if key in ("restype", "argtypes") and value is not None:
            object.__setattr__(self, "configured", True)
        object.__setattr__(self, key, value)


class _RecordingDll:
    def __init__(self):
        self.fns: dict[str, _RecordingFn] = {}

    def __getattr__(self, name):
        if not name.startswith("hyperdbg_u_"):
            raise AttributeError(name)
        return self.fns.setdefault(name, _RecordingFn(name))


_SDK = _sdk_prototypes()
_DLL = _RecordingDll()
ffi._configure(_DLL)


def test_header_parsed():
    assert len(_SDK) >= 70  # v0.25.0 exports 73; a parse regression shows up here


@pytest.mark.parametrize("name", sorted(_DLL.fns))
def test_binding_matches_sdk(name):
    assert name in _SDK, f"{name} is not exported by the SDK header"
    ret, params = _SDK[name]
    fn = _DLL.fns[name]
    assert _matches(ret, fn.restype), f"{name} returns {ret}, bound as {fn.restype}"
    assert fn.argtypes is not None and len(fn.argtypes) == len(params), (
        f"{name} takes {params}, bound as {fn.argtypes}"
    )
    for i, (c_type, actual) in enumerate(zip(params, fn.argtypes, strict=True)):
        assert _matches(c_type, actual), f"{name} arg {i}: {c_type} bound as {actual}"
