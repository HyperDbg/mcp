"""
* @file ffi.py
* @author munraimix
* @brief ctypes bindings for libhyperdbg. Signatures verified against
*        HyperDbg/HyperDbg: hyperdbg/include/SDK/imports/user/HyperDbgLibImports.h.
* @copyright This project is released under the GNU Public License v3.
*
* Hardening notes (see docs/DESIGN.md §9):
*   - Struct layouts use _pack_ = 1 to match the SDK's #pragma pack(1); sizeof()
*     is asserted at import so a layout drift fails loudly instead of silently
*     returning garbage.
*   - The callback object lifetime is the caller's responsibility (session.py
*     holds a persistent reference). Never pass an inline CFUNCTYPE here.
*   - Loading uses CDLL (the exports are extern "C" __cdecl). Python bitness
*     must match the DLL (x64).
"""

from __future__ import annotations

import os
import sys
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    c_char_p,
    c_int,
    c_ubyte,
    c_uint16,
    c_uint32,
    c_uint64,
    c_void_p,
    c_wchar_p,
    sizeof,
)

from .errors import HyperDbgError, LibraryLoadError

DEFAULT_LIB_NAME = "libhyperdbg.dll" if sys.platform == "win32" else "libhyperdbg.so"


# --------------------------------------------------------------------------- #
# Enums (values verified from SDK headers)
# --------------------------------------------------------------------------- #
class ReadMemoryType:
    """DEBUGGER_READ_MEMORY_TYPE"""

    PHYSICAL = 0
    VIRTUAL = 1


class EditMemoryType:
    """DEBUGGER_EDIT_MEMORY_TYPE"""

    VIRTUAL = 0
    PHYSICAL = 1


class ReadingType:
    """DEBUGGER_READ_READING_TYPE"""

    FROM_KERNEL = 0
    FROM_VMX_ROOT = 1


class AddressMode:
    """DEBUGGER_READ_MEMORY_ADDRESS_MODE"""

    BIT_32 = 0
    BIT_64 = 1


# REGS_ENUM subset (0..119 in the SDK); the general-purpose registers plus RIP.
REGS_ENUM: dict[str, int] = {
    "rax": 0,
    "rcx": 5,
    "rdx": 10,
    "rbx": 15,
    "rsp": 20,
    "rbp": 24,
    "rsi": 28,
    "rdi": 32,
    "r8": 36,
    "r9": 41,
    "r10": 46,
    "r11": 51,
    "r12": 56,
    "r13": 61,
    "r14": 66,
    "r15": 71,
    "rip": 102,
}


# --------------------------------------------------------------------------- #
# Structs - #pragma pack(1)
# --------------------------------------------------------------------------- #
class GUEST_REGS(Structure):
    _pack_ = 1
    _fields_ = [
        (name, c_uint64)
        for name in (
            "rax",
            "rcx",
            "rdx",
            "rbx",
            "rsp",
            "rbp",
            "rsi",
            "rdi",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        )
    ]


class GUEST_EXTRA_REGISTERS(Structure):
    # NOT packed. Verified against BasicTypes.h (this struct is outside the
    # #pragma pack(1) that wraps GUEST_REGS) AND on hardware: the UINT64
    # RFLAGS/RIP are naturally 8-byte aligned, leaving 4 padding bytes after
    # the six 16-bit segment selectors -> RFLAGS at offset 16, RIP at 24,
    # total size 32. Marking this _pack_=1 shifted RFLAGS/RIP by 4 bytes.
    _fields_ = [
        ("cs", c_uint16),
        ("ds", c_uint16),
        ("fs", c_uint16),
        ("gs", c_uint16),
        ("es", c_uint16),
        ("ss", c_uint16),
        ("rflags", c_uint64),
        ("rip", c_uint64),
    ]


# Fail loudly on any layout drift (see DESIGN §9.3).
assert sizeof(GUEST_REGS) == 128, f"GUEST_REGS packing wrong: {sizeof(GUEST_REGS)}"
assert sizeof(GUEST_EXTRA_REGISTERS) == 32, (
    f"GUEST_EXTRA_REGISTERS size wrong: {sizeof(GUEST_EXTRA_REGISTERS)}"
)
assert GUEST_EXTRA_REGISTERS.rflags.offset == 16, "RFLAGS must be 8-byte aligned at offset 16"
assert GUEST_EXTRA_REGISTERS.rip.offset == 24, "RIP must be at offset 24"


# --------------------------------------------------------------------------- #
# Batch C hardware packet structs (RequestStructures.h - NO #pragma pack, so
# natural alignment). Sizes asserted so a layout drift fails loudly.
# --------------------------------------------------------------------------- #
_MAX_IDT_ENTRIES = 256
_MAX_IO_APIC_ENTRIES = 400


class INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS(Structure):
    _fields_ = [
        ("KernelStatus", c_uint32),
        ("IdtEntry", c_uint64 * _MAX_IDT_ENTRIES),
    ]


class IO_APIC_ENTRY_PACKETS(Structure):
    _fields_ = [
        ("ApicBasePa", c_uint64),
        ("ApicBaseVa", c_uint64),
        ("IoIdReg", c_uint32),
        ("IoLl", c_uint32),
        ("IoArbIdReg", c_uint32),
        ("LlLhData", c_uint64 * _MAX_IO_APIC_ENTRIES),
    ]


# enum SMI_OPERATION_REQUEST_TYPE: READ_COUNT=0, TRIGGER_POWER_SMI=1
SMI_READ_COUNT = 0


class SMI_OPERATION_PACKETS(Structure):
    _fields_ = [
        ("SmiOperationType", c_int),
        ("SmiCount", c_uint64),
        ("KernelStatus", c_uint32),
    ]


assert sizeof(INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS) == 8 + _MAX_IDT_ENTRIES * 8
assert sizeof(IO_APIC_ENTRY_PACKETS) == 32 + _MAX_IO_APIC_ENTRIES * 8
assert IO_APIC_ENTRY_PACKETS.LlLhData.offset == 32
assert SMI_OPERATION_PACKETS.SmiCount.offset == 8


# --------------------------------------------------------------------------- #
# Callback type
# --------------------------------------------------------------------------- #
# libhyperdbg emits command output through this callback (the return of
# run_command is only a status code - see DESIGN §2). Verified against
# SDK/headers/DataTypes.h:
#     typedef int (*SendMessageWithParamCallback)(const char * Text);
# i.e. returns int, takes a single C string. The handler MUST return an int
# (0) and MUST NOT raise (see session.py - an exception escaping a ctypes
# callback corrupts the transient thread state).
TextMessageCallback = CFUNCTYPE(c_int, c_char_p)

# run_command / other status-returning commands use this sentinel for success:
#     #define DEBUGGER_OPERATION_WAS_SUCCESSFUL 0xFFFFFFFF
# Failures are 0xc0000... error codes (SDK/headers/ErrorCodes.h).
OPERATION_WAS_SUCCESSFUL = 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# errcheck helpers
# --------------------------------------------------------------------------- #
def _check_bool(result, func, _args):
    """BOOLEAN exports: 0 => failure."""
    if not result:
        raise HyperDbgError(f"{func.__name__} returned FALSE", status_code=result)
    return result


def _check_bool_needs_context(result, func, _args):
    """BOOLEAN exports that require a halted CPU context.

    Verified on hardware: in local VMI mode with nothing paused, register /
    memory / stepping calls return FALSE because there is no frozen guest
    context to act on. Surface that as actionable guidance.
    """
    if not result:
        raise HyperDbgError(
            f"{func.__name__} returned FALSE. In local VMI mode this usually means "
            "execution isn't paused - there is no halted CPU context to read/modify. "
            "Pause the debuggee at an event/breakpoint (or use Debugger Mode) first.",
            status_code=result,
        )
    return result


# --------------------------------------------------------------------------- #
# Prototype configuration
# --------------------------------------------------------------------------- #
def _configure(dll: CDLL) -> None:
    dll.hyperdbg_u_connect_local_debugger.restype = None
    dll.hyperdbg_u_connect_local_debugger.argtypes = []

    # Remote / Debugger-Mode connect (serial, named pipe, network). BOOLEAN.
    dll.hyperdbg_u_connect_remote_debugger_using_com_port.restype = c_ubyte
    dll.hyperdbg_u_connect_remote_debugger_using_com_port.argtypes = [
        c_char_p,  # port_name (e.g. "com4")
        c_uint32,  # DWORD baudrate
        c_ubyte,  # BOOLEAN pause_after_connection
    ]
    dll.hyperdbg_u_connect_remote_debugger_using_named_pipe.restype = c_ubyte
    dll.hyperdbg_u_connect_remote_debugger_using_named_pipe.argtypes = [c_char_p, c_ubyte]
    # `.debug remote ... reattach` (HyperDbg PR #701): absent from older builds.
    reattach_pipe = getattr(dll, "hyperdbg_u_reattach_remote_debugger_using_named_pipe", None)
    if reattach_pipe is not None:
        reattach_pipe.restype = c_ubyte
        reattach_pipe.argtypes = [c_char_p, c_ubyte]
    reattach_com = getattr(dll, "hyperdbg_u_reattach_remote_debugger_using_com_port", None)
    if reattach_com is not None:
        reattach_com.restype = c_ubyte
        reattach_com.argtypes = [c_char_p, c_uint32, c_ubyte]
    dll.hyperdbg_u_connect_remote_debugger.restype = c_ubyte
    dll.hyperdbg_u_connect_remote_debugger.argtypes = [c_char_p, c_char_p]  # ip, port
    dll.hyperdbg_u_debug_close_remote_debugger.restype = c_ubyte
    dll.hyperdbg_u_debug_close_remote_debugger.argtypes = []

    # INT status: 0 on success, an 0xC0000xxx error code on failure (see
    # session._is_error_status, which compares the low 32 bits).
    dll.hyperdbg_u_run_command.restype = c_int
    dll.hyperdbg_u_run_command.argtypes = [c_char_p]

    dll.hyperdbg_u_set_text_message_callback.restype = None
    dll.hyperdbg_u_set_text_message_callback.argtypes = [TextMessageCallback]

    dll.hyperdbg_u_read_memory.restype = c_ubyte
    dll.hyperdbg_u_read_memory.argtypes = [
        c_uint64,  # target_address
        c_int,  # DEBUGGER_READ_MEMORY_TYPE
        c_int,  # DEBUGGER_READ_READING_TYPE
        c_uint32,  # pid
        c_uint32,  # size
        c_ubyte,  # get_address_mode
        POINTER(c_int),  # DEBUGGER_READ_MEMORY_ADDRESS_MODE*
        POINTER(c_ubyte),  # target_buffer
        POINTER(c_uint32),  # return_length
    ]
    dll.hyperdbg_u_read_memory.errcheck = _check_bool_needs_context

    dll.hyperdbg_u_write_memory.restype = c_ubyte
    dll.hyperdbg_u_write_memory.argtypes = [
        c_void_p,  # destination_address
        c_int,  # DEBUGGER_EDIT_MEMORY_TYPE
        c_uint32,  # process_id
        c_void_p,  # source_address
        c_uint32,  # number_of_bytes
    ]
    dll.hyperdbg_u_write_memory.errcheck = _check_bool_needs_context

    dll.hyperdbg_u_read_all_registers.restype = c_ubyte
    dll.hyperdbg_u_read_all_registers.argtypes = [
        POINTER(GUEST_REGS),
        POINTER(GUEST_EXTRA_REGISTERS),
    ]
    dll.hyperdbg_u_read_all_registers.errcheck = _check_bool_needs_context

    dll.hyperdbg_u_read_target_register.restype = c_ubyte
    dll.hyperdbg_u_read_target_register.argtypes = [c_int, POINTER(c_uint64)]
    dll.hyperdbg_u_read_target_register.errcheck = _check_bool_needs_context

    dll.hyperdbg_u_write_target_register.restype = c_ubyte
    dll.hyperdbg_u_write_target_register.argtypes = [c_int, c_uint64]
    dll.hyperdbg_u_write_target_register.errcheck = _check_bool_needs_context

    dll.hyperdbg_u_set_breakpoint.restype = c_ubyte
    dll.hyperdbg_u_set_breakpoint.argtypes = [c_uint64, c_uint32, c_uint32, c_uint32]
    dll.hyperdbg_u_set_breakpoint.errcheck = _check_bool

    dll.hyperdbg_u_continue_debuggee.restype = None
    dll.hyperdbg_u_continue_debuggee.argtypes = []

    dll.hyperdbg_u_pause_debuggee.restype = None
    dll.hyperdbg_u_pause_debuggee.argtypes = []

    for step_fn in (
        "hyperdbg_u_stepping_instrumentation_step_in",
        "hyperdbg_u_stepping_regular_step_in",
        "hyperdbg_u_stepping_step_over",
    ):
        fn = getattr(dll, step_fn)
        fn.restype = c_ubyte
        fn.argtypes = []
        fn.errcheck = _check_bool_needs_context

    dll.hyperdbg_u_eval_expression.restype = c_uint64
    dll.hyperdbg_u_eval_expression.argtypes = [c_char_p, POINTER(c_ubyte)]

    dll.hyperdbg_u_run_script.restype = c_ubyte
    dll.hyperdbg_u_run_script.argtypes = [c_char_p, c_ubyte]
    dll.hyperdbg_u_run_script.errcheck = _check_bool

    # Assembler (Batch C): encode x86-64 mnemonics to machine code.
    dll.hyperdbg_u_assemble_get_length.restype = c_ubyte
    dll.hyperdbg_u_assemble_get_length.argtypes = [c_char_p, c_uint64, POINTER(c_uint32)]
    dll.hyperdbg_u_assemble.restype = c_ubyte
    dll.hyperdbg_u_assemble.argtypes = [c_char_p, c_uint64, c_void_p, c_uint32]

    # Structured hardware reads (Batch C).
    dll.hyperdbg_u_get_idt_entry.restype = c_ubyte
    dll.hyperdbg_u_get_idt_entry.argtypes = [POINTER(INTERRUPT_DESCRIPTOR_TABLE_ENTRIES_PACKETS)]
    dll.hyperdbg_u_get_idt_entry.errcheck = _check_bool
    dll.hyperdbg_u_get_io_apic.restype = c_ubyte
    dll.hyperdbg_u_get_io_apic.argtypes = [POINTER(IO_APIC_ENTRY_PACKETS)]
    dll.hyperdbg_u_get_io_apic.errcheck = _check_bool
    dll.hyperdbg_u_perform_smi_operation.restype = c_ubyte
    dll.hyperdbg_u_perform_smi_operation.argtypes = [POINTER(SMI_OPERATION_PACKETS)]
    dll.hyperdbg_u_perform_smi_operation.errcheck = _check_bool

    # --- module / VMM lifecycle + diagnostics (no errcheck: INT status vary) ---
    dll.hyperdbg_u_detect_vmx_support.restype = c_ubyte
    dll.hyperdbg_u_detect_vmx_support.argtypes = []

    dll.hyperdbg_u_is_any_module_loaded.restype = c_ubyte
    dll.hyperdbg_u_is_any_module_loaded.argtypes = []

    dll.hyperdbg_u_install_kd_driver.restype = c_int  # 0 = ok, 1 = failed
    dll.hyperdbg_u_install_kd_driver.argtypes = []
    dll.hyperdbg_u_load_vmm.restype = c_int
    dll.hyperdbg_u_load_vmm.argtypes = []

    dll.hyperdbg_u_unload_kd.restype = c_int
    dll.hyperdbg_u_unload_kd.argtypes = []
    dll.hyperdbg_u_unload_vmm.restype = c_int
    dll.hyperdbg_u_unload_vmm.argtypes = []

    dll.hyperdbg_u_unset_text_message_callback.restype = None
    dll.hyperdbg_u_unset_text_message_callback.argtypes = []

    # --- Batch B: simple SDK-typed exports ---
    dll.hyperdbg_u_get_kernel_base.restype = c_uint64
    dll.hyperdbg_u_get_kernel_base.argtypes = []

    dll.hyperdbg_u_get_processor_vendor.restype = c_int  # GENERIC_PROCESSOR_VENDOR
    dll.hyperdbg_u_get_processor_vendor.argtypes = []

    dll.hyperdbg_u_load_all_modules.restype = c_int
    dll.hyperdbg_u_load_all_modules.argtypes = []
    dll.hyperdbg_u_unload_all_modules.restype = c_int
    dll.hyperdbg_u_unload_all_modules.argtypes = []

    dll.hyperdbg_u_enable_transparent_mode_ex.restype = c_ubyte
    dll.hyperdbg_u_enable_transparent_mode_ex.argtypes = [c_uint32, c_char_p, c_ubyte, c_uint32]
    dll.hyperdbg_u_disable_transparent_mode.restype = c_ubyte
    dll.hyperdbg_u_disable_transparent_mode.argtypes = []

    dll.hyperdbg_u_start_process.restype = c_ubyte
    dll.hyperdbg_u_start_process.argtypes = [c_wchar_p]
    dll.hyperdbg_u_start_process_with_args.restype = c_ubyte
    dll.hyperdbg_u_start_process_with_args.argtypes = [c_wchar_p, c_wchar_p]

    dll.hyperdbg_u_stepping_step_over_for_gu.restype = c_ubyte
    dll.hyperdbg_u_stepping_step_over_for_gu.argtypes = [c_ubyte]
    dll.hyperdbg_u_stepping_step_over_for_gu.errcheck = _check_bool_needs_context
    dll.hyperdbg_u_stepping_instrumentation_step_in_for_tracking.restype = c_ubyte
    dll.hyperdbg_u_stepping_instrumentation_step_in_for_tracking.argtypes = []
    dll.hyperdbg_u_stepping_instrumentation_step_in_for_tracking.errcheck = (
        _check_bool_needs_context
    )

    # Transparent-mode evasion-mask bits (EvadeMask); ALL = 0x1F.
    #   SYSCALL_HOOK=0x01 CPUID=0x02 MSR=0x04 TRAP_FLAG=0x08 RIP_OVERFLOW=0x10


def load_libhyperdbg(path: str | None = None) -> CDLL:
    """Load and configure libhyperdbg.

    Resolution order: explicit ``path`` -> ``HYPERDBG_LIB_PATH`` env -> the
    platform default name on the loader search path.
    """
    resolved = path or os.environ.get("HYPERDBG_LIB_PATH") or DEFAULT_LIB_NAME

    # libhyperdbg depends on sibling DLLs (hyperhv, hyperlog, ...). When a full
    # path is given, register its directory so the loader can resolve those
    # dependencies (plain LoadLibrary does not search the DLL's own dir).
    if sys.platform == "win32":
        lib_dir = os.path.dirname(os.path.abspath(resolved))
        if os.path.isdir(lib_dir):
            try:
                os.add_dll_directory(lib_dir)
            except OSError:
                pass
            # HyperDbg also loads DLLs at run time with a plain LoadLibrary, which
            # ignores add_dll_directory: pdbex's LoadLibrary("msdia140.dll") then
            # fails under python.exe and `dt` / `struct` print nothing.
            import ctypes

            ctypes.windll.kernel32.SetDllDirectoryW(lib_dir)

    try:
        dll = CDLL(resolved)
    except OSError as exc:  # missing file, wrong bitness, unmet deps
        raise LibraryLoadError(
            f"Could not load libhyperdbg from {resolved!r}: {exc}. "
            "Confirm HyperDbg is installed, the path/HYPERDBG_LIB_PATH is correct, "
            "and Python bitness matches the DLL (x64)."
        ) from exc
    _configure(dll)
    _use_driver_next_to_dll(dll)
    return dll


def _use_driver_next_to_dll(dll: CDLL) -> None:
    """Point libhyperdbg at the hyperkd.sys shipped beside the DLL.

    libhyperdbg looks for its driver next to the process EXE (GetModuleHandle
    (NULL)): fine for hyperdbg-cli.exe, but under Python that is python.exe's
    folder, so `load vmm` fails with "target file is not loaded".
    """
    if sys.platform != "win32":
        return
    import ctypes

    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetModuleFileNameW(ctypes.c_void_p(dll._handle), buf, len(buf)):
        return
    driver = os.path.join(os.path.dirname(buf.value), "hyperkd.sys")
    if os.path.isfile(driver):
        dll.hyperdbg_u_set_custom_driver_path.restype = c_ubyte
        dll.hyperdbg_u_set_custom_driver_path.argtypes = [c_char_p, c_char_p]
        dll.hyperdbg_u_set_custom_driver_path(driver.encode("mbcs"), b"hyperkd")


SCRIPT_ENGINE_LIB_NAME = "script-engine.dll" if sys.platform == "win32" else "libscript-engine.so"


class SYMBOL_BUFFER(Structure):
    """script-engine's parse result (ScriptEngineCommonDefinitions.h)."""

    _fields_ = [
        ("Head", c_void_p),
        ("Pointer", c_uint32),
        ("Size", c_uint32),
        ("Message", c_void_p),  # char *: NULL when the script parsed
    ]


def load_script_engine() -> CDLL | None:
    """The script-engine library libhyperdbg already loaded, for its parser.

    ScriptEngineParse only parses (and resolves symbols); it runs nothing, so
    the server can check a script's syntax before it reaches the target. None
    if the library can't be found: the check is then skipped.
    """
    try:
        lib = CDLL(SCRIPT_ENGINE_LIB_NAME)
    except OSError:
        return None
    lib.ScriptEngineParse.restype = POINTER(SYMBOL_BUFFER)
    lib.ScriptEngineParse.argtypes = [c_char_p]
    lib.RemoveSymbolBuffer.restype = None
    lib.RemoveSymbolBuffer.argtypes = [POINTER(SYMBOL_BUFFER)]
    return lib
