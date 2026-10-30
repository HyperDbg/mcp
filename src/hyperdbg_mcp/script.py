"""
* @file script.py
* @author munraimix
* @brief HyperDbg script-engine helpers: a light lexer, the read-only script
*        check, event-script templates, parse-error formatting and the cookbook.
* @copyright This project is released under the GNU Public License v3.
*
* The engine itself (libhyperdbg/script-engine) is the authority on syntax:
* HyperDbgSession.check_script() runs its parser before anything is sent. The
* checks here only decide what a script is *allowed* to do, so they reject
* anything they cannot prove is read-only instead of trying to parse it fully.
"""

from __future__ import annotations

import re
from typing import Literal, get_args

from .errors import HyperDbgError

# Functions that read target memory (script-engine/python/Grammar.txt). In
# local VMI mode with no paused process the engine runs them in the MCP
# server's own process, so their results mean nothing there.
MEMORY_FUNCTIONS = frozenset(
    """poi db dd dw dq hi low check_address disassemble_len disassemble_len32
    disassemble_len64 physical_to_virtual virtual_to_physical poi_pa hi_pa low_pa
    db_pa dd_pa dw_pa dq_pa strlen wcslen strcmp wcscmp memcmp strncmp wcsncmp""".split()
)
# Functions with no side effects. Everything else (eb/ed/eq, memcpy,
# interlocked_*, event_*, pause, spinlock_*, lbr_*...) writes memory or changes
# debugger state.
PURE_FUNCTIONS = MEMORY_FUNCTIONS | frozenset("neg not reference rdtsc rdtscp".split())
PRINT_FUNCTIONS = frozenset("printf print formats".split())
PSEUDO_REGISTERS = frozenset(
    """pid tid pname core proc thread peb teb ip buffer context event_tag event_id
    event_stage date time""".split()
)
# Words followed by `(` that are not function calls.
_KEYWORDS = frozenset("if while for do switch sizeof return else".split())

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
   |(?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))
   |(?P<str>L?"(?:[^"\\\n]|\\.)*"?)
   |(?P<sym>[A-Za-z_]\w*![A-Za-z_?@$][\w?@$]*)
   |(?P<id>[@$.]?[A-Za-z_]\w*)
   |(?P<num>[0-9][\w`]*(?:\.[0-9]+)?)
   |(?P<op><<=|>>=|->|\+\+|--|==|!=|<=|>=|&&|\|\||<<|>>|[-+*/%&|^]=|.)
    """,
    re.X | re.S,
)
_ASSIGN_OPS = frozenset("= += -= *= /= %= &= |= ^= <<= >>=".split())
_STATEMENT_START = frozenset("; { } ( ,".split())
_PLAIN = re.compile(r"[A-Za-z_]\w*")


def tokens(script: str) -> list[str]:
    """Split a script into tokens, dropping whitespace and comments."""
    out = []
    for m in _TOKEN.finditer(script):
        if m.lastgroup not in ("ws", "comment"):
            out.append(m.group())
    return out


def _is_plain(tok: str) -> bool:
    return bool(_PLAIN.fullmatch(tok)) and tok not in _KEYWORDS


def _defined_functions(toks: list[str]) -> set[str]:
    """Names the script defines itself (`type name(...) {`)."""
    names = set()
    for i, tok in enumerate(toks):
        if i == 0 or toks[i + 1 : i + 2] != ["("] or not _is_plain(tok):
            continue
        if not _is_plain(toks[i - 1]):
            continue
        depth, j = 0, i + 1
        while j < len(toks):
            depth += {"(": 1, ")": -1}.get(toks[j], 0)
            if depth == 0:
                break
            j += 1
        if toks[j + 1 : j + 2] == ["{"]:
            names.add(tok)
    return names


def _what_lvalue_writes(lhs: list[str]) -> str | None:
    """Why assigning to `lhs` is not a plain local variable, or None."""
    if not lhs:
        return "an assignment with nothing on its left"
    target = lhs[-1]
    if target.startswith("@"):
        return f"assigning to {target} writes a register"
    if target.startswith(".") and len(lhs) > 1 and _PLAIN.fullmatch(lhs[-2]):
        return f"assigning to {lhs[-2]}{target} writes a struct member"
    if target.startswith("."):
        return f"assigning to {target} writes a global variable"
    if target.startswith("$"):
        return f"assigning to {target} writes a pseudo-register"
    if lhs[0] == "*" or any(t in ("->", "[", "]", ".") for t in lhs):
        return "assigning through a pointer, member or index writes memory"
    if not all(_is_plain(t) or t == "*" for t in lhs) or not _is_plain(target):
        return f"assigning to {' '.join(lhs)!r} is not a plain local variable"
    return None


def read_only_script(script: str) -> str:
    """Require a script that only reads and prints (for read-only tools).

    Allowed: local variables, if/while/for, functions the script defines,
    the reading functions (poi, db..dq, *_pa, strlen, ...) and printf/print.
    Refused: anything that writes a register, global, memory or debugger state,
    and #include (it reads files on the debugger host).
    """
    if not script.strip():
        raise HyperDbgError("the script is empty")
    toks = tokens(script)
    defined = _defined_functions(toks)
    allowed = PURE_FUNCTIONS | PRINT_FUNCTIONS | defined
    hint = " (not allowed in a read-only script; use hd_script_run)"
    for i, tok in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        prev = toks[i - 1] if i else ""
        if tok == "#":
            raise HyperDbgError("#include reads a file on the debugger host" + hint)
        if nxt == "(" and _PLAIN.fullmatch(tok) and tok not in _KEYWORDS:
            if tok not in allowed:
                raise HyperDbgError(f"function {tok}() writes or changes state" + hint)
        elif tok in _ASSIGN_OPS:
            start = i
            while start > 0 and toks[start - 1] not in _STATEMENT_START:
                start -= 1
            why = _what_lvalue_writes(toks[start:i])
            if why:
                raise HyperDbgError(why + hint)
        elif tok in ("++", "--"):
            postfix = bool(prev) and (_PLAIN.fullmatch(prev) or prev[0] in "@$." or prev in ")]")
            operand = prev if postfix else nxt
            if postfix:
                around = toks[i - 2] if i >= 2 else ""
            else:
                around = toks[i + 2] if i + 2 < len(toks) else ""
            if not _is_plain(operand) or around in ("->", "[", "."):
                why = _what_lvalue_writes([operand]) or "increments something that is not a local"
                raise HyperDbgError(f"{tok} {why}" + hint)
    return script


def needs_target_context(script: str) -> list[str]:
    """What in the script reads registers or memory of the target, if anything."""
    found = []
    for tok in tokens(script):
        if tok.startswith("@") and len(tok) > 1:
            found.append(tok)
        elif tok.startswith("$") and tok[1:] in PSEUDO_REGISTERS:
            found.append(tok)
        elif tok in MEMORY_FUNCTIONS:
            found.append(f"{tok}()")
    return list(dict.fromkeys(found))


_PARSE_HINTS = {
    "Unresolved Variable": (
        "a name that is not a variable, symbol or function. A variable must be "
        "assigned earlier in the same script before it is read - a global too: "
        "`if (0) { .n = 0; }` declares .n without resetting it. Globals start with "
        "'.', registers with '@' (@rax), pseudo-registers with '$' ($pid)."
    ),
    "Unknown Token": (
        "a character the engine does not know. Numbers are hex by default (0n10 is "
        "decimal); strings use double quotes."
    ),
    "Undefined Function": (
        "no such function. See hd_script_cookbook for the list."
    ),
    "Invalid Syntax": (
        "end every statement with ';', balance the parentheses and braces, and write "
        "if/while/for bodies in { }."
    ),
}
_WORD_AT = re.compile(r"[A-Za-z_]\w*")
_HEX_WORD = re.compile(r"[0-9a-fA-F]+")
_SYMBOL_AT = re.compile(r"[A-Za-z_]\w*![\w?@$]+")
_PARSE_MESSAGE = re.compile(r"Line (\d+):\n(.*)\n( *)\^\n(.*)", re.S)


def format_parse_error(message: str, script: str = "") -> str:
    """Turn the engine's `Line N:\\n<src>\\n   ^\\nCause` into one readable error.

    The engine counts lines from 0; this says line 1 for the first one. After
    the first line its excerpt also starts one character late (the scanner has
    read ahead when it records the line start): with the script at hand, the
    real line is shown and the column moved to match.
    """
    m = _PARSE_MESSAGE.match(message.strip("\n"))
    if not m:
        return f"script error: {message.strip()}"
    line, source, pad, cause = m.groups()
    lines = script.splitlines()
    real = lines[int(line)] if int(line) < len(lines) else ""
    if source and real != source and real.endswith(source):
        pad = " " * (len(real) - len(source) + len(pad))
        source = real
    cause = cause.strip()
    text = (
        f"script error at line {int(line) + 1}, column {len(pad) + 1}: {cause}\n"
        f"  {source}\n  {pad}^"
    )
    symbol = _SYMBOL_AT.match(source, len(pad))
    word = _WORD_AT.match(source, len(pad))
    if word and _HEX_WORD.fullmatch(word.group()):
        hint = (
            f"{word.group()!r} reads as the hex number 0x{word.group()}: numbers are hex "
            "by default, so a name made only of hex digits (a, b, add, cafe) is a "
            "number. Rename it."
        )
    elif symbol:
        hint = (
            f"{symbol.group()} is not a known symbol: check the name (hd_sym_examine) "
            "and that symbols are loaded (hd_sym_path + hd_sym_reload)."
        )
    else:
        hint = _PARSE_HINTS.get(cause.split(":", 1)[-1].strip())
    return text + (f"\nhint: {hint}" if hint else "")


# --------------------------------------------------------------------------- #
# Event-script templates                                                       #
# --------------------------------------------------------------------------- #
_FIELD_LABEL = re.compile(r"[\w@$!+\-*() ]+")
TemplateKind = Literal["log", "log_if", "count", "break_if", "block_if"]
TEMPLATE_KINDS: tuple[str, ...] = get_args(TemplateKind)


def _field(spec: str, n: int) -> tuple[str, str, str]:
    """(label, printf specifier, expression) for one `fields` entry."""
    fmt = "%llx"
    for prefix, spec_fmt in (("ws:", "%ws"), ("s:", "%s"), ("d:", "%d")):
        if spec.startswith(prefix):
            fmt, spec = spec_fmt, spec[len(prefix) :].strip()
            break
    if not spec:
        raise HyperDbgError(f"field {n}: empty expression")
    read_only_script(spec + ";")
    if any(c in spec for c in ";{}"):
        raise HyperDbgError(f"field {spec!r}: one expression per field")
    label = spec if _FIELD_LABEL.fullmatch(spec) else f"f{n}"
    return label, fmt, spec


def _split_fields(fields: str) -> list[str]:
    """Split on top-level commas only (`poi(@rsp+8)` keeps its own)."""
    out, depth, cur, quoted = [], 0, "", False
    for c in fields:
        if c == '"':
            quoted = not quoted
        elif not quoted and c in "([":
            depth += 1
        elif not quoted and c in ")]":
            depth -= 1
        if c == "," and depth == 0 and not quoted:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def _condition(condition: str) -> str:
    if not condition.strip():
        raise HyperDbgError("this template needs a condition, e.g. @rcx == 0x10")
    read_only_script(f"if ({condition}) {{ }}")
    if any(c in condition for c in ";{}"):
        raise HyperDbgError(f"condition {condition!r}: one expression")
    return condition.strip()


def build_template(
    kind: str, *, fields: str = "", condition: str = "", tag: str = "hit", every: int = 1
) -> str:
    """Build an event script for one of TEMPLATE_KINDS (see hd_script_template)."""
    if kind not in TEMPLATE_KINDS:
        raise HyperDbgError(f"invalid kind {kind!r} (use {' | '.join(TEMPLATE_KINDS)})")
    if not _PLAIN.fullmatch(tag):
        raise HyperDbgError(f"invalid tag {tag!r} (letters, digits, _)")
    if every < 1:
        raise HyperDbgError("every must be at least 1")

    parts = [("core", "%x", "$core"), ("pid", "%x", "$pid"), ("tid", "%x", "$tid")]
    parts.append(("rip", "%llx", "@rip"))
    parts += [_field(f, n) for n, f in enumerate(_split_fields(fields), 1)]
    fmt = " ".join(f"{label}={spec}" for label, spec, _ in parts)
    printf = f'printf("{tag} {fmt}\\n", {", ".join(e for _, _, e in parts)});'

    if kind == "log":
        return printf
    if kind == "log_if":
        return f"if ({_condition(condition)}) {{ {printf} }}"
    if kind == "count":
        var = f".{tag}_hits"
        # The parser only knows a global once something assigns it earlier in
        # the same script; `if (0)` declares it without resetting it per hit.
        return (
            f"if (0) {{ {var} = 0; }} {var} = {var} + 1; "
            f'if ({var} % {every:#x} == 0) {{ printf("{tag} hits=%d\\n", {var}); }}'
        )
    if kind == "break_if":
        return f"if ({_condition(condition)}) {{ {printf} pause(); }}"
    return f"if ({_condition(condition)}) {{ {printf} event_sc(1); }}"


COOKBOOK = """\
# HyperDbg script cookbook (hyperdbg-mcp)

## Where scripts run
- hd_eval(expression)        one read-only expression -> integer.
- hd_script_eval(script)     read-only script; returns what printf prints. No
                             confirmation, available in --read-only.
- hd_script_run(script)      any script (writes allowed); asks for confirmation.
- hook tools, script=...     runs on every hit of the event, in the hypervisor.
                             hd_script_template builds common ones.

Every script is parsed by HyperDbg's own parser before it is sent, so a syntax
error comes back with its line, column and a hint instead of a vague failure.

## Context: local VMI mode vs Debugger Mode
- Debugger Mode (serial/pipe), debuggee halted: everything reads the real target.
- Local VMI mode with a paused user-mode process (hd_process_start or attach):
  scripts run in that process's paused thread (registers, its memory).
- Local VMI mode with no paused process: HyperDbg only *simulates* the engine
  (all registers 0, no target memory). Symbols and arithmetic work; @registers,
  $pseudo-registers and memory functions are refused with an explanation
  instead of silently returning 0. Use hd_mem_read / hd_reg_read there.
- Hook scripts always run at event time on the real target, in any mode.

## Syntax in one screen
    x = 10;                      // locals; numbers are HEX by default
    y = 0n10;                    // 0n = decimal, 0y = binary, 0x = hex
    if (0) { .count = 0; }       // globals start with '.', persist across hits;
    .count = .count + 1;         //   assign one before reading it (see below)
    @rax = 0;                    // registers start with '@'
    printf("pid=%x %s\\n", $pid, @rcx);   // pseudo-registers start with '$'
    if (poi(@rsp) == nt!KiSystemCall64) { print(1); } else { print(2); }
    for (i = 0; i < 4; i++) { printf("%llx\\n", dq(@rsp + i * 8)); }
    while (x != 0) { x = x - 1; }
    int sq(int x) { return x * x; }   // user-defined functions

printf specifiers: %llx %x %d %s (char*) %ws (wchar_t*) %f.

Two parser rules that trip everyone:
- A name made only of hex digits (a, b, add, cafe, f1) is a NUMBER: `int sq(int a)`
  fails. Use names with other letters (x, n, len, ptr).
- A variable must be assigned earlier in the same script before it is read,
  globals included: `.n = .n + 1;` alone is "Unresolved Variable". Declare it
  with `if (0) { .n = 0; }` (never runs, so the value survives between hits).

## Functions
Read (pure): poi db dw dd dq hi low (memory at an address), *_pa variants
(physical), strlen wcslen strcmp wcscmp strncmp wcsncmp memcmp, check_address,
disassemble_len[32|64], virtual_to_physical, physical_to_virtual, neg, not,
reference, rdtsc, rdtscp.
Print: printf print formats.
Write / state (hd_script_run or hooks only): eb ed eq (and *_pa), memcpy[_pa],
interlocked_*, spinlock_*, pause, flush, microsleep, event_enable/disable/clear,
event_sc (short-circuit: drop the event), event_inject*, event_trace_*, lbr_*.

Pseudo-registers: $pid $tid $pname $core $proc $thread $peb $teb $ip $buffer
$context $event_tag $event_id $event_stage $date $time.

## Rules for hook script= blocks
The script sits inside `script { ... }` on the command line, so: no // or /* */
comments, no backslash outside a string literal, braces balanced.

## Recipes
- Log every hit with arguments:
    hd_script_template(kind="log", fields="@rcx, @rdx, s:@r8")
- Count hits, print every 0x100th:
    hd_script_template(kind="count", tag="ntcreate", every=256)
- Log only one process:      kind="log_if", condition="$pid == 0x1234"
- Drop a syscall for one pid: kind="block_if" (pre-stage event, short_circuit)
- Break into the debugger:   kind="break_if" (Debugger Mode only)
- Read a UNICODE_STRING:     printf("%ws\\n", dq(@rcx + 8));
- Walk a list:  p = poi(nt!PsLoadedModuleList); while (p != nt!PsLoadedModuleList)
                { printf("%llx\\n", p); p = poi(p); }
"""
