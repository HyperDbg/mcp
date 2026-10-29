"""
 * @file errors.py
 * @author munraimix
 * @brief Typed errors for the HyperDbg MCP server.
 * @copyright This project is released under the GNU Public License v3.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError


class HyperDbgError(ToolError):
    """Base error for all HyperDbg / libhyperdbg failures.

    A ToolError, so mcp>=2 returns the message to the model instead of the
    generic "Error executing tool" it uses for unexpected exceptions.

    ``status_code`` carries the raw BOOLEAN/INT returned by libhyperdbg when
    available, so callers (and error-recovery guidance) can branch on it.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class LibraryLoadError(HyperDbgError):
    """libhyperdbg.dll could not be loaded (missing, wrong bitness, deps)."""


class NotConnectedError(HyperDbgError):
    """A tool was invoked before the local debugger session was connected."""


class PreconditionError(HyperDbgError):
    """The debuggee is in the wrong state for this operation (e.g. running)."""
