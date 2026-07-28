# Candidate HyperDbg contribution: serial resync on framing overflow

Upstream issue: https://github.com/HyperDbg/HyperDbg/issues/661 (PR to `Dev`
should reference it with `Fixes #661`).

Stops the debuggee flooding "buffer exceeds the buffer limitation" (and wedging
its KD driver) when the debugger drops a serial link uncleanly.

Files:
- `hyperdbg/hyperkd/code/debugger/communication/SerialConnection.c`
- `hyperdbg/include/SDK/headers/Constants.h` (one new bound, beside the existing
  end-of-buffer constants)

Target branch: `Dev`. License: GPLv3.

## Problem

`SerialConnectionRecvBuffer()` frames packets by reading bytes until it sees the
4-byte marker `SERIAL_END_OF_BUFFER_CHAR_1..4`, bounded only by
`MaxSerialPacketSize`. On overflow it logs and returns `FALSE`. The caller,
`KdDispatchAndPerformCommandsFromDebugger()` in `Kd.c`, treats `FALSE` as a
normal validation miss and calls `SerialConnectionRecvBuffer()` again. If the
stream is desynced (the debugger went away mid-frame without sending the close
packet), the next call overflows immediately on the residual bytes, so the log
floods and the session wedges. On the following reconnect the KD driver can then
fail to reinstall (`DeleteService failed (430)`, "marked for delete"), needing a
reboot.

There is no length header and no resync, so the receiver cannot re-align on its
own.

## Context: HyperDbg already has a clean-disconnect packet

`DEBUGGER_REMOTE_PACKET_REQUESTED_ACTION_ON_VMX_ROOT_MODE_CLOSE_AND_UNLOAD_DEBUGGEE`
already exists (Connection.h) and is handled on the debuggee by
`KdCloseConnectionAndUnloadDebuggee()`; the host sends it from
`KdCloseConnection()` / `hyperdbg_u_debug_close_remote_debugger`. The flood only
happens when the host never sends that packet (process killed, terminal closed,
cable pulled). So this change is the debuggee's defence for the case where a
clean close never arrives. The complementary half is host-side (always send the
close packet on teardown), which a controller such as an MCP server should do,
and which is out of scope for this driver change.

## Fix

Add a bounded resync at the framing layer and log the desync once per episode
instead of every iteration. No header change (the helper stays file-local like
its siblings `SerialConnectionCheckForTheEndOfTheBuffer` and
`SerialConnectionSendEndOfBuffer`). No change to the caller or the return
contract.

### 1. Constants.h, beside the end-of-buffer definitions

```c
//
// Maximum number of bytes to discard while resyncing the serial stream to the
// next end-of-buffer marker after a framing overflow. Bounded so a dead link
// cannot spin forever.
//
#define SERIAL_RESYNC_MAX_BYTES (MaxSerialPacketSize * 4)
```

### 2. SerialConnection.c, file scope

```c
//
// Set when the serial stream desyncs so the warning is logged once per episode
// (cleared on the next good frame) rather than on every overflow.
//
static BOOLEAN g_SerialConnectionDesyncReported = FALSE;
```

### 3. SerialConnection.c, new helper before SerialConnectionRecvBuffer

```c
/**
 * @brief Discard bytes until the next end-of-buffer marker, re-aligning the
 * stream to a frame boundary after a desync
 *
 * @return BOOLEAN TRUE if a marker was found (stream re-aligned), FALSE if too
 * many bytes arrived without one (treat the link as dead)
 */
BOOLEAN
SerialConnectionResyncToNextFrame()
{
    BYTE   Window[4] = {NULL_ZERO, NULL_ZERO, NULL_ZERO, NULL_ZERO};
    UINT32 Discarded = 0;

    while (Discarded < SERIAL_RESYNC_MAX_BYTES)
    {
        UCHAR RecvChar = NULL_ZERO;

        if (!KdHyperDbgRecvByte(&RecvChar))
        {
            continue;
        }

        Window[0] = Window[1];
        Window[1] = Window[2];
        Window[2] = Window[3];
        Window[3] = RecvChar;
        Discarded++;

        if (Window[0] == SERIAL_END_OF_BUFFER_CHAR_1 &&
            Window[1] == SERIAL_END_OF_BUFFER_CHAR_2 &&
            Window[2] == SERIAL_END_OF_BUFFER_CHAR_3 &&
            Window[3] == SERIAL_END_OF_BUFFER_CHAR_4)
        {
            return TRUE;
        }
    }

    return FALSE;
}
```

### 4. SerialConnection.c, modified SerialConnectionRecvBuffer

```c
BOOLEAN
SerialConnectionRecvBuffer(CHAR *   BufferToSave,
                           UINT32 * LengthReceived)
{
    UINT32 Loop = 0;

    while (TRUE)
    {
        UCHAR RecvChar = NULL_ZERO;

        if (!KdHyperDbgRecvByte(&RecvChar))
        {
            continue;
        }

        if (!(MaxSerialPacketSize > Loop))
        {
            //
            // Overflowed without an end-of-buffer marker: the stream is
            // desynced (the debugger most likely dropped the link mid-frame
            // without sending the close packet). Returning FALSE here sends
            // the caller straight back into the same desynced stream, which
            // overflows again at once and floods the log. Log once per episode
            // and resync to the next frame boundary instead.
            //
            if (!g_SerialConnectionDesyncReported)
            {
                LogWarning("Warning, serial stream desynced (exceeded the buffer "
                           "limitation with no end marker); resyncing to the next frame");
                g_SerialConnectionDesyncReported = TRUE;
            }

            if (!SerialConnectionResyncToNextFrame())
            {
                //
                // Too many bytes without a marker: treat the link as dead.
                //
                return FALSE;
            }

            Loop = 0;
            continue;
        }

        BufferToSave[Loop] = RecvChar;

        if (SerialConnectionCheckForTheEndOfTheBuffer(&Loop, (BYTE *)BufferToSave))
        {
            break;
        }

        Loop++;
    }

    //
    // A full frame arrived, so the stream is back in sync.
    //
    g_SerialConnectionDesyncReported = FALSE;

    *LengthReceived = Loop;

    return TRUE;
}
```

## Why here

- All framing lives in SerialConnection.c; the caller already retries on
  `FALSE` the same way it handles every other validation miss, so recovery
  belongs at this layer and the caller stays unchanged.
- The helper matches the file's existing internal helpers: defined in the `.c`,
  not declared in `SerialConnection.h`.
- `SERIAL_RESYNC_MAX_BYTES` sits in Constants.h with the other serial protocol
  constants (`MaxSerialPacketSize`, `SERIAL_END_OF_BUFFER_CHAR_*`).
- `LogWarning` fits a recoverable, transient condition; `LogError` is used for
  unrecoverable ones. The once-per-episode flag stops the flood without a timer
  or a magic threshold.

## Build and test

1. Branch off `Dev` in a fork, apply the above.
2. Build `hyperkd.sys` (VS + WDK, the HyperDbg CMake build).
3. Replace `hyperkd.sys` on the debuggee, boot with DSE off.
4. Bring up the serial rig, connect a debugger.
5. Kill the debugger host mid-session (close the terminal or kill the process).
   Expected: one `LogWarning` line, then the debuggee resyncs on the next
   `.debug prepare` / reconnect. No flood, no wedged driver.

## Issue text (post first, then reference it from the PR)

Title: Debuggee floods "buffer exceeds the buffer limitation" and cannot resync
after an unclean serial disconnect

Body:

> Component: hyperkd, SerialConnection.c (SerialConnectionRecvBuffer). Mode:
> Debugger Mode over serial.
>
> If the debugger side drops the serial link uncleanly mid-frame (terminal
> closed, controller process killed, or a client that exits without sending an
> end-of-buffer), the debuggee spins forever logging "buffer exceeds the buffer
> limitation" and the session wedges. On the next reconnect the KD driver can
> fail to reinstall (DeleteService failed (430) / marked for delete), needing a
> reboot.
>
> Root cause: SerialConnectionRecvBuffer uses delimiter-only framing bounded by
> MaxSerialPacketSize. On overflow it logs and returns FALSE, and the Kd.c
> dispatch loop calls it again into the still-desynced stream, so it overflows
> again at once. There is no resync to a frame boundary.
>
> HyperDbg already has the clean path (CLOSE_AND_UNLOAD packet handled by
> KdCloseConnectionAndUnloadDebuggee); this is only about the case where that
> packet never arrives.
>
> Proposed fix: on overflow, log once per episode (LogWarning) and discard bytes
> to the next end-of-buffer marker to re-align, bounded, then start a fresh
> frame. Framing and protocol unchanged. I have a patch ready and can open a PR
> against Dev.
