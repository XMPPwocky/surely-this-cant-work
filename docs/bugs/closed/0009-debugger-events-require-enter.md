# 0009: Debugger events require Enter keypress to appear

**Reported:** 2026-02-16
**Status:** Closed (2026-02-16)
**Severity:** MEDIUM
**Subsystem:** debugger (user/dbg)

## Symptoms

After running the `suspend` command in the debugger, the user must hit Enter
before the debugger prints "[event] Process suspended". Events appear to be
polled rather than delivered asynchronously. Same problem for breakpoint hit
and process exited events.

## Reproduction Steps

1. `make run`
2. `run /bin/dbg`
3. `attach 6` (attach to the fs process, or any long-running user process)
4. `suspend`
5. Observe: "Suspend requested (waiting for event...)" is printed, but
   "[event] Process suspended" does NOT appear until Enter is pressed.

## Investigation

The bug was reported with the symptom that `[event] Process suspended` did not
appear until the user pressed Enter after running `suspend` in the debugger.

The first step was reading the debugger client source (`user/dbg/src/main.rs`)
alongside the debug protocol definitions (`lib/rvos-proto/src/debug.rs`) and
the kernel debug service (`kernel/src/services/proc_debug.rs`). After reading
the client, the problem was immediately apparent in the main loop structure:
`poll_events()` used a non-blocking `try_recv`, followed unconditionally by a
blocking `stdin.read_line()`. The polling happened only at the top of the loop,
so any event arriving while blocked on stdin would be silently queued.

To confirm the fix direction, the kernel's channel poll infrastructure was
examined. A search for `sys_chan_poll_add` and `sys_block` confirmed that the
OS already had an `epoll`-style mechanism: `sys_chan_poll_add` registers a
channel of interest, then `sys_block` sleeps until any registered channel has
data. The fbcon window client (`user/fbcon/src/main.rs`) was read as a reference
implementation of this poll/block pattern, since it already multiplexes a
window-server event channel and a keyboard input channel.

The next question was how to replace `stdin.read_line()` with a manual read that
could be part of the poll loop. This required reading the rvOS stdio
implementation (`vendor/rust/library/std/src/sys/stdio/rvos.rs`) and the raw
channel API (`lib/rvos/src/raw.rs`) to understand that stdin reads are just
`FileRequest::Read` messages sent to the stdin channel handle. The
`FileRequest`/`FileResponse` types from `rvos-proto` provided the message
encoding needed to implement manual, non-blocking stdin reads.

No dead ends were encountered: the cause was visible from the first code read,
and the fix pattern was already proven in fbcon. The investigation phase was
primarily code-reading to understand the syscall interface well enough to write
the multiplexed `read_line_with_events()` function.

## Root Cause

The debugger main loop in `user/dbg/src/main.rs` had this structure:

```
loop {
    poll_events();         // non-blocking try_recv on event channel
    stdin.read_line();     // BLOCKS on stdin channel only
    dispatch(command);
}
```

`poll_events()` uses `try_recv` (non-blocking) on the event channel, which
only succeeds if the event has already arrived. It then calls
`std::io::stdin().read_line()`, which internally sends a `FileRequest::Read`
to the stdin channel and does a blocking `channel_recv_blocking` on that
channel alone.

When the kernel sends a `DebugEvent::Suspended` on the event channel (after
the target process takes its next trap), the debugger process is blocked
waiting on the stdin channel. The event sits in the event channel buffer
unread. Only when the user presses Enter does `read_line` return, the loop
iterates, and `poll_events()` finally discovers the event.

**Bug class:** Missing multiplexed I/O — single-channel blocking instead of
multi-channel poll.

**Code location:** `user/dbg/src/main.rs` main loop (originally lines 468-485)

## Fix

Replaced the `std::io::stdin().read_line()` call (when attached) with a new
`read_line_with_events()` function that manually implements the file read
protocol and uses `sys_chan_poll_add` on both the stdin handle and the event
handle, then `sys_block` to sleep until either channel has data. When woken,
it drains debug events (printing them immediately) and checks for stdin data.

This uses the same poll/block pattern as fbcon, window-server, and fs.

When not attached, the debugger still uses `std::io::stdin().read_line()`
since there's no event channel to multiplex.

Also simplified `poll_events()` to use `raw::sys_chan_recv` directly instead
of creating a temporary `RawChannel` wrapper (which required a careful
`into_raw_handle()` to avoid closing the handle on drop).

## Verification

- Build: `make build` — clean, no warnings
- Clippy: `make clippy` — clean
- Boot test: system boots and reaches shell prompt
- Bug reproduction: expect script confirms event appears within 5 seconds of
  `suspend` without any extra keypress (`>>> SUCCESS: Event received without
  extra Enter!`)
- Regression: `make test` — 69 passed, 0 failed, 0 leaked
- Regression: `make bench` — passes, no performance regression

## Lessons Learned

### Blast Radius
Any user-space program that reads from stdin while also needing to respond
to events on another channel has this same bug pattern. Currently only the
debugger has this issue.

### Prevention
The bug was a design oversight in the original debugger client, not a subtle
race. The poll_events/read_line structure looked correct at first glance but
fundamentally couldn't work for async events. A test that verifies events
arrive without user input (like the expect script added during verification)
would catch this.

### Invariants
User-space programs that need to wait on multiple channels must use the
poll pattern: `sys_chan_poll_add` for each channel of interest, then
`sys_block` to sleep. Using `recv_blocking` on a single channel while
needing data from another channel will always miss events.

### Desktop Rust Analogy
On a desktop OS, this would be solved with `epoll`/`poll`/`kqueue` (or
in Rust: `mio`, `tokio::select!`, or a dedicated event-reading thread).
The kernel's `sys_chan_poll_add` + `sys_block` is the rvOS equivalent of
`epoll_ctl` + `epoll_wait`.
