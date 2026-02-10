# 0003: Compositor FPS drops after closing child fbcon window

**Reported:** 2026-02-10
**Status:** Closed (2026-02-10)
**Severity:** HIGH
**Subsystem:** shell

## Symptoms

User launches a child fbcon window (`run /bin/fbcon 400 400`) from the parent
fbcon shell. The child window works fine. When the child window is closed, the
system hangs for approximately one second. After the hang, the compositor's FPS
drops dramatically — from ~47 FPS to ~3-8 FPS. The `flush` time increases from
~1ms to ~91ms, while `composite` time stays roughly the same (~8-9ms).

```
[compositor] fps=32 composite=9388us flush=1276us
[compositor] fps=47 composite=9803us flush=552us
[compositor] fps=11 composite=9435us flush=17077us
[compositor] fps=3 composite=8031us flush=91774us
[compositor] fps=8 composite=8014us flush=91814us
[compositor] fps=8 composite=7998us flush=91567us
```

The orphaned shell process (PID 14) shows 90% CPU usage after the window closes.

Does NOT happen with `winclient` — only `fbcon` (because winclient has no child
processes with IPC channels).

## Reproduction Steps

1. `make run-gui`
2. In the fbcon shell, type `run /bin/fbcon 400 400`
3. Wait for the child fbcon window to appear
4. Close the child window (close button or let the child process exit)
5. Observe ~1 second hang and subsequent FPS drop in compositor
6. `ps` shows the orphaned shell still running at ~90% CPU

**Note:** This does NOT happen when closing a `winclient` window — only `fbcon`.

## Root Cause

**Mechanism:**

1. Child fbcon spawns a shell (`/bin/shell`) with stdin/stdout connected via
   IPC channels (`stdin_our`/`stdout_our` on fbcon side, `stdin_shell`/`stdout_shell`
   on shell side).
2. When the child fbcon receives `CloseRequested`, it calls `close_window()` and
   returns from `main()`. Process exit closes all handles, including `stdin_our`
   and `stdout_our`.
3. The orphaned shell is sitting in its read loop at `shell.rs:891`:
   ```rust
   if io::stdin().lock().read(&mut byte).unwrap_or(0) == 0 {
       continue;  // BUG: spins forever on EOF
   }
   ```
4. With the peer channel closed, `recv_read` in the std layer does:
   - `SYS_CHAN_SEND_BLOCKING` → returns `usize::MAX` immediately (peer closed),
     return value is ignored
   - `SYS_CHAN_RECV_BLOCKING` → returns `2` (ChannelClosed) immediately
   - Returns `total = 0`
5. `Stdin::read()` returns `Ok(0)` (EOF). The shell treats this as "no data yet"
   and `continue`s — creating an infinite busy-loop of two fast-returning syscalls.
6. The busy-looping shell consumes ~90% CPU, starving the GPU kernel task's
   spin-wait in `send_command()` (virtio completion polling). The GPU task gets
   preempted for almost a full scheduler tick (100ms at 10 MHz), inflating each
   `flush_rect` call from ~1ms to ~91ms.

**Fundamental cause:** The shell treated EOF (read returning 0) as a transient
"no data" condition and retried, instead of recognizing it as stdin closure and
exiting.

**Code location:** `user/shell/src/shell.rs:891`

**Bug class:** Busy-wait on EOF (resource exhaustion / CPU starvation)

## Fix

Changed the shell's inner read loop to `return` on EOF instead of `continue`:

```rust
if io::stdin().lock().read(&mut byte).unwrap_or(0) == 0 {
    return; // EOF on stdin — parent process (e.g. fbcon) exited
}
```

When stdin returns 0 bytes (either `Ok(0)` for EOF or any error mapped to 0 via
`unwrap_or`), the shell now exits cleanly. This is the standard Unix behavior:
shells exit on stdin EOF.

## Verification

- `make build` succeeds
- `make clippy` clean

## Lessons Learned

### 1. Blast Radius
Any user-space program that reads stdin in a loop should handle EOF. The shell was
the only program with this pattern (other programs like winclient don't read from
stdin channels). No siblings found.

### 2. Prevention
A simple integration test (spawn fbcon → close window → verify orphan shell exits)
would catch this. The key invariant: "read() returning 0 means EOF, not retry."

### 3. Invariants
EOF handling: In rvOS, `Stdin::read()` returning `Ok(0)` means the peer channel
is closed. Programs must treat this as EOF and exit their read loops, not retry.
This matches POSIX semantics.

### 4. Secondary concern
The std `recv_read` function ignores the return value of `SYS_CHAN_SEND_BLOCKING`.
If the send fails on a closed channel, it still proceeds to recv. This is harmless
(recv also returns immediately with an error), but checking the send result and
returning 0 early would be cleaner and avoid the wasted recv syscall.
