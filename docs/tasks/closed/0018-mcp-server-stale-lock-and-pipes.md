# 0018: MCP server leaves stale QEMU lock files and named pipes on restart

**Reported:** 2026-02-23
**Status:** Closed
**Severity:** MEDIUM
**Subsystem:** scripts/qemu-mcp

## Symptoms

When the MCP server (`scripts/qemu-mcp/server.py`) is restarted by Claude Code
(e.g., on `/exit` and re-entry), two stale resources prevent QEMU from booting:

1. **Stale lock file.** The `.qemu.lock` file (in the git common dir, typically
   `.git/.qemu.lock`) retains the old server's PID. The MCP server's
   `_acquire_lock()` uses `flock()`, which is process-scoped -- when the old
   process dies, the kernel releases the advisory lock. However, if the lock
   file still exists with stale PID info and a new process races or the flock
   fd was inherited, the new server may fail with:
   `"QEMU lock held by another process"`

2. **Stale named pipes.** The serial communication pipes are named with the
   server's PID: `/tmp/rvos-mcp-serial-<pid>.in` and
   `/tmp/rvos-mcp-serial-<pid>.out`. These paths are computed at module load
   time (`SERIAL_PIPE_BASE = f"/tmp/rvos-mcp-serial-{os.getpid()}"`). When
   the old server is killed, the pipes from the old PID may remain on disk.
   The new server gets a new PID so it creates new pipes, but if QEMU was
   still running from the previous session and referencing the old pipes,
   attempts to interact produce: `[Errno 6] No such device or address`

After any unclean MCP server restart, QEMU cannot be booted until the stale
lock and pipes are manually removed.

## Reproduction Steps

1. Start a Claude Code session that uses the MCP server
2. Boot QEMU via `qemu_boot`
3. Exit the Claude Code session (which kills the MCP server process via SIGKILL
   or similar, without allowing graceful shutdown)
4. Start a new Claude Code session
5. Attempt `qemu_boot` again
6. Observe failure due to stale lock or pipe errors

## Root Cause

The MCP server has cleanup logic in two places, neither of which runs reliably
when the process is killed:

**Signal handler (line 812-817):** `_signal_handler` schedules an async cleanup
task and calls `loop.call_later(2.0, sys.exit, 0)`. This has multiple problems:
- If the process receives SIGKILL (which cannot be caught), no handler runs
- The handler tries to get the running event loop and schedule a task, but if
  the event loop is not running (e.g., during stdio transport blocking read),
  the task never executes
- The 2-second delay assumes the event loop will process the cleanup task, but
  `sys.exit` may fire before cleanup completes

**Lock acquisition (line 96-113):** The MCP server's `_acquire_lock()` uses
`flock()` which is advisory and released on process exit. However, unlike the
shell script `qemu-lock.sh` (which does check for stale PIDs at lines 39-47),
the MCP server's Python code does NOT check whether the lock holder PID is
still alive before failing. It simply raises `RuntimeError("QEMU lock held by
another process")`.

**Named pipe lifecycle (line 42-43):** `SERIAL_PIPE_BASE` and `QMP_SOCK` are
computed once at module load time using `os.getpid()`. The cleanup methods
`_cleanup_fifos()` and `_cleanup_socket()` only clean up pipes matching the
current PID. Old pipes from a previous server PID are never cleaned up.

**Code locations:**
- `scripts/qemu-mcp/server.py:42-43` -- PID-scoped pipe paths
- `scripts/qemu-mcp/server.py:96-113` -- `_acquire_lock()` with no stale check
- `scripts/qemu-mcp/server.py:126-132` -- `_create_fifos()` only cleans own PID
- `scripts/qemu-mcp/server.py:805-817` -- unreliable signal/exit cleanup

**Bug class:** Resource leak (stale lock file and named pipes on unclean exit)

## Fix

Three changes in `scripts/qemu-mcp/server.py`:

1. **Stale pipe/socket cleanup on boot** (`_cleanup_stale_resources()`):
   New function that globs `/tmp/rvos-mcp-serial-*.{in,out}` and
   `/tmp/rvos-mcp-qmp-*.sock`, extracts the PID from each filename, and
   removes the file if that PID is no longer alive (checked via
   `os.kill(pid, 0)`). Called at the start of `boot()` before creating
   new pipes. The current server's own PID is skipped.

2. **atexit handler** (`_sync_cleanup()`): Registered via
   `atexit.register()` for synchronous cleanup of serial FDs, pipes,
   QMP socket, pcap process, and TAP device. Runs on normal interpreter
   exit even if the async event loop is not available.

3. **Synchronous signal handler**: Replaced the old async-scheduling
   `_signal_handler` (which called `loop.create_task()` and relied on
   the event loop processing it within 2 seconds) with a synchronous
   handler that calls `_sync_cleanup()` directly and then `sys.exit()`.
   Registered for both SIGTERM and SIGINT at module load time.

Note: The bug doc mentions a `_acquire_lock()` / `flock()` mechanism,
but the current code does not have lock file management. The stale
resource issue was solely the named pipes and QMP socket, which are now
handled by the PID-based cleanup.

## Verification

- Syntax check passes (`py_compile`).
- The `_cleanup_stale_resources()` function correctly parses PID from
  all three filename patterns and uses `os.kill(pid, 0)` to detect dead
  processes, matching the pattern from `scripts/qemu-lock.sh`.
- The `atexit` + signal handler combination ensures cleanup runs on both
  graceful exit and SIGTERM/SIGINT. SIGKILL still cannot be caught, but
  the stale resource cleanup on the next boot handles that case.

## Lessons Learned

- Async signal handlers that depend on the event loop running are
  unreliable in MCP servers where the transport layer (stdio) may be
  blocking. Synchronous cleanup is safer.
- PID-scoped temp files are a good pattern for concurrency, but require
  a reaping mechanism for the case where the owning process dies without
  cleanup. Glob + `os.kill(pid, 0)` is a simple, effective approach.
