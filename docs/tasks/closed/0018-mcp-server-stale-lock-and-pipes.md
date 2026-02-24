# 0018: MCP server leaves stale QEMU lock files and named pipes on restart

**Reported:** 2026-02-23
**Status:** Open
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

(To be filled in during fix phase)

Proposed approach:
1. **Stale lock recovery in `_acquire_lock()`:** When `flock()` fails, read the
   PID from the lock file and check if it is still alive (`os.kill(pid, 0)`).
   If the holder is dead, remove the stale lock file and retry -- matching the
   existing logic in `scripts/qemu-lock.sh` (lines 39-47).
2. **Stale pipe cleanup on boot:** Before creating new pipes in `qemu_boot`,
   glob `/tmp/rvos-mcp-serial-*.in` and `/tmp/rvos-mcp-serial-*.out` and
   remove any whose owning PID (extracted from the filename) is no longer alive.
   Same for `/tmp/rvos-mcp-qmp-*.sock`.
3. **atexit handler:** Register `atexit.register()` for synchronous cleanup of
   pipes and lock file, as a belt-and-suspenders measure alongside the async
   signal handler.
4. **SIGTERM/SIGINT handling:** Replace the current async-scheduling signal
   handler with one that does synchronous cleanup (close fds, unlink pipes,
   release lock) since the event loop may not be in a state to process tasks.

## Verification

(To be filled in during fix phase)

## Lessons Learned

(To be filled in during fix phase)
