# 0025: Watchdog false positive on idle kernel services

**Reported:** 2026-02-26
**Closed:** 2026-02-26
**Status:** Fixed
**Severity:** HIGH
**Subsystem:** watchdog, services, ipc

## Symptoms

Running `make run` interactively triggers a watchdog timeout after exactly
10 seconds, even though no service is hung:

```
!!! WATCHDOG TIMEOUT !!!
  Kernel task 'timer' (slot 2) has not heartbeated in 10039ms
```

The process list shows all services in `Blocked` state — legitimately idle,
waiting for work. The system is healthy but the watchdog fires anyway.

## Root Cause

Kernel services heartbeat at the top of their main loop, then block when
idle. A blocked service never returns to the top of the loop, so the
heartbeat goes stale. The watchdog cannot distinguish "blocked and idle"
from "blocked and deadlocked."

**Mechanism:** heartbeat at T=0 -> no work -> block_process -> stays blocked
-> T=10s -> watchdog sees 10s since last heartbeat -> fires.

**Bug class:** Design flaw -- heartbeat-only monitoring without accounting
for legitimate idle periods.

## Fix

Services never block indefinitely. They block with a deadline set to half
the watchdog timeout (the "pet interval"), wake up on expiry, heartbeat,
and re-block. A deadlocked service stuck in the wrong blocking call never
returns to its main loop -- the heartbeat goes stale and the watchdog fires
correctly.

### Changes

1. **`watchdog::pet_interval()`** -- returns `TIMEOUT_TICKS / 2` (0 when
   disabled). Services use this as their maximum blocking duration.

2. **`ipc::channel_recv_blocking_timeout()`** -- like `channel_recv_blocking`
   but with a deadline. Returns `Err(TimedOut)` or `Err(ChannelClosed)`.

3. **`ipc::accept_client_timeout()`** -- like `accept_client` but with a
   deadline. Used by sysinfo service.

4. **Poll-based services (init, console, timer):** Changed `block_process`
   to `block_with_deadline(my_pid, now + interval)` when watchdog is active.

5. **Blocking-IPC services (sysinfo):** Switched from `accept_client` +
   `channel_recv_blocking` to their timeout variants.

6. **User-space (fs process):** Added `SYS_BLOCK_DEADLINE` syscall (210)
   for poll-style blocking with a deadline. The fs process uses
   `sys_heartbeat()` to get the pet interval and `sys_block_deadline()` to
   block with a timeout. `sys_heartbeat` now returns the pet interval.

### Files Modified

| File | Change |
|------|--------|
| `kernel/src/watchdog.rs` | Add `pet_interval()` |
| `kernel/src/ipc/mod.rs` | Add `RecvTimeoutError`, `channel_recv_blocking_timeout`, `accept_client_timeout` |
| `kernel/src/services/init.rs` | `block_process` -> `block_with_deadline` |
| `kernel/src/services/console.rs` | `block_process` -> `block_with_deadline` |
| `kernel/src/services/timer.rs` | `block_process` -> `block_with_deadline` (no-timers path) |
| `kernel/src/services/sysinfo.rs` | Use timeout variants of accept + recv |
| `kernel/src/arch/syscall/mod.rs` | Add `SYS_BLOCK_DEADLINE` (210), update `SYS_HEARTBEAT` to return pet interval |
| `lib/rvos/src/raw.rs` | Add `sys_block_deadline`, update `sys_heartbeat` return type |
| `user/fs/src/main.rs` | Use `sys_block_deadline` with watchdog interval |

## Verification

1. `make build` + `make clippy` clean
2. `make test-quick` passes (69/69, 0 failures)
3. MCP boot: waited 35+ seconds idle, `watchdog` command shows all slots
   with recent heartbeats (all under 5s), no timeout
4. `ps` shows services blocked with `timer(+Nms)` deadlines, cycling normally

## Lessons Learned

- Heartbeat-only monitoring is insufficient when services legitimately block.
  The fix is to never block indefinitely -- always use a deadline shorter than
  the monitoring interval.
- The pattern (block with deadline = half timeout, heartbeat on wakeup) works
  for both kernel tasks and user processes, maintaining the watchdog's ability
  to detect real deadlocks while avoiding false positives.
