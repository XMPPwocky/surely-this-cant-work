# 0017: System Watchdog

**Date:** 2026-02-24
**Status:** Complete (2026-02-24)
**Subsystem:** kernel/watchdog, kernel/arch/trap, kernel/arch/syscall, lib/rvos

## Motivation

rvOS has no mechanism to detect or recover from deadlocks and system hangs.
When a kernel task deadlocks or a critical process hangs during automated
testing, the only protection is the expect script's global timeout (60-300s),
which wastes time and provides no diagnostics about what hung.

Historical bugs show hangs most commonly originate from: IPC channel ref
counting errors causing recv_blocking to wait forever (bugs 0002, 0007,
0008, 0022), VirtIO driver spin loops starving the system (bug 0004), and
resource exhaustion leading to invalid handles (bug 0012).

**Goal:** A three-tier watchdog system that detects hangs at every level
and shuts down with diagnostics, so automated tests fail fast with useful
debug output.

## Design

### Overview

The watchdog uses three tiers of detection:

1. **Tier 1 (implicit):** Timer interrupt liveness. The `timer_tick()`
   function firing IS proof the kernel interrupt system is alive. If S-mode
   interrupts are disabled permanently, only the external expect script
   timeout catches it (RISC-V QEMU virt has no hardware watchdog or NMI).

2. **Tier 2:** Kernel task heartbeats. Critical kernel tasks call
   `watchdog::heartbeat(SLOT)` at the top of their main loop.
   `timer_tick()` calls `watchdog::check(now)` which scans all active slots
   using lock-free atomics. If any slot's last heartbeat exceeds the timeout,
   the watchdog fires.

3. **Tier 3:** User process heartbeats via `SYS_HEARTBEAT` syscall. Critical
   user processes call `sys_heartbeat()` in their main loop. The watchdog
   checks these timestamps alongside tier 2.

### Configuration

Parsed from FDT `/chosen` node `bootargs` property:

- `no-watchdog` -- disable all tiers
- `watchdog=N` -- set timeout to N seconds
- Default: **enabled, 10 second timeout**

### Interface Changes

**New syscall:** `SYS_HEARTBEAT` (235)
- No arguments
- Returns 0 always
- Updates calling process's `last_heartbeat` to current `rdtime`

**New sysinfo command:** `Watchdog(8)` in `SysinfoCommand` enum.

**New shell command:** `watchdog` -- shows enabled/disabled, timeout,
per-slot heartbeat ages, and critical user process heartbeat status.

### Internal Changes

**New file:** `kernel/src/watchdog.rs` (~300 lines)
- Lock-free heartbeat tracking using `AtomicU64` arrays
- `init()`, `register()`, `heartbeat()`, `pet_all()`, `check()`, `status()`
- `fire()` / `fire_user()` for diagnostics + `sbi_shutdown()`
- `parse_bootargs()` for no-alloc bootargs parsing

**New FDT parsing:** `kernel/src/platform/fdt.rs`
- Extracts `bootargs` property from `/chosen` node
- Stored as raw pointer + length in `PlatformInfo` (zero allocation)

**New Process fields:** `kernel/src/task/process.rs`
- `last_heartbeat: u64` -- updated by `SYS_HEARTBEAT`
- `watchdog_critical: bool` -- set at spawn time for critical processes

**New scheduler functions:** `kernel/src/task/scheduler.rs`
- `try_process_list()` -- uses `try_lock()` for safe interrupt context
- `check_critical_heartbeats()` -- scans critical processes' timestamps
- `update_current_heartbeat()` -- updates current process's heartbeat
- `set_watchdog_critical_by_name()` -- marks a process as critical
- `watchdog_process_status()` -- formats status for shell command

### Watched Kernel Tasks

| Slot | Task | Why Critical |
|------|------|-------------|
| 0 | init | All service discovery + spawn |
| 1 | serial-console | stdin/stdout for shell |
| 2 | timer | Sleep/deadline support |
| 3 | sysinfo | Diagnostic commands |

### Critical User Processes

| Process | Why Critical |
|---------|-------------|
| fs | All file I/O goes through this |

### Lock-Free Design

Tier 2 checking is entirely lock-free -- it reads two `AtomicU64` values
per active slot. This means the watchdog works even when the scheduler lock
is held (which is the most common deadlock scenario). Tier 3 and diagnostics
use `try_lock()` on the scheduler -- if the lock is held, tier 3 is skipped
but tier 2 still fires for kernel task deadlocks.

### Diagnostics on Timeout

When the watchdog fires:
1. Disables further watchdog checks
2. Prints `!!! WATCHDOG TIMEOUT !!!` with slot/process name and elapsed time
3. Prints kstat counters (lock-free atomics, always safe)
4. Attempts to print process list via `try_lock()` (skipped if locked)
5. Calls `sbi_shutdown()`

### Resource Limits

- `MAX_WATCHED` = 8 kernel task heartbeat slots
- No heap allocation in the fast path (`check()`)
- Bootargs stored as pointer into FDT blob (no allocation)

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| FDT bootargs parsing | fdt.rs, platform/mod.rs | Low (additive, new property) |
| New watchdog module | watchdog.rs (NEW) | Low (new code, no existing changes) |
| timer_tick() integration | trap.rs | Low (one line addition) |
| Kernel service heartbeats | init.rs, console.rs, timer.rs, sysinfo.rs | Low (one line per file) |
| try_process_list() | scheduler.rs, task/mod.rs | Low (new function, no existing changes) |
| SYS_HEARTBEAT syscall | syscall/mod.rs, process.rs, raw.rs, kernel-abi.md | Medium (new syscall number + ABI) |
| User process heartbeats | fs/main.rs | Low (one line) |
| Sysinfo protocol | rvos-proto/sysinfo.rs | Low (additive variant) |
| Shell command | shell.rs | Low (additive) |
| MCP server bootargs | server.py | Low (new optional parameter) |

## Acceptance Criteria

- [x] `make build` succeeds
- [x] `make clippy` clean
- [x] `make test-quick` passes with watchdog enabled (default)
- [x] MCP boot shows `[watchdog] Enabled, timeout=10s`
- [x] `watchdog` shell command shows status and per-slot heartbeat times
- [x] `docs/kernel-abi.md` updated with SYS_HEARTBEAT

## Deferred

| Item | Rationale |
|------|-----------|
| IPC-level health checking | sys_heartbeat proves a process was recently scheduled, not that it can process IPC. Proper IPC health checking needs multi-channel poll / async reactor in user processes. |
| Shell as critical process | Shell uses complex std IO and legitimately idles on stdin. Marking it critical would cause false positives. |
| Hardware watchdog | RISC-V QEMU virt has no hardware watchdog or NMI. Would require M-mode (OpenSBI) changes. |
| Hang simulation test | Would require a mechanism to intentionally stall a kernel task, best done as a future ktest. |

## Implementation Notes

- The FDT bootargs are stored as a raw pointer + length into the FDT blob
  memory (which persists in SBI memory for the kernel's lifetime). Zero
  allocation needed.

- The `check()` function runs from `timer_tick()` (interrupt context). It
  must not take any locks that could be held by interrupted code. Tier 2 is
  entirely atomic; tier 3 uses `try_lock()`.

- The `fs` server heartbeats at the top of its poll loop (`poll_add` +
  `block` + non-blocking recv cycle). When idle (no requests), it's blocked
  in `sys_block()` and won't heartbeat -- but it's also not hung, just idle.
  The heartbeat only matters when the process is actively running but stuck.

- MCP server and interactive Makefile targets do NOT disable the watchdog by
  default. The MCP `qemu_boot` tool accepts an optional `bootargs` parameter
  so agents can pass `no-watchdog` if needed.

## Verification

- Build: `make build` succeeds
- Clippy: `make clippy` clean (0 warnings)
- Test: `make test-quick` passes (69/69 tests, 0 failures)
- Boot log confirms: `[watchdog] Enabled, timeout=10s (100000000 ticks)`
- Shell `watchdog` command shows all 4 kernel slots and `fs` critical process
- Watchdog does not interfere with normal test execution (all tests complete
  well within 10s timeout)
