# 0011: IPC Deadlock Detection Watchdog

**Date:** 2026-02-20
**Status:** Design
**Subsystem:** kernel/task, kernel/ipc, kernel/services

## Motivation

In a microkernel where every operation is IPC, deadlocks are the #1
liveness failure mode. Process A blocks on recv from B, B blocks on recv
from A — both wait forever. Currently there is no detection: the system
silently hangs with no diagnostic output.

Erlang solves this with process monitoring and supervision trees. DTrace
solves it with lockstat. rvOS needs a watchdog that detects IPC deadlock
cycles and reports them.

## Design

### Overview

A periodic kernel watchdog task that:
1. Runs every N seconds (configurable, default 5s)
2. Scans all Blocked processes
3. Builds a "waits-for" graph from BlockReason (requires Feature 0010)
4. Detects cycles using DFS
5. Logs detected deadlocks to the console with full cycle description

The watchdog is advisory only — it logs but does not kill processes.

### Dependency

**Requires Feature 0010** (BlockReason enum). Without knowing *what*
each process is blocked on, the watchdog cannot build the waits-for graph.

### Wait-For Graph Construction

For each Blocked process P with BlockReason:
- `IpcRecv(ep)` → P waits for whoever will send on ep. Look up the
  channel: if the *other* side's endpoint has a process blocked on send
  (send_blocked_X), that's not a dependency. The dependency is: P waits
  for *any process that holds a handle to the other endpoint*. For
  simplicity, if the other endpoint has exactly one ref (ref_count=1)
  and a process is blocked on it, that's a direct edge.
- `IpcSend(ep)` → P waits for the receiver to drain. Look up blocked_X
  on the destination side — that process is who P is waiting for.

### Cycle Detection

Simple DFS with coloring (White/Gray/Black). If we reach a Gray node,
we have a cycle. With MAX_PROCS=64, this is trivially fast.

### Interface Changes

- New kernel service: watchdog task (spawned from kmain)
- Console output on detection: `[watchdog] DEADLOCK: PID 3 (shell) → ep 14 → PID 7 (fs) → ep 22 → PID 3 (shell)`
- New sysinfo command `Deadlocks(8) {}` — returns current deadlock report
  (empty if none detected)
- New shell command `deadlock` — queries watchdog for current status

### Internal Changes

- New file: `kernel/src/services/watchdog.rs`
- New kernel task spawned in kmain
- Uses `channel_stats()` from Feature 0010 for channel state
- Uses `BlockReason` from Feature 0010 for process state
- Needs a way to query which PID owns which endpoints — may need a new
  `channel_endpoint_owner(ep) -> Option<usize>` function in ipc/mod.rs

### Resource Limits

No new tables. The waits-for graph is computed on the stack using
fixed-size arrays (MAX_PROCS=64 → 64-entry adjacency list + 64-byte
color array = <1 KiB).

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| New watchdog.rs | services/watchdog.rs (new), services/mod.rs, main.rs | Low (additive) |
| Spawn watchdog task | main.rs kmain() | Low (one line) |
| Endpoint owner query | ipc/mod.rs (new function) | Low (read-only query) |
| Sysinfo command | rvos-proto/sysinfo.rs, services/sysinfo.rs | Low (additive) |
| Shell command | user/shell/src/shell.rs | Low (additive) |

## Acceptance Criteria

- [ ] Watchdog task runs without affecting normal operation
- [ ] Artificially induced deadlock (two processes blocking on each other)
      is detected and logged within 10 seconds
- [ ] No false positives during normal boot and shell usage
- [ ] `deadlock` shell command shows "no deadlocks" in normal state
- [ ] `make bench` shows no regression

## Deferred

| Item | Rationale |
|------|-----------|
| Automatic deadlock resolution (kill one process) | Too dangerous without user policy |
| Multi-hop deadlock detection (A→B→C→A) | Start with 2-party; extend if needed |
| Timeout-based detection ("blocked > 30s") | Different from cycle detection; complementary |

## Implementation Notes

(To be filled during implementation)

## Verification

(To be filled during implementation)
