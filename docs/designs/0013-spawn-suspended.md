# 0013: Spawn Suspended

**Date:** 2026-02-20
**Status:** Implemented
**Subsystem:** kernel/task, kernel/services, lib/rvos-proto, lib/rvos, user/dbg

## Motivation

The debugger currently cannot catch the first instruction of a process.
To debug program startup (e.g., inspect the entry point, set a breakpoint
at `_start` before any code runs), you need to:

1. Spawn the process.
2. Race to attach the debugger and suspend it.
3. Hope the process hasn't already executed past the code you care about.

This is fundamentally racy — the process starts executing immediately after
spawn. A "spawn suspended" flag tells init to create the process in a
blocked state before it ever runs a single usermode instruction. The
debugger (or any other tool) can then inspect it, set breakpoints, and
resume when ready.

## Design

### Overview

Add a `suspended` flag to the existing `BootRequest::Spawn` message. When
set, init spawns the process normally (creating TrapContext, loading ELF,
setting up boot channel), then immediately blocks it with a new
`BlockReason::SpawnSuspended` before it can be scheduled. The process
handle channel still receives `ProcessStarted { pid }` as usual, so the
caller knows the PID.

The debugger's new `spawn <path>` command uses this flag, reads the PID
from the process handle channel, then attaches to the suspended process
using the existing debug attach flow. When the proc_debug service
attaches to a spawn-suspended process, it transitions the block reason
from `SpawnSuspended` to `DebugSuspend` and marks `debug_suspended = true`
so the full debug feature set (register reads, memory access, breakpoints)
works immediately.

This approach keeps spawn-suspended as a general scheduler mechanism — not
debugger-specific — while the debugger is the primary consumer.

### Interface Changes

#### Boot Protocol (`lib/rvos-proto/src/boot.rs`)

Add `suspended` field to `Spawn`:

```rust
Spawn(1) { path: &'a str, args: &'a [u8], ns_overrides: &'a [u8], suspended: bool },
```

Existing callers pass `suspended: false` — no behavior change.

#### User Library (`lib/rvos/src/service.rs`)

New public function:

```rust
/// Spawn a process suspended at its entry point.
/// Returns a process handle channel (receives ProcessStarted then ExitNotification).
pub fn spawn_process_suspended(path: &str) -> SysResult<RawChannel>;
```

#### Process Struct (`kernel/src/task/process.rs`)

New `BlockReason` variant:

```rust
pub enum BlockReason {
    // ... existing variants ...
    SpawnSuspended,  // blocked at spawn before first instruction
}
```

Displays as `"spawn-susp"` in `ps` output.

#### Debug Protocol (`lib/rvos-proto/src/debug.rs`)

No wire format changes. The existing `DebugAttachRequest { pid }` and
attach response work unchanged. The proc_debug service detects that the
target is spawn-suspended and handles it transparently.

#### Debugger (`user/dbg`)

New command:

```
  spawn <path>    Spawn a process suspended at its entry point
```

### Internal Changes

#### `kernel/src/task/scheduler.rs`

New function:

```rust
/// Suspend a freshly spawned process before it runs.
/// Removes the PID from the ready queue and blocks it with SpawnSuspended.
/// Must be called after spawn, before the next schedule() call.
pub fn suspend_spawned_process(pid: usize);
```

Implementation: acquires SCHEDULER lock, removes PID from ready_queue
(via `retain`), sets state = Blocked, block_reason = SpawnSuspended.

New accessor for the proc_debug service:

```rust
/// Check if a process is blocked with SpawnSuspended.
pub fn process_is_spawn_suspended(pid: usize) -> bool;
```

#### `kernel/src/services/init.rs`

In `finish_fs_launch()`, after spawning the process, check the `suspended`
flag on the FsLaunchCtx. If set, call `suspend_spawned_process(pid)`.

The `FsLaunchCtx` struct gains a `suspended: bool` field, populated from
the Spawn request in `handle_spawn_request()`.

#### `kernel/src/services/proc_debug.rs`

In the attach handler, after validating the target PID:

1. Check `process_is_spawn_suspended(target_pid)`.
2. If true: call `mark_debug_suspended(target_pid)`,
   `set_block_reason(target_pid, BlockReason::DebugSuspend)`.
3. After sending the attach response, send `DebugEvent::Suspended {}`
   on the event channel so the debugger knows the process is ready for
   inspection.

This transitions the process from a generic spawn-suspended state to a
debug-suspended state, enabling all debug operations (register read/write,
memory access, breakpoints).

#### `user/dbg/src/main.rs`

New `cmd_spawn(path)` method on `Debugger`:

1. Sends `BootRequest::Spawn { path, args: &[], ns_overrides: &[],
   suspended: true }` on the boot channel (handle 0).
2. Receives `BootResponse::Ok` with process handle cap.
3. Reads `ProcessStarted { pid }` from the handle channel.
4. Calls `self.attach(pid)` to enter the debug session.
5. The process is already suspended — the debugger immediately has
   full access.

### Resource Limits

No new limits. The spawn-suspended process uses the same resources as a
normal process. The block state consumes no additional channels or memory.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Add `suspended` field to `BootRequest::Spawn` | `lib/rvos-proto/src/boot.rs` | **Medium** — all Spawn construction sites must add the field |
| Update `spawn_impl()` and callers | `lib/rvos/src/service.rs` | Low — add `suspended: false` to existing calls |
| New `BlockReason::SpawnSuspended` | `kernel/src/task/process.rs`, `scheduler.rs` (ps output) | Low — additive variant |
| New `suspend_spawned_process()` | `kernel/src/task/scheduler.rs`, `kernel/src/task/mod.rs` | Low — new function |
| Init checks suspended flag | `kernel/src/services/init.rs` (FsLaunchCtx, handle_spawn_request, finish_fs_launch) | Low — small additions |
| proc_debug attach-to-spawn-suspended | `kernel/src/services/proc_debug.rs` | Low — small addition to attach path |
| New `spawn` command in dbg | `user/dbg/src/main.rs` | Low — additive |

### Callers of `BootRequest::Spawn` (must add `suspended: false`)

1. `lib/rvos/src/service.rs:spawn_impl()` — user-space library
2. `lib/rvos/src/service.rs:spawn_process_with_overrides_on()` — user-space library (builds Spawn manually)

### Callers affected by new `BlockReason` variant

1. `kernel/src/task/scheduler.rs:process_list()` — ps display (add match arm)

## Acceptance Criteria

- [ ] `make build` succeeds
- [ ] `make clippy` passes with no new warnings
- [ ] System boots and reaches shell normally (no regression)
- [ ] Existing `dbg` `attach <pid>` still works unchanged
- [ ] `dbg` `spawn /bin/hello-std` spawns the process suspended
- [ ] `ps` shows the process as `Blocked` with `spawn-susp` reason (before attach)
- [ ] After `dbg` auto-attaches, `regs` shows pc = entry point of the binary
- [ ] `mem <entry_addr>` reads the first instructions
- [ ] `break <addr>` + `continue` runs to the breakpoint
- [ ] `continue` from entry without breakpoints runs the process to completion
- [ ] `detach` from a spawn-suspended session resumes the process
- [ ] Process exit: debugger receives `ProcessExited` event
- [ ] Spawning a nonexistent path returns an error
- [ ] `spawn_process_suspended()` works from user-space (library API)
- [ ] `make bench` shows no significant regression (>20%)

## Deferred

| Item | Rationale |
|------|-----------|
| Spawn suspended with arguments | Can be added to spawn_process_suspended() later; not needed for basic debug use |
| Resume spawn-suspended without debugger | Could add a message on the process handle channel; not needed now |
| Auto-attach to child spawns | Requires process hierarchy tracking; different feature |
| Symbol loading from ELF | Future debugger enhancement |

## Implementation Notes

All changes as described in the design. Key implementation details:

- `suspended: bool` added as the last field in `BootRequest::Spawn` wire format,
  maintaining backward compatibility (new field at end of message).
- `suspend_spawned_process()` acquires the scheduler lock, removes the PID from
  the ready queue via `retain()`, and sets state=Blocked, reason=SpawnSuspended.
  Called from `finish_fs_launch()` after spawn succeeds but before returning.
- proc_debug attach checks `process_is_spawn_suspended()` after creating the
  session/event channels. If true, transitions to DebugSuspend and sends a
  `Suspended` event so the client knows it can inspect immediately.
- dbg `spawn` command uses `rvos::spawn_process_suspended()`, reads
  `ProcessStarted { pid }` from the handle channel, then calls `self.attach(pid)`.
  The process handle is intentionally leaked (forgotten) — it stays open for the
  lifetime of the debugger process. The dbg process already has the event channel
  for receiving ProcessExited notifications.
- std Command::spawn (in vendor/rust/library/std/) constructs its own
  `BootRequest::Spawn` — it was not modified since it uses `suspended: false`
  and the field is added at the end.

The std sysroot does not construct `BootRequest::Spawn` directly (it uses
the `rvos` library), so no std rebuild is needed.

## Verification

- `make build` — passes
- `make clippy` — no new warnings
- Boot and shell prompt verified manually
- Existing debugger commands tested via expect scripts
