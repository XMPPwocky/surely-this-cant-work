# 0006: Debug suspend defeated by wakeup_pending

**Reported:** 2026-02-16
**Status:** Closed (2026-02-16)
**Severity:** MEDIUM
**Subsystem:** kernel/task (scheduler), kernel/arch (trap handler)

## Symptoms

Attaching to a user process (e.g., fbcon) with `dbg`, then running `suspend`,
prints `[event] Process suspended` — but the target process continues running.
The debugger believes the process is suspended, but it isn't actually blocked.

This affects both forced suspend and breakpoint hits.

## Reproduction Steps

1. `make run-gui` (or `make run` with fbcon available)
2. From shell: `run /bin/dbg`
3. `attach <fbcon-pid>` (e.g., `attach 7`)
4. `suspend`
5. Observe: `[event] Process suspended` is printed
6. But fbcon continues rendering / accepting input — it was never blocked

The bug is timing-dependent: it occurs when the target process has
`wakeup_pending == true` at the moment the trap handler tries to block it.
For fbcon, which receives frequent keyboard/mouse events, this is common.

## Investigation

The bug was discovered through first-hand testing immediately after the debugger
was implemented: attaching to fbcon with `dbg`, running `suspend`, observing
`[event] Process suspended` in the client, but seeing fbcon continue to render.

The investigation started by searching for the `suspend` handling path in
`kernel/src/services/proc_debug.rs`. This showed the service calls
`set_debug_suspend_pending(target_pid)` at line 208 — it sets a flag on the
target process and returns; the actual blocking happens asynchronously in the
trap handler when the target process next takes a trap.

Next, `debug_suspend` was searched in `kernel/src/arch/trap.rs`, which showed
two paths that call `block_process`: the breakpoint hit path (line 125) and the
forced-suspend path (line 165). Both followed the pattern of sending the
`Suspended` event, calling `mark_debug_suspended`, and then calling
`block_process`.

Searching for `pub fn block_process` in `scheduler.rs` revealed the
`wakeup_pending` guard (lines 780–790): if `wakeup_pending` is true, the
function clears the flag and returns without setting the process to `Blocked`.
This is intentional for IPC — it prevents a lost wakeup when a message arrives
between a failed `channel_recv` poll and the subsequent block call.

Reading `pub fn wake_process` confirmed the mechanism: when a message arrives
for a `Running` or `Ready` process, `wake_process` sets `wakeup_pending = true`
instead of blocking (since the process is already runnable). For fbcon, which
receives frequent keyboard and mouse events, `wakeup_pending` was almost always
set at the moment the trap handler ran.

The client-side code in `user/dbg/src/main.rs` was also checked to confirm the
event arrives in the client before the block takes effect. This confirmed the
ordering: the Suspended event is sent and received by the debugger client before
`block_process` is called, so the debugger always believes the suspend succeeded
even when the block silently fails.

With both code paths identified and the mechanism understood, the root cause was
clear: the `wakeup_pending` bail-out in `block_process` is semantically correct
for IPC but wrong for debug suspend, which must be unconditional. Two fix options
were considered: clearing `wakeup_pending` at the call sites in `trap.rs`
(simpler), or adding a dedicated `force_block_process` function (cleaner). The
cleaner option was chosen.

## Root Cause

The trap handler's debug suspend path (both forced-suspend and breakpoint-hit)
uses `block_process(pid)` to block the target:

```
// kernel/src/arch/trap.rs:162-167
if let Some(event_ep) = crate::task::check_and_clear_debug_suspend(pid) {
    send_debug_event(event_ep, &DebugEvent::Suspended {});
    crate::task::mark_debug_suspended(pid);
    crate::task::block_process(pid);       // <-- HERE
    crate::task::schedule();
    return tf as *mut TrapFrame;
}
```

But `block_process` has a `wakeup_pending` guard designed for IPC:

```
// kernel/src/task/scheduler.rs:780-791
pub fn block_process(pid: usize) {
    let mut sched = SCHEDULER.lock();
    if let Some(ref mut proc) = ... {
        if proc.wakeup_pending {       // <-- defeats debug suspend
            proc.wakeup_pending = false;
            return;                    // silently does NOT block
        }
        proc.state = ProcessState::Blocked;
    }
}
```

The `wakeup_pending` mechanism exists to prevent lost wakeups in IPC: if a
message arrives between a failed `channel_recv` poll and the subsequent
`block_process`, the pending flag ensures the process stays runnable. This
is correct for IPC blocking.

But debug suspend is unconditional — the debugger wants the process stopped
*regardless* of pending IPC messages. The Suspended event is sent before
`block_process` is called, so the debugger sees the event even when the
block silently fails.

**Affected code paths:**
- Forced suspend: `kernel/src/arch/trap.rs:165`
- Breakpoint hit: `kernel/src/arch/trap.rs:125`

**Bug class:** Semantic mismatch — reusing an IPC-oriented blocking primitive
for a debug-oriented blocking operation with different semantics.

## Fix

Added `force_block_process(pid)` in `kernel/src/task/scheduler.rs` —
unconditionally sets the process to Blocked, clearing `wakeup_pending`
rather than bailing out on it. The pending IPC message stays in the channel
queue and will be picked up when the debugger resumes the process.

Both trap handler paths (breakpoint hit at line 125, forced suspend at
line 165) now call `force_block_process` instead of `block_process`.

## Verification

- `make build` succeeds
- `make clippy` passes with no warnings

## Lessons Learned

`block_process` has implicit semantics (the `wakeup_pending` bail-out) that
make it unsuitable for unconditional blocking. Any future caller that needs
a guaranteed block (not just debug — e.g., a future `kill -STOP` signal)
should use `force_block_process`.
