# 0007: Per-Task Trap Frames

**Date:** 2026-02-15
**Status:** Complete (2026-02-15)
**Subsystem:** kernel/arch, kernel/task

## Motivation

Bug 0004 revealed a fundamental flaw in how kernel-mode traps interact with
scheduling. All kernel-mode traps (`_from_kernel`) save their trap frame on
a single shared `KERNEL_TRAP_STACK`. When a kernel task is preempted
(timer tick → `schedule()` → `switch_context`), its trap frame remains on
this shared stack. Any subsequent kernel trap overwrites it, corrupting the
preempted task's saved sepc, sstatus, and registers.

This manifests as: kernel task resumes with wrong register values, jumps to
a bogus address, page faults, dies. Downstream tasks that depended on it
(e.g., window-server waiting for gpu-server's FlushOk) deadlock.

The root cause is deeper than the shared stack: the trap handler is
re-entrant (it calls `schedule()` which re-enables interrupts), and the
trap frame lives on a shared resource. The fix is architectural: **store
each task's trap frame in the task's own Process struct**, and restructure
the trap handler so it never context-switches with a live trap frame on a
shared stack.

## Design

### Overview

Move the trap frame from the stack (shared kernel trap stack or per-task
kernel stack) into the `Process` struct. `sscratch` always holds a pointer
to the current task's trap context. On trap entry, registers are saved
directly into the current task's struct. On trap exit, registers are
restored from the (possibly different) current task's struct.

Preemptive scheduling (timer tick) no longer calls `schedule()` from the
trap handler. Instead, it sets a flag. The asm epilogue checks the flag,
calls a `preempt()` function that changes `current`, and restores from the
new task's trap frame. The trap handler is never re-entered.

Cooperative scheduling (blocking IPC) continues to use `switch_context` as
today. The two mechanisms coexist: preemptive saves go through the trap
frame, cooperative saves go through `TaskContext`.

### Data Structure Changes

New struct in `context.rs` (or `process.rs`):

```rust
/// Per-task trap context. Lives in the Process struct.
/// `sscratch` always points to the current task's TrapContext.
#[repr(C)]
pub struct TrapContext {
    pub frame: TrapFrame,        // 272 bytes: regs[32] + sstatus + sepc
    pub kernel_stack_top: usize, // used by user traps for handler stack
    pub user_satp: usize,        // used by user trap return for satp switch
}
```

Process struct gains:

```rust
pub struct Process {
    pub trap_ctx: TrapContext,   // NEW: per-task trap frame + metadata
    pub context: TaskContext,    // KEPT: callee-saved regs for cooperative switches
    // ... existing fields unchanged ...
}
```

### Trap Entry (trap.S)

A single entry point replaces the current split:

```
_trap_entry:
    csrrw   t0, sscratch, t0       # t0 = TrapContext ptr, sscratch = old t0
    sd      t1, 48(t0)             # pre-save t1 (regs[6])
    csrr    t1, sscratch            # t1 = original t0
    sd      t1, 40(t0)             # save original t0 (regs[5])
    # Save remaining GPRs to t0->frame.regs[...]
    sd      x1,  8(t0)
    sd      x2, 16(t0)             # sp (user or kernel sp)
    sd      x3, 24(t0)
    ...
    sd      x31, 248(t0)
    sd      zero, 0(t0)
    # Save CSRs
    csrr    t1, sstatus
    sd      t1, 256(t0)
    csrr    t1, sepc
    sd      t1, 264(t0)
```

Then check SPP to determine handler stack:

```
    srli    t1, t1, 8
    andi    t1, t1, 1              # SPP: 1=kernel, 0=user
    bnez    t1, _kernel_trap

_user_trap:
    # Switch to kernel page table
    load    t1, KERNEL_SATP_RAW
    csrw    satp, t1; sfence.vma
    # Handler runs on per-task kernel stack
    ld      sp, 272(t0)            # TrapContext.kernel_stack_top
    j       _call_handler

_kernel_trap:
    # Handler runs on shared KERNEL_TRAP_STACK (handler call chain only,
    # no trap frame stored here — safe to reuse across tasks)
    load    sp, KERNEL_TRAP_STACK_TOP
    j       _call_handler

_call_handler:
    csrw    sscratch, t0           # keep TrapContext ptr in sscratch
    mv      a0, t0                 # pass TrapContext ptr to Rust
    call    trap_handler           # may set need_resched; never calls schedule()
    # trap_handler returns new TrapContext ptr in a0
    # (same task if no preemption, different task if preempted)
    mv      t0, a0
    csrw    sscratch, t0           # update sscratch for next trap
```

### Trap Exit (trap.S)

```
    # Restore sstatus, sepc
    ld      t1, 256(t0)
    csrw    sstatus, t1
    ld      t1, 264(t0)
    csrw    sepc, t1

    # If returning to user mode (SPP=0): switch satp
    csrr    t1, sstatus
    srli    t1, t1, 8
    andi    t1, t1, 1
    bnez    t1, _restore_regs
    # User return: load user_satp from TrapContext
    ld      t1, 280(t0)            # TrapContext.user_satp
    beqz    t1, _restore_regs
    csrw    satp, t1
    sfence.vma

_restore_regs:
    ld      x1,  8(t0)
    ld      x2, 16(t0)             # restore sp
    ld      x3, 24(t0)
    ld      x4, 32(t0)
    ld      x6, 48(t0)             # restore t1 before t0
    ld      x7, 56(t0)
    ... (x8-x31) ...
    ld      x5, 40(t0)             # restore t0 LAST
    sret
```

### Preemptive Scheduling

`timer_tick()` no longer calls `schedule()`. It resets the SBI timer and
returns. The Rust `trap_handler` checks for preemption and, if needed,
calls `preempt()`:

```rust
fn trap_handler(ctx: &mut TrapContext) -> *mut TrapContext {
    let scause = read_scause();
    // ... dispatch interrupt/exception ...

    // After handling: check if preemption needed
    if need_resched() {
        return preempt(ctx);   // returns new task's TrapContext ptr
    }
    ctx as *mut TrapContext     // same task, no switch
}
```

`preempt()` lives in the scheduler:

```rust
fn preempt(old_ctx: &mut TrapContext) -> *mut TrapContext {
    let mut sched = SCHEDULER.lock();
    // CPU accounting, pick next task, re-enqueue old...
    let next_pid = pick_next();
    sched.current = next_pid;

    // Set old task's TaskContext so cooperative switch_context can
    // resume it later (ra = preempt_resume_trampoline)
    let old = &mut sched.processes[old_pid].context;
    old.ra = preempt_resume_trampoline as usize;
    old.sp = 0; // unused — trampoline loads sp from trap frame

    let new_ctx = &mut sched.processes[next_pid].trap_ctx;
    new_ctx as *mut TrapContext
}
```

When a preemptively-saved task is later resumed by `switch_context`
(cooperative path), `ra = preempt_resume_trampoline`:

```asm
preempt_resume_trampoline:
    # Resumed by switch_context after being preemptively saved.
    # Full state is in our TrapContext. Jump to the standard trap
    # exit path to restore and sret.
    csrr    t0, sscratch           # our TrapContext ptr
    j       _restore_from_trap     # shared restore + sret code
```

### Cooperative Scheduling (Unchanged)

Blocking IPC (`channel_recv_blocking`, etc.) and explicit yield still call
`schedule()` → `switch_context()`. This saves callee-saved registers to
`TaskContext`, exactly as today. The trap frame in `TrapContext` persists
in the `Process` struct across the cooperative switch.

When the task resumes via `switch_context`, it returns through the syscall
handler → trap handler → asm trap exit, which restores from the same
task's `TrapContext`.

### sscratch Invariant

`sscratch` always holds a pointer to the **current task's TrapContext**.
This replaces the current dual-use (0 = kernel mode, nonzero = user kernel
stack). User/kernel distinction is determined by checking `sstatus.SPP`
after saving it to the trap frame.

Updated on:
- `preempt()`: sets sscratch to the new task's TrapContext
- First-time task entry: `kernel_task_trampoline` / `user_entry_trampoline`
  sets sscratch
- Scheduler init: sets sscratch for idle task (PID 0)

### Shared KERNEL_TRAP_STACK

Retained for kernel-mode traps. It now holds only the trap handler's call
chain (trap_handler → timer_tick, etc.), never the trap frame. The call
chain fully unwinds before any task switch occurs (preempt() returns to the
asm, which does the switch). No stale data persists across tasks.

This preserves the stack-overflow safety net: if a kernel task's stack
overflows, the handler still runs on a known-good stack.

### Unification Potential

Today, there are two context-save mechanisms:

| Mechanism | What's saved | Where | When |
|-----------|-------------|-------|------|
| Trap frame (`TrapContext.frame`) | All 31 GPRs + sstatus + sepc | Process struct | Preemptive (trap entry) |
| `TaskContext` via `switch_context` | ra, sp, s0-s11 (14 regs) | Process struct | Cooperative (blocking IPC, yield) |

These could be **unified**: cooperative switches could also save full state
into the trap frame (e.g., by triggering a software interrupt, or by
manually filling in `TrapContext`). This would eliminate `switch_context`,
`TaskContext`, `kernel_task_trampoline`, and `user_entry_trampoline`
entirely. All task state would live in `TrapContext`; all scheduling would
be "change the current pointer."

This is deferred because it requires restructuring every cooperative yield
point (blocking IPC, syscall yield, process exit) and the first-run
trampolines. The current two-mechanism approach is correct and
well-understood. Unification is a simplification, not a correctness fix.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| New `TrapContext` struct | context.rs or process.rs | Low (additive) |
| `TrapContext` field in `Process` | process.rs — all 3 constructors (new_kernel, new_user_elf, new_idle) | Low (additive) |
| Rewrite `_trap_entry` / `_from_kernel` / `_from_user` | trap.S (entire file) | **High** — core trap path |
| `sscratch` invariant change | trap.S, switch.S (user_entry_trampoline), scheduler.rs (init) | **High** — must update all sscratch writers |
| `trap_handler` returns TrapContext ptr | trap.rs (signature change, ~1 call site in asm) | Medium |
| `timer_tick` stops calling `schedule()` | trap.rs | Low (removal) |
| New `preempt()` function | scheduler.rs | Medium (new code) |
| `preempt_resume_trampoline` | switch.S | Low (additive) |
| `preempt()` updates `TaskContext.ra` | scheduler.rs, context.rs | Medium (new interaction) |
| Update `sscratch` in `preempt()` | scheduler.rs | Medium |
| `KERNEL_TRAP_STACK` usage change | trap.S (now handler stack only, not trap frame) | Medium |
| `user_entry_trampoline` sets sscratch | switch.S | Low (change value written) |
| Idle task (PID 0) needs valid TrapContext | scheduler.rs init, process.rs new_idle | Low |

No changes to: syscall numbers, wire protocols, user-space code, IPC,
shared memory, page tables, frame allocator, `kernel-abi.md`.

## Acceptance Criteria

- [x] `make build` succeeds, `make clippy` clean
- [x] Serial-only boot (`make run`): system boots, shell works, `ps` shows all tasks
- [ ] GUI boot (`make run-gui`): fbcon renders, window-server runs, winclient works (not tested — no virtio-gpu in test config)
- [ ] GPU stress test: run winclient, move mouse continuously for 60+ seconds — no hang, no page fault, no gpu-server death (not tested — no virtio-gpu in test config)
- [x] Cooperative scheduling still works: blocking IPC (shell commands, fs requests) operates normally
- [x] Kernel task preemption works: `ps` shows CPU accounting updates for kernel tasks (they're being preempted and re-scheduled)
- [x] No regressions: `make bench` — all 12 benchmarks pass
- [x] `grep -r KERNEL_TRAP_STACK` confirms no trap frame storage on shared stack

## Deferred

| Item | Rationale |
|------|-----------|
| Unify cooperative switches into trap frame mechanism | Simplification, not correctness. Requires restructuring all yield points. |
| Eliminate `TaskContext` / `switch_context` | Follows from unification above. |
| Per-task trap stacks for kernel tasks | Not needed: shared stack only holds handler call chain, fully unwound before switch. |
| Volatile DMA fixes for tablet/input drivers | Separate correctness issue (blast radius item from bug 0004), not related to trap architecture. |

## Implementation Notes

### Design Deviations

**`preempt()` uses `switch_context`, not trap-frame return.** The original
design had `preempt()` return a different `*mut TrapFrame` and set
`TaskContext.ra` to a trampoline. The actual implementation has `preempt()`
call `switch_context()` just like `schedule()`. This is simpler: both
cooperative and preemptive paths use the same underlying mechanism. The asm
epilogue always restores from the same task's trap frame (the one that
called `trap_handler`).

**S-mode traps use the task's own kernel stack, not KERNEL_TRAP_STACK.**
The design suggested using the shared KERNEL_TRAP_STACK for S-mode trap
handler call frames. The implementation instead reloads `sp` from the saved
register (`ld sp, 16(t0)`), keeping the handler on the task's own kernel
stack. This is necessary because `preempt()` calls `switch_context()` from
the handler — the call frames must survive across context switches. The
shared KERNEL_TRAP_STACK still exists but is unused by the current
implementation (retained for potential future stack-overflow safety net).

**`schedule()` also manages sscratch.** In addition to `preempt()` and the
trampolines, `schedule()` writes sscratch before/after `switch_context()`
to maintain the invariant that sscratch always points to the current task's
TrapContext.

### Bugs Found During Implementation

**1. Stale sscratch after switch_context (scheduler.rs).** When
`switch_context()` is called from `schedule()`, the new task resumes in
Rust code (after its own `switch_context()` call). If sscratch still
pointed to the old task's TrapContext, any trap would corrupt the old
task's state. Fix: write sscratch to the new task before `switch_context`,
and restore to self after.

**2. SpinLock interrupt-state interaction (scheduler.rs).** The SpinLock
disables SIE on `lock()` and restores on `drop()`. In `schedule()`,
`interrupts_were_on` was captured *after* the lock disabled SIE, so it
always read `false`. After `switch_context` returned, SIE was never
re-enabled for kernel tasks. This caused all kernel tasks to permanently
lose interrupts after their first context switch. The idle task would WFI
with SIE=0, unable to wake from timer or UART interrupts — system freeze.
Fix: capture `interrupts_were_on` *before* `SCHEDULER.lock()`, and add
`disable_interrupts()` after `drop(sched)` to close the preemption window
opened by SpinLock::drop().

## Verification

- `make build` succeeds
- `make clippy` clean (no new warnings)
- Serial boot (`make run`): shell works, `ps` shows all tasks, `help`
  and `math add 2 3` work
- `make bench`: all 12 benchmarks pass, hello-std integration test passes
- Cooperative scheduling works: IPC (math, fs) operates normally
- No regressions in benchmark numbers
- GUI mode not tested (no virtio-gpu in current QEMU config)
