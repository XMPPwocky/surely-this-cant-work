# 0005: Scheduling race + kernel task return crash

**Reported:** 2026-02-15
**Status:** Closed (2026-02-15)
**Severity:** HIGH
**Subsystem:** kernel/task (scheduler, context)

## Symptoms

After running `/bin/winclient` from fbcon and moving the mouse, a
nondeterministic kernel panic occurs:

```
Page fault (instruction): sepc=0x0, stval=0x0, SPP=1 (S-mode)
  sstatus=0x200040100 ra=0x0 sp=0x8101b170
  s0=0xffffffffffffffff s1=0xffffffffffffffff s2=0x806a6e78
  current_pid=13
```

Key observations:
- `sepc=0x0, ra=0x0`: execution jumped to address 0
- `SPP=1`: crash in S-mode (kernel code)
- `s0=s1=0xFFFFFFFFFFFFFFFF`: corrupted callee-saved registers
- `current_pid=13`: winclient (a user process)
- Nondeterministic: requires sustained mouse activity to trigger

## Root Causes

Two independent bugs were found:

### Bug A: schedule() race condition (SpinLock interrupt restore)

**The critical bug.** In `schedule()`, `sched.current` is set to `next_pid`
while the scheduler lock is held. After the lock is dropped, `SpinLock::drop()`
re-enables interrupts (because kernel tasks run with SIE=1). There is a window
of ~1 instruction between `drop(sched)` (enables interrupts) and the subsequent
`disable_interrupts()` call.

If a timer interrupt fires in this window:

1. `_trap_entry` saves registers to the current task's TrapContext (via
   sscratch, which hasn't been updated yet — still points to the OLD task)
2. `trap_handler` sees `NEED_RESCHED`, calls `preempt()`
3. `preempt()` reads `sched.current = next_pid` — **wrong!** The CPU is
   actually executing `old_pid`'s `schedule()` continuation
4. `preempt()` computes `old_ctx = &processes[next_pid].context` and calls
   `switch_context(old_ctx, third_task_ctx)`
5. `switch_context` saves the **actually-running task's** s0-s11 registers
   into **`next_pid`'s TaskContext** — **corrupting it**
6. When `next_pid` is later resumed, it loads corrupted register values

The corruption cascades: the wrong task's schedule() continuation runs with
the wrong identity, wrong handles, wrong sscratch. Eventually something
crashes with garbage register values (hence `s0=s1=0xFFFFFFFFFFFFFFFF`).

**Why nondeterministic:** The window is ~1 instruction wide. The timer fires
every 100ms. Under heavy mouse activity, kernel tasks (mouse-server,
gpu-server) call `schedule()` very frequently via blocking IPC, increasing
the probability of hitting the window.

**Why only kernel tasks are affected:** User-mode syscalls run with SIE=0
(cleared by hardware on trap entry). The SpinLock saves SIE=0 and restores
SIE=0 on drop — no interrupt window. Kernel tasks run with SIE=1, so the
SpinLock saves SIE=1 and re-enables on drop.

### Bug B: Kernel task return to address 0

`TrapContext::new_kernel()` did not initialize `frame.regs[1]` (ra). When a
kernel task's entry function returns (e.g., gpu-server on client disconnect),
`ret` jumps to address 0 → instruction page fault. This was a simpler,
deterministic crash for any kernel task that doesn't loop forever.

## Fixes

### Fix A: `SpinLockGuard::suppress_irq_restore()` (spinlock.rs, scheduler.rs)

Added `suppress_irq_restore()` to `SpinLockGuard`: sets `irq_was_enabled =
false` so that `drop()` releases the lock without re-enabling interrupts.

In `schedule()`, call `sched.suppress_irq_restore()` before `drop(sched)`.
Interrupts now stay disabled from lock acquisition through `switch_context`
and sscratch updates. The caller restores interrupts at the end based on the
pre-lock `interrupts_were_on` flag.

`preempt()` is NOT affected: it runs from the trap handler where SIE=0,
so the SpinLock's `irq_was_enabled` is always false.

### Fix B: `kernel_task_return_handler` (context.rs, scheduler.rs)

Added `kernel_task_return_handler()`: a `#[no_mangle] extern "C" fn() -> !`
that calls `exit_current()`. `TrapContext::new_kernel()` now sets
`frame.regs[1]` (ra) to this handler. When a kernel task returns from its
entry function, it safely exits instead of jumping to address 0.

## Files Changed

| File | Change |
|------|--------|
| `kernel/src/sync/spinlock.rs` | Added `suppress_irq_restore()` method |
| `kernel/src/task/scheduler.rs` | Use suppress in `schedule()`, added `kernel_task_return_handler()` |
| `kernel/src/task/context.rs` | Set ra in `TrapContext::new_kernel()` |

## Verification

- `make build` succeeds
- `make clippy` clean
- Serial boot: shell works, ps/help/math all pass
- `make bench`: all 12 benchmarks pass, no regressions
- GPU headless boot: all tasks alive, winclient renders, gpu-server stable
- GUI mode not tested (no display in CI environment; requires manual testing
  with sustained mouse movement to verify the race is eliminated)

## Lessons Learned

### 1. SpinLock::drop() and interrupt windows

SpinLock::drop() unconditionally restores the saved interrupt state. Code
that needs interrupts disabled across a lock boundary must use
`suppress_irq_restore()` to prevent the drop from creating an interrupt
window. This pattern is needed whenever:
- State is updated inside the lock that affects interrupt handler behavior
- Code after the lock drop (but before explicit disable) could be interrupted

### 2. Kernel task lifecycle

Kernel tasks must have a safe return path. Unlike user processes (which trap
on `ecall` for SYS_EXIT), kernel tasks return via `ret`. If ra is not set
to a cleanup handler, the task jumps to whatever ra contains (0 from
TrapFrame::zero()).

### 3. Race window analysis

The schedule() race requires:
1. Caller has SIE=1 (kernel task, not syscall handler)
2. Timer interrupt fires in the ~1 instruction window
3. NEED_RESCHED is set (timer_tick always sets it)

Under normal load the probability per schedule() call is ~10^-8. But mouse
activity at 60+ events/sec, each causing multiple schedule() calls across
kernel tasks, compounds to a meaningful probability per minute.
