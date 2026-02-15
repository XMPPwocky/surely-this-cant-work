# Kernel Lock Ordering

This document defines the lock acquisition hierarchy for the rvOS kernel.
All code that acquires multiple locks must follow this ordering to prevent
deadlocks.

## Lock Hierarchy (acquire from top to bottom, never invert)

```
Level 0 — Leaf locks (independent, never acquire other locks while held)
  UART            drivers/uart.rs:88      UART 16550 hardware
  SERIAL_INPUT    drivers/tty.rs:47       Serial console input ring buffer
  SERIAL_WAKE_PID drivers/tty.rs:50       PID blocked on serial input
  RAW_KBD_EVENTS  drivers/tty.rs:104      Raw keyboard event ring buffer
  RAW_KBD_WAKE_PID drivers/tty.rs:107     PID blocked on keyboard input
  RAW_MOUSE_EVENTS drivers/tty.rs:193     Raw mouse event ring buffer
  RAW_MOUSE_WAKE_PID drivers/tty.rs:196   PID blocked on mouse input
  TRACE_RING      trace.rs:41             Kernel trace buffer
  FRAME_ALLOCATOR mm/frame.rs:107         Physical frame bitmap
  HEAP            mm/heap.rs:310          Buddy allocator (LockedHeap)

Level 1 — IPC locks (may call into Level 0; may call wake_process after release)
  SHM_REGIONS     ipc/mod.rs:564          Shared memory regions + ref counts
  CHANNELS        ipc/mod.rs:185          Channel pairs, message queues, blocked PIDs

Level 2 — Scheduler (may be called by Level 1 wakeups after lock release)
  SCHEDULER       task/scheduler.rs:76    Process table, ready queue, current PID

Level 3 — Init server
  INIT_CONFIG     services/init.rs:121    Boot registrations, service directory
```

## Critical Ordering Rules

### Rule 1: Release CHANNELS before calling wake_process

`channel_close()` and send/recv operations may need to wake a blocked
process via `wake_process()`, which acquires SCHEDULER. The CHANNELS lock
must be released first to avoid CHANNELS → SCHEDULER → CHANNELS deadlock.

Pattern (ipc/mod.rs):
```rust
let wake_pid = {
    let mut mgr = CHANNELS.lock();
    // ... modify channel state ...
    wake_pid_to_notify
};  // CHANNELS lock dropped here
if wake_pid != 0 {
    crate::task::wake_process(wake_pid);  // acquires SCHEDULER
}
```

### Rule 2: Release SCHEDULER before calling channel_close or frame_dealloc

`terminate_current_process()` collects all handles and frame ranges under
the SCHEDULER lock, then releases it before cleanup. This avoids
SCHEDULER → CHANNELS (via channel_close → wake_process) deadlock.

Pattern (scheduler.rs):
```rust
let (handles, frames) = {
    let mut sched = SCHEDULER.lock();
    // ... collect cleanup data ...
    (handles, frames)
};  // SCHEDULER lock dropped here
for ep in handles { channel_close(ep); }    // acquires CHANNELS
for ppn in frames { frame_dealloc(ppn); }   // acquires FRAME_ALLOCATOR
```

### Rule 3: Release INIT_CONFIG before calling channel_close

The init server collects override endpoints under INIT_CONFIG, then
closes them after releasing the lock. This avoids INIT_CONFIG → CHANNELS
→ SCHEDULER deadlock.

### Rule 4: suppress_irq_restore before SCHEDULER drop + switch_context

When `schedule()` sets `sched.current = next_pid` under the lock, the
lock drop must NOT re-enable interrupts before `switch_context` completes.
A timer interrupt between the two would cause `preempt()` to read the
wrong current PID and corrupt the wrong task's context.

Pattern (scheduler.rs):
```rust
sched.suppress_irq_restore();   // prevent IRQ restore on drop
drop(sched);                     // release lock WITHOUT enabling IRQs
unsafe { switch_context(...); }  // now safe to switch
restore_interrupts_if_needed();  // manually restore IRQ state
```

### Rule 5: Release SHM_REGIONS before calling frame_dealloc

`shm_dec_ref()` may need to free physical frames when the last reference
is dropped. The SHM lock is released before calling `frame_dealloc()`.

## Adding New Locks

When adding a new lock:

1. Determine its level in the hierarchy based on what it may call.
2. If it never calls into other locked subsystems, it's Level 0.
3. If it may trigger process wakeups, it's Level 1 or higher.
4. Document the lock in this file.
5. Never acquire a higher-level lock while holding a lower-level one.
