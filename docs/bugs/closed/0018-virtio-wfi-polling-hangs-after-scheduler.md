# 0018: VirtIO driver wfi polling hangs after scheduler/interrupts enabled

**Reported:** 2026-02-23
**Status:** Fixed
**Severity:** MEDIUM
**Subsystem:** drivers/virtio

## Symptoms

The virtio-blk driver functions (`read_sectors`, `write_sectors`, `flush`,
`read_serial_into`) use a `wfi` polling loop to wait for device completion.
This works during early boot (before the scheduler and interrupts are enabled)
because `wfi` resumes only when the device interrupt fires.

However, if any of these functions are called **after** `task::init()` and
`interrupts_enable()` have been called, the `wfi` can receive a timer interrupt,
which triggers `preempt()` -> `schedule()`, switching to another task. The
original polling loop is never returned to, and the system hangs (or the
request silently stalls).

The same pattern exists in the virtio-gpu and virtio-net drivers.

## Affected Functions

All VirtIO driver functions that use `wfi` polling:

- `kernel/src/drivers/virtio/blk.rs:322` — `read_sectors()` polling loop
- `kernel/src/drivers/virtio/blk.rs:391` — `write_sectors()` polling loop
- `kernel/src/drivers/virtio/blk.rs:435` — `flush()` polling loop
- `kernel/src/drivers/virtio/blk.rs:468` — `read_serial_into()` polling loop
- `kernel/src/drivers/virtio/gpu.rs:191` — `send_command()` polling loop
- `kernel/src/drivers/virtio/net.rs:329` — `send_frame()` polling loop

## Reproduction Steps

1. Move any `blk::read_sectors()` or `blk::get_serial()` call to execute
   after `task::init()` and `interrupts_enable()` in the kernel boot path.
2. Boot the system.
3. The system hangs because the timer interrupt preempts the `wfi` polling
   loop. The `preempt()` handler switches to another task, and the polling
   context is abandoned on the scheduler's ready queue. Even if it eventually
   runs again, the VirtIO request state may be stale or already completed
   and consumed by an IRQ handler.

## Investigation

This bug was discovered while implementing VirtIO serial-number-based drive
identification (to reliably map QEMU block devices to their intended mount
points regardless of MMIO enumeration order).

**Step 1: Initial implementation and first hang.** A `get_serial()` function
was added to `virtio/blk.rs` using the same `wfi` polling loop as the existing
`read_sectors()`/`write_sectors()` functions. `get_serial()` was called from
`kernel/src/main.rs` after `task::init()` and `interrupts_enable()` — the
natural place to look up device serials before spawning ext2 servers. When
booted via the MCP server, the system hung immediately: the boot log showed
blk-server spawns but the `rvos>` prompt never appeared. The 60-second
`qemu_boot` timeout fired. The partial boot log confirmed the kernel reached
the blk-server spawn but then went silent, with no panic or error message.

**Step 2: Understanding the mechanism.** Inspection of the boot log revealed
the system stalled right after `"Spawned [7] \"blk-server1\" (PID 7)"` —
which is after `task::init()` and `interrupts_enable()` were called. The
conclusion: a timer interrupt fired while the `wfi` was spinning, causing
`preempt()` → `schedule()` to switch away from the kernel boot task. The
polling loop was abandoned mid-flight on the scheduler's ready queue.

**Step 3: Move serial read to `init_one()` (pre-scheduler).** The serial
read was moved into `init_one()`, which runs during device probing before
the scheduler starts. The `read_serial_into()` helper was added to operate
on a `BlkDevice` reference, and a `serial()` accessor was added for later
lookup. A second boot attempt was made. The system again timed out — the
boot log showed progress through blk probing but stalled at
`[blk] Found VirtIO blk at 0x10007000 (IRQ 7)` without printing the blk0
summary line. The issue was that `init_one()` ran before the PLIC was
configured and SIE was set for the VirtIO device IRQ, so the device
completion interrupt never fired and `wfi` slept forever.

**Step 4: Replace `wfi` with `spin_loop()`.** Since `init_one()` is called
before interrupts are enabled, the VirtIO device interrupt cannot unblock
`wfi`. The fix was to replace `unsafe { core::arch::asm!("wfi") }` with
`core::hint::spin_loop()` in `read_serial_into()`. A third boot succeeded:
the kernel printed `[blk] blk0: 32768 sectors (16 MiB), RW +flush
serial=""` — progress, but the serial strings came back empty.

**Step 5: QEMU serial= option placement.** The `serial=bin` option was
initially placed on the `-drive` line (e.g. `-drive
if=none,id=blk0,file=bin.img,format=raw,serial=bin`). The QEMU source
(`hw/block/virtio-blk.c`) showed that the VirtIO blk serial is set via the
`serial` property on the `-device` line, not the `-drive` line. The drive
serial (`blk_get_serial()`) is a block backend property that does not
propagate to the VirtIO device's GET_ID response. Moving the option to the
`-device virtio-blk-device,...,serial=bin` line returned the expected
serial strings.

**Step 6: MCP server also had hardcoded drives.** The MCP server
(`scripts/qemu-mcp/server.py`) constructs its own QEMU command independent
of the Makefile's `QEMU_BLK` variable. The `serial=` tags had to be added
there as well.

**Summary of dead ends:** (1) Calling `get_serial()` post-scheduler with
`wfi` — timer preemption prevents the polling loop from completing. (2)
Moving to `init_one()` while still using `wfi` — VirtIO IRQ not configured
yet, `wfi` sleeps forever. (3) Placing `serial=` on the `-drive` line —
this sets the block backend serial, not the VirtIO device GET_ID response.

## Root Cause

The low-level VirtIO drivers use `wfi` (Wait For Interrupt) as a synchronous
polling mechanism:

```rust
loop {
    if let Some((head, _len)) = dev.requestq.pop_used() {
        dev.requestq.free_chain(head);
        break;
    }
    unsafe { core::arch::asm!("wfi"); }
}
```

`wfi` halts the CPU until **any** interrupt fires — not just the VirtIO device
interrupt. Before the scheduler is running, the only interrupt source is the
VirtIO device itself, so this works correctly.

After the scheduler starts, the timer interrupt fires periodically. Each timer
interrupt invokes `preempt()`, which may call `schedule()` and switch to a
different task. The polling loop's execution context is suspended mid-loop.
This causes several problems:

1. **Preemption abandons the poll**: The task is placed on the ready queue and
   may not run again for an arbitrary amount of time.
2. **Shared DMA buffer corruption**: The `BlkDevice` struct has a single set of
   DMA buffers (`outhdr_buf`, `data_buf`, `status_buf`). If the preempted
   polling task runs concurrently with the `blk_server` kernel task (which uses
   the same device), the DMA buffers get corrupted.
3. **IRQ handler interaction**: The `handle_irq` function calls
   `wake_process(pid)` for the registered `blk_server` PID, not for whatever
   task is stuck in the `wfi` loop.

**Bug class:** Design constraint violation — synchronous polling mechanism
incompatible with preemptive scheduling.

## Current Mitigations

- `read_serial_into()` is called from `init_one()` during device init, which
  happens before the scheduler starts. This was explicitly moved there to avoid
  this bug (see comment on line 166: "Read serial/ID before interrupts and
  scheduler are enabled").
- The `blk_server` kernel task avoids this by using `set_wake_pid()` +
  `channel_recv_blocking()` (the scheduler's cooperative blocking mechanism)
  rather than direct `wfi` polling.
- The GPU and net drivers are similarly only used during early boot or from
  dedicated kernel tasks that use their own blocking mechanisms.

## Impact

**Currently low** — all callers are either pre-scheduler or use the scheduler's
blocking mechanism. But the public API (`read_sectors`, `write_sectors`,
`flush`) is `pub` and callable from anywhere, making this a latent footgun.
Any future code that calls these functions after boot will silently hang.

## Possible Fixes

1. **Disable timer interrupts around wfi polls** — Clear `STIE` (Supervisor
   Timer Interrupt Enable) in the `sie` CSR before the polling loop, restore
   after. This allows the device interrupt through but blocks preemption.
   Downside: increases interrupt latency for the timer during I/O.

2. **Replace wfi with spin_loop** — Use `core::hint::spin_loop()` instead of
   `wfi`. This avoids the interrupt problem entirely but wastes CPU cycles
   (acceptable for short device operations during early boot).

3. **Document the constraint** — Add `/// # Safety` or `/// # Panics`
   documentation stating these functions must only be called before the
   scheduler starts. Add a runtime assertion (`debug_assert!`) that the
   scheduler is not yet initialized.

4. **Add a scheduler-aware path** — If the scheduler is running, use
   `set_wake_pid()` + `block_current()` instead of `wfi`. This is the most
   correct fix but requires significant refactoring.

Option (3) is the simplest immediate fix. Option (1) or (4) would be needed if
any post-scheduler callers are required in the future.

## Fix

The immediate trigger was `read_serial_into()` being called after the scheduler
started. Fixed by:

1. Moving the serial read into `init_one()` (during device probe, before scheduler).
2. Replacing `wfi` with `core::hint::spin_loop()` in `read_serial_into()` since
   interrupts are not yet configured at that point.

The broader issue (public `read_sectors`/`write_sectors`/`flush` APIs using `wfi`)
remains a latent risk but is currently safe because all post-boot callers go
through `blk_server` which uses the scheduler's cooperative blocking.

## Verification

System boots successfully with serial reads during `init_one()`.

## Lessons Learned

VirtIO driver functions that use `wfi` polling are only safe before the scheduler
starts. Any new driver functionality that needs to run post-boot must use the
scheduler's blocking mechanism (`set_wake_pid` + `block_current`) instead.
