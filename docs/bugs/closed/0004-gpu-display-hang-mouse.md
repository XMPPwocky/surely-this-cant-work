# 0004: GPU display hang during mouse movement

**Reported:** 2026-02-12
**Status:** Closed (2026-02-15)
**Severity:** HIGH
**Subsystem:** virtio, gpu

## Symptoms

After running `/bin/winclient` from fbcon and moving the mouse for a while,
the display hangs. The serial console stays responsive. `ps` shows:

- gpu-server (PID 3) in **Ready** state at **99% CPU** (1s window), 7.6% (1m window)
- window-srv (PID 10) is **Blocked**
- All other GUI processes (fbcon, winclient, shell) are **Blocked**

The 1s/1m CPU discrepancy confirms the hang started recently, not at boot.
The bug is intermittent ("not quite deterministic").

Two failure modes were observed:
1. **Kernel panic** (with timeout): gpu-server hits the spin timeout in `send_command`
2. **Silent freeze** (without panic): gpu-server at 100% CPU, display frozen

## Reproduction Steps

1. `make run-gui`
2. In the fbcon shell, type `run /bin/winclient`
3. Move the mouse continuously over the winclient window for 10-30 seconds
4. Observe display freeze (serial console remains responsive)
5. Type `ps` in serial console to confirm gpu-server at 99% CPU

Intermittent: fails roughly 1 in 3-5 attempts with sustained mouse movement.

## Root Cause

**QEMU's VirtIO GPU uses deferred command processing (bottom-half).**

1. Each display frame requires the window-server to send a `Flush` request
   to gpu-server, which calls `flush_rect()` issuing two VirtIO commands
   (`transfer_to_host_2d` + `resource_flush`) via `send_command()`.
2. `send_command()` writes descriptors to the virtqueue, notifies the device
   via an MMIO write, then spin-polls `pop_used()` for command completion.
3. QEMU's VirtIO GPU does NOT process commands synchronously during the MMIO
   notify write. Instead, `virtio_gpu_handle_ctrl_cb` calls
   `qemu_bh_schedule(g->ctrl_bh)` to schedule a bottom-half (BH).
4. The BH runs from QEMU's main event loop, not during guest CPU emulation.
   A tight spin loop in the guest prevents QEMU from breaking out of the CPU
   emulation loop to run its event loop and process the BH.
5. The GPU never processes the command because its BH never runs.

**Why it was intermittent:** QEMU periodically breaks out of the CPU loop
for timer signals and I/O checking. Under light load, these breaks are
frequent enough for the BH to run between spin iterations. Under heavy load
(rapid mouse movement generating many flush requests), the spin loop can
starve QEMU's event loop long enough to deadlock.

**Code locations:**
- `kernel/src/drivers/virtio/gpu.rs` — `send_command()` tight spin loop
- `vendor/qemu/hw/display/virtio-gpu.c` — `virtio_gpu_handle_ctrl_cb()`
  schedules BH instead of processing inline

**Bug class:** Host event loop starvation (guest spin loop prevents
host-side deferred work from executing)

## Fix

Two changes:

### 1. WFI-based polling in `send_command()` (gpu.rs)

Replaced the tight spin loop with WFI (Wait For Interrupt) instruction.
WFI yields the RISC-V CPU, causing QEMU to break out of the CPU emulation
loop and run its event loop, which processes the VirtIO GPU bottom-half.

The GPU's PLIC interrupt is enabled during `gpu::init()`, so when the device
completes a command and raises an interrupt, WFI returns and `pop_used()`
finds the completed descriptor. A 1000-iteration timeout with diagnostic
panic provides a safety net.

During early boot (before `enable_timer()` sets `sstatus.SIE`), `sie.SEIE`
is explicitly enabled in `gpu::init()` so WFI can wake on GPU interrupts.

### 2. GPU interrupt handler (gpu.rs + trap.rs)

Added `handle_irq()` to acknowledge GPU interrupts (read `INTERRUPT_STATUS`,
write `INTERRUPT_ACK`), and `irq_number()` to expose the IRQ. Wired into
`external_interrupt()` in trap.rs alongside keyboard and tablet handlers.

### 3. Volatile DMA accesses (queue.rs)

Converted all DMA shared memory accesses in `queue.rs` from regular pointer
dereferences to `read_volatile`/`write_volatile`. While not the root cause
of this bug, non-volatile DMA access is a correctness issue (the compiler
may cache reads to device-modified memory). Functions updated:

- `pop_used()`: volatile read of `used.idx` and `used.ring[]`
- `push_avail()`: volatile read/write of `avail.idx` and `avail.ring[]`
- `write_desc()`: volatile write of all descriptor fields
- `alloc_desc()`: volatile read of `desc.next`
- `free_desc()`: volatile write of all descriptor fields
- `free_chain()`: volatile read of `desc.flags` and `desc.next`

## Verification

- `make build` succeeds with no errors
- `make clippy` clean (no warnings)
- Boot test (headless VNC mode): GPU init completes all 6 commands via
  WFI-based polling, gpu-server starts, fbcon renders, all processes running

## Lessons Learned

### 1. QEMU's VirtIO is asynchronous

VirtIO device implementations in QEMU use bottom-halves (BHs) for command
processing. The guest MUST yield CPU time (via WFI, HLT, or similar) to
let QEMU's event loop run. Tight spin loops will deadlock under load.

This applies to ALL VirtIO devices, not just GPU. The keyboard and tablet
drivers use interrupt-driven event processing (not spin polling), so they
are not affected. Any future VirtIO driver that spin-polls for completion
must use WFI.

### 2. Blast Radius

The same non-volatile DMA access pattern exists in:
- `kernel/src/drivers/virtio/tablet.rs` — event buffer read
- `kernel/src/drivers/virtio/input.rs` — event buffer read

These read event buffers AFTER `pop_used()` confirms the device has written
them, so the fence in `pop_used()` provides ordering. With `pop_used()` now
using `read_volatile`, these are less likely to trigger bugs, but should be
converted to `read_volatile` for correctness in a follow-up.

### 3. Prevention

Convention added to `kernel/CLAUDE.md`: all DMA shared memory accesses
must use `read_volatile`/`write_volatile`. Never create Rust references
to DMA memory.
