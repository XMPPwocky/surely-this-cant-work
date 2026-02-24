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

## Investigation

The investigation proceeded through several phases, each revealing a deeper layer of the problem.

### Phase 1: Static code analysis

The bug was reported with `ps` output showing gpu-server (PID 3) in `Ready` state at 99% CPU.
The `Ready` (not `Blocked`) state with high CPU immediately pointed to a spin loop rather than an
IPC deadlock. Three background subagents explored the GPU driver, window-server, and IPC subsystem
in parallel while the main agent traced the call path from mouse event to GPU flush.

Several theories were evaluated:
- **Lost wakeup race in IPC**: Ruled out — would result in both parties `Blocked`, not one at 99% CPU `Ready`.
- **Channel deadlock**: Lock-step protocol means at most 1 message in flight; no deadlock path found.
- **Frame allocator double-allocation**: Ruled out by bitmap implementation.
- **Descriptor free list corruption**: Traced through carefully, appeared correct.
- **Non-volatile DMA reads (initial primary theory)**: `pop_used()` in `queue.rs` read `used.idx`
  through a regular pointer dereference rather than `read_volatile`. If the compiler cached this read,
  the spin loop would never observe the device updating the used ring.

### Phase 2: Volatile DMA fix — necessary but not sufficient

The non-volatile DMA theory was plausible and the fix was correct practice, so volatile reads/writes
were applied to all DMA shared memory accesses in `queue.rs`. A spin timeout with panic was also added
to `send_command()` in `gpu.rs` to convert silent hangs to observable panics.

After deploying these changes and triggering the bug, the kernel panic fired — confirming the
gpu-server was genuinely stuck waiting for a VirtIO command that never completed. The volatile fix
was correct but had not resolved the hang: the VirtIO GPU device itself was not responding.

### Phase 3: QEMU source analysis — discovering deferred BH processing

With the timeout confirming a device-level issue, the QEMU source (`vendor/qemu/hw/display/virtio-gpu.c`)
was examined. The critical finding: `virtio_gpu_handle_ctrl_cb()` does NOT process commands
synchronously when the guest writes `QUEUE_NOTIFY`. Instead, it calls `qemu_bh_schedule(g->ctrl_bh)`
to schedule a bottom-half (BH) that runs later from QEMU's main event loop (`main_loop_wait()`).

The BH only executes when `cpu_exec()` yields back to the event loop. Under normal load, QEMU's
host alarm timer (~10ms) periodically fires `exit_request`, causing `cpu_exec()` to yield.
Under heavy load (rapid mouse movement generating continuous flush requests), the guest's tight spin
loop kept the CPU emulation running without interruption, starving the event loop and preventing the
BH from ever running.

An intermediate theory considered adding a VirtIO MMIO register read inside the spin loop: MMIO
accesses force Translation Block (TB) boundaries in QEMU TCG, which would give the host alarm timer
opportunities to set `exit_request`. This approach was superseded by the cleaner WFI solution.

### Phase 4: WFI fix and secondary bug (SEIE not set during gpu init)

The WFI (`wfi`) instruction was chosen as the fix: it yields the RISC-V CPU, causing QEMU to break
out of `cpu_exec()` and run its event loop, processing the GPU BH. A GPU PLIC interrupt handler was
added so WFI would return when the device completed a command.

An initial boot attempt with this fix failed — the GPU init sequence hung at the first `send_command`
call. Investigation revealed that `gpu::init()` runs before `enable_timer()` which sets `sie.SEIE`
(external interrupt enable). Without SEIE, WFI never woke on GPU interrupts. Fix: explicitly enable
`sie.SEIE` in `gpu::init()` before the first `send_command` call.

After this fix, boot succeeded and the GPU init completed all six initialization commands via
WFI-based polling.

### Phase 5: Tertiary bug — shared KERNEL_TRAP_STACK corruption

After the WFI fix was deployed, interactive testing with `make run-gui` revealed a new failure mode:
during mouse movement, the display still froze, but now with a kernel diagnostic:

```
Page fault (instruction): sepc=0x15e1a, stval=0x15e1a, SPP=0 (U-mode)
  sstatus=0x8000000200046020 ra=0x15de4 sp=0x81f51de0
  current_pid=3
  Killing user process due to page fault
```

The gpu-server (PID 3) was dying with `SPP=0` (U-mode) even though it is a kernel task running in
S-mode, and `sepc`/`ra` pointed into user-address space. This indicated trap frame corruption.

Analysis of `trap.S` revealed the root cause: the `_from_kernel` path used a single shared
`KERNEL_TRAP_STACK` for all kernel task traps. When gpu-server executed `wfi` and a timer interrupt
fired: (1) the trap frame was saved on the shared stack, (2) `timer_tick()` called `schedule()`,
(3) another kernel task ran and took a timer interrupt — overwriting the same shared trap stack
location, (4) when gpu-server was rescheduled, it restored the corrupted trap frame and jumped to
a garbage address.

This secondary bug was architectural: the `_from_kernel` trap handler called `schedule()` which
re-enabled interrupts mid-handler, making the handler re-entrant against the shared trap stack.
This issue was always latent but only became visible once WFI made kernel tasks susceptible to
being interrupted while waiting for device completions. The resolution was feature 0007
(per-task trap frames), which moved trap frames from the shared stack into each `Process` struct.

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
