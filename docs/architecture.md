# rvOS Architecture

This document describes the internal architecture of rvOS: boot flow, memory
management, trap handling, context switching, scheduling, and the service model.

---

## 1. Boot Flow

The boot sequence has six phases, all orchestrated by `kmain()` in
`kernel/src/main.rs`.

### Phase 1: Hardware Init

1. **OpenSBI firmware** (provided by QEMU) initializes the machine, sets up
   M-mode trap delegation, and jumps to `0x80200000` (the kernel entry point).
2. **`boot.S`** runs: sets `sp` to the top of the 64 KiB boot stack, zeroes
   the `.bss` section, and calls `kmain`.
3. **UART init** — the 16550A at `0x10000000` is configured (divisor latch,
   FIFO enable, interrupts). Any characters buffered during firmware boot are
   drained into the serial ring buffer.

### Phase 2: Memory Management

1. **Heap** — a 4 MiB buddy allocator is initialized, enabling `Vec`,
   `Box`, `String`, etc. via `#[global_allocator]`. All heap allocations
   are tracked under 4-byte ASCII pool tags for per-subsystem memory
   accounting.
2. **Frame allocator** — a bitmap allocator scans from `_end` to `0x88000000`
   (128 MiB RAM top). Each bit represents one 4 KiB frame. Supports both
   single-frame and contiguous multi-frame allocation (needed for DMA and mmap).
3. **Kernel page table** — an Sv39 identity-mapped page table is built:
   - Kernel `.text` → R+X
   - Kernel `.rodata` → R
   - Kernel `.data`/`.bss`/stack → R+W
   - MMIO regions (UART, PLIC, CLINT, VirtIO) → R+W
   - Free memory → R+W
4. **Paging enabled** — `satp` is set to `mode=8 | root_ppn`, `sfence.vma`
   flushes the TLB. The kernel satp is saved for later restoration after
   user-mode traps.

### Phase 3: Traps and Devices

1. **Trap handler** — `stvec` is set to `_trap_entry` (in `trap.S`).
2. **PLIC** — the Platform-Level Interrupt Controller is initialized. UART
   (IRQ 10) and VirtIO keyboard IRQs are enabled at priority 1; the hart
   threshold is set to 0 (accept all priorities).
3. **VirtIO GPU** (optional) — probed at `0x10001000`..`0x10008000`. If
   present, a framebuffer is allocated via the GPU command protocol
   (`RESOURCE_CREATE_2D`, `RESOURCE_ATTACH_BACKING`, `SET_SCANOUT`). The
   framebuffer console (8x16 bitmap font) is initialized.
4. **VirtIO keyboard** (optional) — if present, initialized and its IRQ
   registered with the PLIC.

### Phase 4: Scheduler and IPC

1. **Scheduler** — the round-robin scheduler is initialized with capacity for
   64 processes. PID 0 is the idle task (the `kmain` loop itself).
2. **IPC channels** — the channel manager is initialized with 32 channel slots.
3. **TTY** — serial and (optionally) framebuffer ring buffers for keyboard
   input.

### Phase 5: Services and Processes

The kernel creates channels and spawns all services and user processes:

```
kmain
 ├── creates control channels for: serial-con, sysinfo, math, process-debug, timer
 ├── creates boot channels for: shell-serial
 ├── (with GPU) creates control channels for: gpu, kbd, mouse
 ├── (with net) creates control channels for: net-raw
 ├── spawns kernel tasks:
 │   ├── init         (service directory + process loader)
 │   ├── serial-con   (serial console server)
 │   ├── sysinfo      (process/memory info service)
 │   ├── math         (computation service)
 │   ├── proc-debug   (process debugger attach/step/breakpoint)
 │   ├── timer        (timed wakeups via IPC)
 │   ├── gpu-server   (VirtIO GPU wrapper, if GPU)
 │   ├── kbd-server   (VirtIO keyboard wrapper, if GPU)
 │   ├── mouse-server (VirtIO tablet wrapper, if GPU)
 │   └── net-server   (VirtIO net wrapper, if net device present)
 └── spawns user processes (ELF):
     ├── fs           (filesystem server, tmpfs)
     ├── shell-serial (interactive shell on serial)
     └── (with GPU) shell-fb (interactive shell on framebuffer)
```

Additional user processes spawned by init on demand:

- **net-stack** — user-space TCP/IP stack, connects to `net-raw`, registers
  as `"net"` service, provides TCP and UDP socket API
- **window-server** — compositing window manager (GPU mode)
- **fbcon** — framebuffer console multiplexer (GPU mode)

### Phase 6: Preemptive Scheduling

Timer, external, and software interrupts are enabled in `sie`. The first
timer interrupt is armed. `kmain` enters the idle loop: `schedule()` →
`fb_flush()` → `wfi`.

---

## 2. Memory Layout

### Physical Address Map (QEMU virt, 128 MiB)

| Address Range            | Device / Region               |
|--------------------------|-------------------------------|
| `0x0200_0000..0x0200_FFFF` | CLINT (timer, software IRQ) |
| `0x0C00_0000..0x0FFF_FFFF` | PLIC (interrupt controller) |
| `0x1000_0000..0x1000_0FFF` | UART 16550A                 |
| `0x1000_1000..0x1000_8FFF` | VirtIO MMIO (8 device slots)|
| `0x8000_0000..0x801F_FFFF` | OpenSBI firmware             |
| `0x8020_0000..kernel _end` | Kernel image (.text, .rodata, .data, .bss) |
| `_end..+64 KiB`            | Boot stack                  |
| `_end+64K..0x8800_0000`    | Free physical frames         |

### Virtual Memory (Sv39)

rvOS uses **identity mapping** throughout — virtual addresses equal physical
addresses for all mappings. This simplifies:

- DMA buffers (VirtIO GPU needs physical addresses)
- User pointer translation (VA→PA walk still required for validation, but
  the PA can be directly dereferenced by kernel code)
- mmap return values (the returned address works in both kernel and user
  page tables)

Each user process gets its own Sv39 page table with:
- Kernel pages mapped **without** the U bit (invisible to user code)
- User code/stack/mmap pages mapped **with** the U bit
- The kernel page table is a superset of all user page tables

### Page Table Hierarchy

```
Level 2 (root)    512 entries × 1 GiB each
  └─ Level 1      512 entries × 2 MiB each
       └─ Level 0  512 entries × 4 KiB each (leaf PTEs)
```

PTE flags: V (valid), R (read), W (write), X (execute), U (user), A (accessed),
D (dirty). rvOS sets A and D bits at map time to avoid hardware page faults.

---

## 3. Trap Handling

### Per-Task Trap Frames

Each process owns a `TrapContext` embedded directly in its `Process` struct.
The `TrapContext` contains:

```
Offset 0..255:   TrapFrame.regs[0..31]  (32 × 8 = 256 bytes)
Offset 256:      TrapFrame.sstatus      (8 bytes)
Offset 264:      TrapFrame.sepc         (8 bytes)
Offset 272:      kernel_stack_top       (8 bytes, per-task)
Offset 280:      user_satp              (8 bytes, user page table root)
```

The `sscratch` CSR **always** points to the current task's `TrapContext`.
This invariant is maintained at four update sites, all with interrupts
disabled:

1. `init()` — sets sscratch to the idle task's TrapContext
2. `schedule()` — updates sscratch before and after `switch_context`
3. `preempt()` — updates sscratch before `switch_context`
4. Trampolines — `kernel_task_trampoline` and `user_entry_trampoline`
   write sscratch from the s1 register on first entry

### Trap Entry (`trap.S`)

The trap vector at `_trap_entry` handles both S-mode and U-mode traps:

1. **Save context** — swaps `t0` with `sscratch` to get the TrapContext
   pointer, then saves all 32 GPRs + `sstatus` + `sepc` into the per-task
   TrapContext.

2. **Check origin** — reads `sstatus.SPP` (bit 8) to determine whether
   the trap came from S-mode (kernel, SPP=1) or U-mode (user, SPP=0).

3. **S-mode path** — the interrupted task was already running on its own
   kernel stack. Reload `sp` from the saved regs so call frames survive
   context switches. Call `trap_handler()`.

4. **U-mode path**:
   - Load the kernel `satp` from `KERNEL_SATP_RAW`
   - Execute `sfence.vma` to flush the TLB
   - Load the per-task `kernel_stack_top` from TrapContext offset 272
   - Switch `sp` to the task's kernel stack
   - Call `trap_handler()`

5. **Trap exit** (`_restore_from_trap`):
   - If returning to U-mode (SPP=0), switch to the user page table
     (load `user_satp` from TrapContext offset 280, write `satp`,
     `sfence.vma`)
   - Restore all 32 GPRs from the TrapContext
   - Write the TrapContext pointer back to `sscratch`
   - Execute `sret` back to the interrupted code

### Trap Dispatch (`trap.rs`)

The Rust trap handler classifies by `scause`:

| scause bit 63 | Code | Handler                          |
|---------------|------|----------------------------------|
| 1 (interrupt) | 5    | Timer tick → `preempt()`         |
| 1 (interrupt) | 9    | External → PLIC claim/dispatch   |
| 0 (exception) | 8    | Environment call → syscall       |
| 0 (exception) | 2    | Illegal instruction → panic      |
| 0 (exception) | 12,13,15 | Page fault → panic (no demand paging) |

### Syscall Handling

On `ecall` (exception code 8):
1. `sepc` is advanced by 4 (past the `ecall` instruction)
2. Syscall number read from `a7` (register x17)
3. Arguments from `a0`, `a1`
4. Return values written to `a0` (and `a1` for `SYS_CHAN_CREATE`)

---

## 4. Context Switching

### Kernel Context Switch (`switch.S`)

`switch_context(old_ctx, new_ctx)` saves/restores only callee-saved registers
(ra, sp, s0–s11) — the C calling convention guarantees that's sufficient:

```
switch_context:
    # Save callee-saved regs to old_ctx
    sd ra, 0(a0)
    sd sp, 8(a0)
    sd s0, 16(a0)
    ...
    sd s11, 104(a0)
    # Restore from new_ctx
    ld ra, 0(a1)
    ld sp, 8(a1)
    ld s0, 16(a1)
    ...
    ld s11, 104(a1)
    ret
```

### Task Trampolines

Both kernel and user tasks start via trampolines that establish the sscratch
invariant before entering the task. On first schedule, `switch_context` restores
`s1` to the TrapContext pointer (set up by `fixup_trap_ctx_ptr` in scheduler.rs).

**Kernel task trampoline** (`kernel_task_trampoline`):
1. Writes the TrapContext pointer (from `s1`) to `sscratch`
2. Jumps to `_restore_from_trap`, which executes `sret` into the entry
   function (TrapFrame was pre-filled with `sepc` = entry, `SPP=1`, `SPIE=1`)
3. If the entry function returns, `ra` points to `kernel_task_return_handler`,
   which marks the process as Dead and calls `schedule()` — the task exits
   cleanly instead of jumping to address 0.

**User entry trampoline** (`user_entry_trampoline`):
1. Writes the TrapContext pointer (from `s1`) to `sscratch`
2. Jumps to `_restore_from_trap`, which switches to the user page table
   (because TrapFrame has `SPP=0`), restores user registers, and `sret`s
   into user code at the ELF entry point

---

## 5. Scheduling

### Algorithm

Round-robin with timer preemption:

1. Timer fires every ~100ms (1,000,000 cycles at QEMU's 10 MHz clock)
2. Two context-switch paths exist:
   - **`schedule()`** — cooperative: called from `SYS_YIELD`, blocking
     operations, and the idle loop
   - **`preempt()`** — preemptive: called from the timer interrupt handler
     inside `trap_handler()`; receives the interrupted task's `TrapFrame`
     and returns it after the switch
3. The current process is pushed to the back of the ready queue
4. The next process is popped from the front
5. `switch_context()` switches callee-saved registers (kernel stacks)

Both paths maintain the sscratch invariant: before `switch_context`, sscratch
is set to the new task's TrapContext; after return (for `schedule()`), it is
restored to the resumed task's TrapContext.

### Process States

```
   spawn → Ready ←──────── wake_process()
             │                    ↑
        schedule()                │
             │                    │
             ↓                    │
          Running ──────→ Blocked (SYS_CHAN_RECV_BLOCKING)
             │
          SYS_EXIT
             │
             ↓
           Dead
```

### Interrupt Safety

The scheduler lock (`SpinLock<Scheduler>`) disables interrupts while held.
A critical invariant: the lock's `Drop` impl must **not** re-enable
interrupts before `switch_context` completes. The `suppress_irq_restore()`
method on `SpinLockGuard` prevents this by marking the guard so that `Drop`
leaves interrupts disabled. After `switch_context` returns and state is
consistent, `schedule()` manually re-enables interrupts if they were
originally on.

Without this, there is a race: `sched.current = next_pid` is set while
holding the lock, but if `Drop` re-enables interrupts before
`switch_context`, a timer interrupt could call `preempt()` which reads
the wrong `current` PID and corrupts the wrong task's `TaskContext`.

---

## 6. Service Architecture

rvOS follows a **microkernel service model**. All user-visible services run as
kernel tasks communicating over IPC channels. User processes access services
through the init server's service discovery protocol.

### Service Topology

```
                              ┌──────────┐
                              │   init   │ ← service directory + process loader
                              └────┬─────┘
        ┌──────────┬──────────┬────┼────┬────────────┬─────────────┐
        ↓          ↓          ↓    ↓    ↓            ↓             ↓
  ┌──────────┐ ┌────────┐ ┌────┐ ┌───┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
  │serial-con│ │sysinfo │ │math│ │tmr│ │proc-debug│ │net-server│ │gpu-server│
  └────┬─────┘ └────────┘ └────┘ └───┘ └──────────┘ └────┬─────┘ └──────────┘
       ↓                                                   ↓
  [shell-serial]                                      [net-stack] ← "net" service
  [shell-fb]                                               ↓
                                                      [tcp-echo]
                                                      [udp-echo]
```

Kernel tasks (in-process): init, serial-con, sysinfo, math, timer, proc-debug,
gpu-server, kbd-server, mouse-server, net-server.

User processes (ELF): fs, shell, net-stack, udp-echo, window-server, fbcon,
dbg, bench, winclient, triangle, gui-bench, ktest.

### Service Discovery Flow

1. User process sends service name (e.g., `"stdio"`) on handle 0 (boot channel)
2. Init receives the request, creates a new channel pair
3. Init sends one endpoint to the appropriate service server (via its control
   channel, as a capability)
4. Init sends the other endpoint back to the user process (via the boot
   channel, as a capability)
5. The user process now has a direct channel to the service

### Console Server

Each console server (serial, framebuffer) runs in a loop:
1. Wait for a client endpoint from init (via control channel)
2. Spawn a handler for this client
3. The handler reads from the client channel → writes to the hardware device
4. The handler reads from TTY input → sends to the client channel
5. When the client disconnects, loop back to step 1

The serial console server uses interrupt-driven input: UART IRQ 10 pushes
characters into a ring buffer, and the server reads from it. The framebuffer
console uses the VirtIO keyboard input device similarly.

---

## 7. User Process Model

### ELF Loading

User programs are compiled as standard RISC-V ELF binaries and embedded into
the kernel image at build time. The ELF loader:

1. Validates the ELF header (magic, class=64, machine=RISC-V)
2. Iterates PT_LOAD segments
3. Allocates physical frames for each segment
4. Copies segment data from the ELF
5. Maps pages into the process's page table with appropriate permissions
6. Sets the entry point from the ELF header

### Address Space

Each user process gets:
- **Code pages** — loaded from ELF segments, mapped U+R+W+X
- **Stack** — 8 pages (32 KiB), mapped U+R+W, grows downward
- **Kernel stack** — 16 pages (64 KiB) + 1 guard page, mapped without U bit
  (kernel-only). The guard page at the bottom is unmapped; any stack overflow
  triggers a page fault instead of silently corrupting adjacent memory.
- **mmap regions** — dynamically allocated via `SYS_MMAP`, mapped U+R+W

### Handle Table

Each process has a 32-slot handle table mapping local indices to global IPC
endpoint IDs or SHM region references. Handle 0 is the boot channel by
convention. Handles are the process's capabilities — they determine which
channels and shared memory regions the process can access.

---

## 8. Assembly Files

rvOS has exactly 4 assembly files (< 400 lines total):

| File | Purpose |
|------|---------|
| `boot.S` | Machine entry: set stack, zero BSS, call `kmain` |
| `trap.S` | Trap entry/exit for S-mode and U-mode, register save/restore, satp switching |
| `switch.S` | Context switch (callee-saved), kernel task trampoline, user entry trampoline |
| `user_programs.S` | `.incbin` directives embedding user ELF binaries into the kernel image |

Everything else is Rust with inline `asm!` for CSR access, `wfi`,
`sfence.vma`, and `ecall`.
