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

1. **Heap** — a 1 MiB linked-list allocator is initialized, enabling `Vec`,
   `Box`, `String`, etc. via `#[global_allocator]`.
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
 ├── creates control channels for: serial-con, fb-con, sysinfo, math
 ├── creates boot channels for: shell-serial, shell-fb, hello-std
 ├── spawns kernel tasks:
 │   ├── init         (service directory)
 │   ├── serial-con   (serial console server)
 │   ├── fb-con       (framebuffer console server, if GPU)
 │   ├── sysinfo      (process list service)
 │   └── math         (computation service)
 └── spawns user processes (ELF):
     ├── hello-std    (test program using Rust std)
     ├── shell-serial (interactive shell on serial)
     └── shell-fb     (interactive shell on framebuffer, if GPU)
```

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

### Trap Entry (`trap.S`)

The trap vector at `_trap_entry` handles both S-mode and U-mode traps:

1. **Check origin** — reads `sscratch`: if zero, the trap came from S-mode
   (kernel); if nonzero, it came from U-mode (user).

2. **S-mode path** — saves all 32 GPRs + `sstatus` + `sepc` onto the
   current kernel stack as a `TrapFrame`, calls `trap_handler()`, restores
   registers, executes `sret`.

3. **U-mode path**:
   - Swaps `sp` and `sscratch` (sscratch held the kernel stack pointer)
   - Saves all user registers to the kernel stack as a `TrapFrame`
   - Loads the kernel `satp` from a global variable
   - Executes `sfence.vma` to flush the TLB
   - Calls `trap_handler()`
   - On return: reloads the user `satp`, flushes TLB, restores user
     registers, restores `sscratch`, and executes `sret` back to U-mode

### Trap Dispatch (`trap.rs`)

The Rust trap handler classifies by `scause`:

| scause bit 63 | Code | Handler                          |
|---------------|------|----------------------------------|
| 1 (interrupt) | 5    | Timer tick → reschedule          |
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

### New Kernel Task Trampoline

New kernel tasks start via `kernel_task_trampoline`:
1. Enables interrupts (`csrsi sstatus, 2` — sets SIE)
2. Jumps to the task's entry function (`jr s0`)

This is needed because new tasks enter via `ret` (not `sret`), so `sstatus.SIE`
wouldn't be restored from `sstatus.SPIE` automatically.

### User Entry Trampoline

User processes start via `user_task_trampoline`:
1. Loads the user's `satp` from a global variable
2. Sets `sstatus.SPP = 0` (return to U-mode)
3. Sets `sepc` to the user entry point
4. Flushes TLB
5. Restores user registers (sp, etc.)
6. Stores the kernel stack pointer in `sscratch`
7. Executes `sret` → user code begins at the entry point

---

## 5. Scheduling

### Algorithm

Round-robin with timer preemption:

1. Timer fires every ~100ms (1,000,000 cycles at QEMU's 10 MHz clock)
2. `schedule()` is called from the timer handler (preemptive) or from
   `SYS_YIELD` / blocking operations (cooperative)
3. The current process is pushed to the back of the ready queue
4. The next process is popped from the front
5. `switch_context()` switches kernel stacks

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
A critical invariant: `disable_interrupts()` must be called **before** dropping
the scheduler lock in `schedule()`, because the `Drop` impl re-enables
interrupts. Without this, there's a race window where a timer interrupt could
re-enter `schedule()` between lock release and context switch.

---

## 6. Service Architecture

rvOS follows a **microkernel service model**. All user-visible services run as
kernel tasks communicating over IPC channels. User processes access services
through the init server's service discovery protocol.

### Service Topology

```
                    ┌──────────┐
                    │   init   │ ← service directory
                    └────┬─────┘
           ┌─────────────┼─────────────┬──────────────┐
           ↓             ↓             ↓              ↓
     ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
     │serial-con│  │  fb-con  │  │ sysinfo  │  │   math   │
     └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
          ↓             ↓             ↓              ↓
     [shell-serial] [shell-fb]    (on demand)    (on demand)
```

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
- **Kernel stack** — 4 pages (16 KiB), mapped without U bit (kernel-only)
- **mmap regions** — dynamically allocated via `SYS_MMAP`, mapped U+R+W

### Handle Table

Each process has a 16-slot handle table mapping local indices to global IPC
endpoint IDs. Handle 0 is the boot channel by convention. Handles are the
process's capabilities — they determine which channels the process can
communicate on.

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
