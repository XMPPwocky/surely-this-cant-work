# rvOS

A from-scratch RISC-V 64-bit microkernel operating system written in Rust. Targets `qemu-system-riscv64` (virt machine). Zero external crates — only `core` and `alloc`.

~4,200 lines of Rust and RISC-V assembly across 33 source files.

## Features

- **Sv39 virtual memory** — 3-level page tables with identity-mapped kernel and per-process user address spaces
- **Preemptive multitasking** — round-robin scheduler driven by timer interrupts, context switch in ~28 instructions
- **User mode** — processes run in U-mode with separate page tables; kernel pages are inaccessible from user code
- **Syscall interface** — `ecall`-based: `SYS_WRITE`, `SYS_EXIT`, `SYS_YIELD`, `SYS_GETPID`, plus IPC syscalls
- **Async IPC channels** — kernel-buffered message passing between processes
- **Interrupt handling** — full trap vector with save/restore of all 32 registers + CSRs, PLIC for external interrupts
- **UART serial console** — 16550A driver with `print!`/`println!` macros via `core::fmt::Write`
- **VirtIO GPU driver** — MMIO transport, split virtqueue, GPU command interface (framebuffer console with 8x16 bitmap font)
- **Physical frame allocator** — bitmap-based, supports contiguous allocation
- **Kernel heap** — linked-list free-list allocator (`#[global_allocator]`), enabling `Vec`, `Box`, `String`
- **SpinLock** — atomic spinlock with RAII guard and interrupt disable/restore

## Screenshot

VirtIO GPU framebuffer console showing the full demo (boot, kernel tasks, IPC, user mode, shutdown):

![rvOS boot screenshot](screenshots/boot.png)

## Quick Start

### Prerequisites

```bash
# Rust nightly with RISC-V target
rustup default nightly
rustup target add riscv64gc-unknown-none-elf
rustup component add rust-src llvm-tools-preview

# QEMU
sudo apt-get install -y qemu-system-misc
```

### Build and Run

```bash
make build    # Build kernel binary
make run      # Boot in QEMU (serial on stdio)
```

### Sample Output

```
  ________  ____  _____
  |_____  \/ /\ \/  __ \  ___
   _ __|  / /  \    / / / /__\
  | | |\ \ \  / \  / / /\___  \
  |_|  \_\_\/ /\_\/__/  \____/

  rvOS v0.1.0 -- RISC-V 64-bit Microkernel
  QEMU virt machine, 128 MiB RAM

Heap initialized: 1024 KiB
Frame allocator: 795 frames reserved, 32768 total (124 MiB free)
[boot] Sv39 paging enabled (root PPN=0x8031b)

Trap handler installed at 0x80200034
PLIC initialized (UART IRQ 10 enabled)
Scheduler initialized (max 64 processes)
[demo] Spawning kernel demo tasks...
  Spawned [1] "counter-A" (PID 1)
  Spawned [2] "counter-B" (PID 2)
  Spawned [3] "ping" (PID 3)
  Spawned [4] "pong" (PID 4)
[demo] Spawning user-mode tasks...
  Spawned user [5] "user-hello" (PID 5)
  Spawned user [6] "user-getpid" (PID 6)

[counter-A] pid=1 iteration 0
[counter-B] pid=2 iteration 0
[ping] sent ping #0
[pong] received: "ping" from PID 3
[pong] sent pong reply
User OK!
PID=6
[ping] received: "pong" from PID 4
...
[shutdown] rvOS shutting down. Goodbye!
```

## Project Structure

```
rvos/
├── Makefile                     # build, run, run-gui, run-vnc, debug, clean
├── kernel/
│   ├── Cargo.toml
│   ├── linker.ld                # Kernel at 0x80200000, BSS markers, 64K boot stack
│   └── src/
│       ├── main.rs              # Entry point, demo task spawning, shutdown
│       ├── panic.rs             # Panic handler with CSR dump
│       ├── arch/
│       │   ├── boot.S           # Assembly entry: set stack, zero BSS, call kmain
│       │   ├── trap.S           # Trap vector: save/restore regs, U/S-mode dispatch
│       │   ├── switch.S         # Context switch (callee-saved), user entry trampoline
│       │   ├── user_programs.S  # Embedded user-mode programs (raw RISC-V machine code)
│       │   ├── trap.rs          # Trap dispatcher, syscall handler, timer/PLIC handling
│       │   ├── paging.rs        # Kernel page table setup, enable Sv39
│       │   ├── csr.rs           # CSR read/write macros (sstatus, scause, satp, etc.)
│       │   └── sbi.rs           # SBI calls (console, timer, shutdown)
│       ├── mm/
│       │   ├── address.rs       # PhysAddr, VirtAddr, PhysPageNum, VirtPageNum newtypes
│       │   ├── frame.rs         # Bitmap physical frame allocator (128MB / 4K = 32768 frames)
│       │   ├── heap.rs          # Linked-list kernel heap allocator (1MB, #[global_allocator])
│       │   └── page_table.rs    # Sv39 PageTable: map/unmap/translate, PTE flags
│       ├── task/
│       │   ├── process.rs       # Process struct, user/kernel creation, user page tables
│       │   ├── scheduler.rs     # Round-robin scheduler, spawn, schedule, exit, process list
│       │   └── context.rs       # TaskContext (callee-saved regs for kernel switch)
│       ├── ipc/
│       │   └── mod.rs           # Channel-based IPC: create, send, recv, close
│       ├── drivers/
│       │   ├── uart.rs          # UART 16550A (0x10000000): polling putchar/getchar
│       │   ├── plic.rs          # PLIC (0x0C000000): init, claim, complete
│       │   └── virtio/
│       │       ├── mmio.rs      # VirtIO MMIO transport: probe, init, register access
│       │       ├── queue.rs     # Split virtqueue: descriptor table, avail/used rings
│       │       └── gpu.rs       # VirtIO GPU: display info, resource create, scanout, flush
│       ├── console/
│       │   ├── mod.rs           # print!/println! macros, dual UART + framebuffer output
│       │   ├── framebuffer.rs   # FbConsole: pixel rendering, cursor, scrolling
│       │   └── font.rs          # 8x16 bitmap font (128 ASCII characters)
│       └── sync/
│           └── spinlock.rs      # SpinLock<T> with RAII guard, interrupt save/restore
└── vendor/
    ├── qemu/                    # QEMU source (submodule, for driver reference)
    └── riscv-isa-manual/        # RISC-V ISA spec (submodule, for arch reference)
```

## Architecture

### Memory Layout (QEMU virt, 128MB)

| Range | Contents |
|-------|----------|
| `0x02000000` | CLINT (timer) |
| `0x0C000000` | PLIC (interrupt controller) |
| `0x10000000` | UART 16550A |
| `0x10001000` | VirtIO MMIO devices (8 slots) |
| `0x80000000` | OpenSBI firmware |
| `0x80200000` | Kernel image (text, rodata, data, bss) |
| `_end + 64K` | Boot stack top |
| `_end` ... `0x88000000` | Free physical frames |

### User Mode

User processes get their own Sv39 page table:
- Kernel memory mapped without U-bit (inaccessible from user code)
- User code and stack pages mapped with U-bit
- Trap entry switches to kernel page table before accessing kernel stack
- `sret` returns to user code with SPP=0 (U-mode)

### Assembly

Only 4 assembly files (< 400 lines total):
- `boot.S` — set stack, zero BSS, jump to Rust
- `trap.S` — trap entry/exit for both S-mode and U-mode traps
- `switch.S` — context switch + kernel/user task trampolines
- `user_programs.S` — embedded user programs as raw machine code

Everything else is Rust with inline `asm!` for CSR access, `wfi`, `sfence.vma`, and `ecall`.

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build kernel ELF and raw binary |
| `make run` | Boot in QEMU with serial on stdio |
| `make run-gui` | Boot with VirtIO GPU (requires X/GTK display) |
| `make run-vnc` | Boot with VirtIO GPU on VNC port 5900 |
| `make run-gpu-screenshot` | Headless GPU boot + PPM screenshot |
| `make debug` | QEMU with GDB stub (`-s -S`) |
| `make clean` | Remove build artifacts |

## Design Decisions

- **No external crates** — everything built on `core` and `alloc` only
- **Identity-mapped kernel** — simplifies early boot and physical/virtual address conversion
- **Polling I/O** — UART and VirtIO GPU use polling (interrupt-driven is available via PLIC but not required for the demo)
- **Bitmap frame allocator** — simple, O(n) scan but sufficient for 128MB; supports contiguous allocation for DMA buffers
- **Linked-list heap** — first-fit with coalescing; backs `Vec`, `Box`, `String` via `#[global_allocator]`
- **Round-robin scheduling** — timer-driven preemption at ~10ms intervals; cooperative yield also available

## License

Educational / research use. No license specified.
