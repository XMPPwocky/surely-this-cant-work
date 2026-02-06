# rvOS

A from-scratch RISC-V 64-bit microkernel operating system written in Rust. Targets `qemu-system-riscv64` (virt machine). Zero external crates — only `core` and `alloc` in the kernel.

~5,000 lines of Rust and RISC-V assembly across 40+ source files.

## Features

- **Sv39 virtual memory** — 3-level page tables with identity-mapped kernel and per-process user address spaces
- **Preemptive multitasking** — round-robin scheduler driven by timer interrupts, context switch in ~28 instructions
- **User mode** — processes run in U-mode with separate page tables; kernel pages are inaccessible from user code
- **ELF loader** — loads standard RISC-V ELF binaries as user processes
- **Capability-based IPC** — Fuchsia-style bidirectional channels with capability passing; all I/O is channel-based
- **Service discovery** — init server acts as a service directory; user processes request services by name and receive channel capabilities
- **mmap/munmap** — user processes can dynamically allocate and free memory pages
- **Rust std support** — custom `riscv64gc-unknown-rvos` compiler target enables user programs with full Rust `std`
- **Interrupt-driven I/O** — UART and keyboard input via IRQ with ring buffers and process wake-up
- **UART serial console** — 16550A driver with `print!`/`println!` macros via `core::fmt::Write`
- **VirtIO GPU driver** — MMIO transport, split virtqueue, framebuffer console with 8x16 bitmap font
- **Buddy allocator** — physical frame allocator with efficient contiguous allocation for DMA
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
make build    # Build kernel + user programs
make run      # Boot in QEMU (serial on stdio)
```

### Shell Commands

Once booted, an interactive shell appears on the serial console:

```
rvos> help       # List available commands
rvos> echo hi    # Echo text
rvos> ps         # Process list (via sysinfo service)
rvos> math add 3 5   # Math service (add/mul/sub)
rvos> shutdown   # Shut down the system
```

## Architecture

rvOS follows a **microkernel service model**. All user-visible services (console I/O, process info, math) run as kernel tasks communicating over IPC channels. User processes access services through capability-based channel endpoints obtained via the init server.

### Process List

| PID | Name | Type | Role |
|-----|------|------|------|
| 0 | idle | kernel | Idle loop (kmain) |
| 1 | init | kernel | Service directory |
| 2 | serial-con | kernel | Serial console server |
| 3 | fb-con | kernel | Framebuffer console (if GPU) |
| 4 | sysinfo | kernel | Process list service |
| 5 | math | kernel | Computation service |
| 6 | hello-std | user | Test program (Rust std) |
| 7 | shell-serial | user | Interactive shell (serial) |
| 8 | shell-fb | user | Interactive shell (framebuffer, if GPU) |

### IPC Model

```
User Process                     Init Server                 Service
     |                               |                          |
     |-- "stdio" on boot channel --->|                          |
     |                               |-- endpoint via ctrl ch ->|
     |<-- channel cap on boot ch ----|                          |
     |                                                          |
     |============= direct channel ============================|
     |-- write data -->                              <-- read --|
     |<-- input data --                              -- send -->|
```

### Memory Layout (QEMU virt, 128 MiB)

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

### Syscall Interface

| # | Name | Description |
|---|------|-------------|
| 93 | `SYS_EXIT` | Terminate process |
| 124 | `SYS_YIELD` | Yield CPU |
| 172 | `SYS_GETPID` | Get process ID |
| 200 | `SYS_CHAN_CREATE` | Create bidirectional channel pair |
| 201 | `SYS_CHAN_SEND` | Send message on channel |
| 202 | `SYS_CHAN_RECV` | Non-blocking receive |
| 203 | `SYS_CHAN_CLOSE` | Close channel handle |
| 204 | `SYS_CHAN_RECV_BLOCKING` | Blocking receive |
| 222 | `SYS_MMAP` | Allocate and map pages |
| 215 | `SYS_MUNMAP` | Unmap and free pages |

See [docs/kernel-abi.md](docs/kernel-abi.md) for the full ABI reference.

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
- `user_programs.S` — embedded user ELF binaries

Everything else is Rust with inline `asm!` for CSR access, `wfi`, `sfence.vma`, and `ecall`.

## Project Structure

```
rvos/
├── Makefile                     # build, run, run-gui, run-vnc, debug, clean
├── kernel/
│   ├── Cargo.toml
│   ├── linker.ld                # Kernel at 0x80200000
│   └── src/
│       ├── main.rs              # Entry point, boot sequence, service spawning
│       ├── arch/                # boot.S, trap.S, switch.S, trap.rs, paging, CSR
│       ├── mm/                  # Heap, frame allocator, Sv39 page tables
│       ├── task/                # Process model and round-robin scheduler
│       ├── ipc/                 # Bidirectional channel IPC
│       ├── services/            # init, console, sysinfo, math servers
│       ├── drivers/             # UART, PLIC, TTY, VirtIO (GPU, keyboard)
│       ├── console/             # print! macros, framebuffer text rendering
│       └── sync/                # SpinLock with interrupt save/restore
├── user/
│   ├── shell/                   # Interactive shell (no_std, raw syscalls)
│   ├── hello/                   # Hello world with Rust std
│   └── rvos-rt/                 # Runtime crate for std programs
├── lib/
│   ├── rvos-wire/               # Serialization library (no_std)
│   └── rust-std/                # Patched Rust std library sources
├── vendor/
│   ├── rust/                    # Custom Rust compiler (rvOS target)
│   ├── qemu/                    # QEMU source (device reference)
│   └── riscv-isa-manual/        # RISC-V ISA specification
└── docs/
    ├── architecture.md          # System architecture deep-dive
    ├── kernel-abi.md            # Syscall and IPC ABI reference
    └── building.md              # Build system and development guide
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build kernel + all user programs |
| `make run` | Boot in QEMU with serial on stdio |
| `make run-gui` | Boot with VirtIO GPU (requires X/GTK display) |
| `make run-vnc` | Boot with VirtIO GPU on VNC port 5900 |
| `make run-gpu-screenshot` | Headless GPU boot + PPM screenshot |
| `make debug` | QEMU with GDB stub (`-s -S`) |
| `make clean` | Remove build artifacts |

## Documentation

- [Architecture Overview](docs/architecture.md) — boot flow, trap handling, context switching, service model
- [Kernel ABI Reference](docs/kernel-abi.md) — syscalls, message format, handle table, boot protocol
- [Building Guide](docs/building.md) — toolchain setup, build system, adding user programs

## Design Decisions

- **No external crates** — kernel built on `core` and `alloc` only
- **Identity-mapped kernel** — simplifies early boot and VA↔PA conversion
- **Channel-based I/O** — all user I/O goes through IPC channels (no direct read/write syscalls)
- **Capability passing** — channel endpoints transferred between processes via messages
- **Buddy allocator** — efficient O(log n) allocation with contiguous frame support for DMA
- **Round-robin scheduling** — timer-driven preemption at ~100ms intervals; cooperative yield also available
- **Custom Rust target** — `riscv64gc-unknown-rvos` enables user programs with full Rust `std` support

## License

Educational / research use. No license specified.
