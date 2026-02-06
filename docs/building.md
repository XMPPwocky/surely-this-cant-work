# Building rvOS

This document explains the rvOS build system, toolchain requirements, and how
to build and run the system.

---

## 1. Prerequisites

### Rust Toolchain

rvOS requires Rust nightly with the RISC-V bare-metal target:

```bash
rustup default nightly
rustup target add riscv64gc-unknown-none-elf
rustup component add rust-src llvm-tools-preview
```

### Custom Rust Toolchain (for std programs)

User programs that use Rust `std` (like `hello-std`) require a custom Rust
compiler with the `riscv64gc-unknown-rvos` target. This compiler lives at
`vendor/rust/` and must be built once:

```bash
cd vendor/rust
./x build library --target riscv64gc-unknown-rvos
rustup toolchain link rvos build/host/stage1
```

After this, `cargo +rvos` will use the custom toolchain.

### QEMU

```bash
sudo apt-get install -y qemu-system-misc
```

The project vendors QEMU source at `vendor/qemu/` for driver reference, but
the system QEMU package is used for running.

---

## 2. Build System

The top-level `Makefile` orchestrates building all components.

### Components

| Component | Location | Target | Build Command |
|-----------|----------|--------|---------------|
| Kernel | `kernel/` | `riscv64gc-unknown-none-elf` | `cargo build --release` |
| Shell | `user/shell/` | `riscv64gc-unknown-none-elf` | `cargo build --release` (with `CARGO_ENCODED_RUSTFLAGS=""`) |
| Hello (std) | `user/hello/` | `riscv64gc-unknown-rvos` | `cargo +rvos build --release` |
| Runtime | `user/rvos-rt/` | (library) | Built as dependency of hello |
| Wire format | `lib/rvos-wire/` | (library) | Built as dependency of shell |

### Build Order

```
build-shell  ──┐
build-hello  ──┼──→  build (kernel)  ──→  objcopy (ELF → raw binary)
               │
```

The kernel build depends on the user binaries because they are embedded via
`.incbin` directives in `arch/user_programs.S`.

### Key Build Details

**Shell crate**: Built with `CARGO_ENCODED_RUSTFLAGS=""` to prevent the
kernel's linker script (`kernel/linker.ld`) from being applied. The shell
uses its own linker script (`user/shell/linker.ld`).

**Hello (std) crate**: Built with `cargo +rvos` using the custom Rust
toolchain. The workspace `.cargo/config.toml` is temporarily renamed during
the build to avoid target conflicts.

**Kernel binary**: The ELF is converted to a raw binary via `rust-objcopy
--strip-all -O binary`. QEMU's `-kernel` flag loads this binary at
`0x80200000`.

---

## 3. Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build everything (shell, hello, kernel, objcopy) |
| `make build-shell` | Build only the shell user program |
| `make build-hello` | Build only the hello-std test program |
| `make run` | Build and boot in QEMU with serial on stdio |
| `make run-gui` | Build and boot with VirtIO GPU (requires X/GTK display) |
| `make run-vnc` | Build and boot with VirtIO GPU on VNC port 5900 |
| `make run-gpu-screenshot` | Headless GPU boot + PPM screenshot |
| `make debug` | Build and boot with GDB stub (`-s -S`) |
| `make clean` | Remove all build artifacts |

### Screenshot Mode

For headless testing of the framebuffer:

```bash
make run-gpu-screenshot DELAY=5 SCREENSHOT=/tmp/rvos.ppm
```

This starts QEMU with a VNC display and monitor socket, waits `DELAY`
seconds, takes a PPM screenshot via the QEMU monitor, then kills QEMU.
Requires `socat`.

---

## 4. Project Layout

```
rvos/
├── Makefile                      # Top-level build orchestration
├── Cargo.toml                    # Workspace root
├── .cargo/config.toml            # Default target = riscv64gc-unknown-none-elf
├── kernel/
│   ├── Cargo.toml
│   ├── linker.ld                 # Kernel at 0x80200000, BSS markers, stack
│   └── src/
│       ├── main.rs               # kmain, boot sequence, service spawning
│       ├── panic.rs              # Panic handler with CSR dump
│       ├── arch/
│       │   ├── boot.S            # Entry: set stack, zero BSS, call kmain
│       │   ├── trap.S            # Trap vector: save/restore, U/S dispatch
│       │   ├── switch.S          # Context switch, trampolines
│       │   ├── user_programs.S   # .incbin user ELF binaries
│       │   ├── trap.rs           # Syscall handler, timer, PLIC dispatch
│       │   ├── paging.rs         # Kernel page table setup
│       │   ├── csr.rs            # CSR read/write macros
│       │   └── sbi.rs            # SBI calls (timer, shutdown)
│       ├── mm/
│       │   ├── address.rs        # PhysAddr, VirtAddr newtypes
│       │   ├── frame.rs          # Bitmap frame allocator
│       │   ├── heap.rs           # Linked-list kernel heap
│       │   └── page_table.rs     # Sv39 page table operations
│       ├── task/
│       │   ├── process.rs        # Process struct, ELF loader
│       │   ├── scheduler.rs      # Round-robin scheduler
│       │   └── context.rs        # TaskContext (callee-saved regs)
│       ├── ipc/
│       │   └── mod.rs            # Bidirectional channels
│       ├── services/
│       │   ├── init.rs           # Service directory (init server)
│       │   ├── console.rs        # Serial + FB console servers
│       │   ├── sysinfo.rs        # Process list service
│       │   └── math.rs           # Math computation service
│       ├── drivers/
│       │   ├── uart.rs           # UART 16550A
│       │   ├── plic.rs           # PLIC interrupt controller
│       │   ├── tty.rs            # TTY ring buffers
│       │   └── virtio/
│       │       ├── mmio.rs       # VirtIO MMIO transport
│       │       ├── queue.rs      # Split virtqueue
│       │       ├── gpu.rs        # VirtIO GPU driver
│       │       └── input.rs      # VirtIO keyboard driver
│       ├── console/
│       │   ├── mod.rs            # print!/println! macros
│       │   ├── framebuffer.rs    # Framebuffer text console
│       │   └── font.rs           # 8x16 bitmap font
│       └── sync/
│           └── spinlock.rs       # SpinLock<T> with interrupt save/restore
├── user/
│   ├── shell/                    # Interactive shell (no_std, raw syscalls)
│   │   ├── src/
│   │   │   ├── main.rs           # _start entry, panic handler
│   │   │   ├── shell.rs          # Shell logic, commands
│   │   │   └── syscall.rs        # Syscall wrappers (inline asm)
│   │   ├── linker.ld             # User linker script
│   │   └── build.rs              # Copies user linker script + objcopy
│   ├── hello/                    # Test program using Rust std
│   │   └── src/main.rs           # println!("Hello from std!")
│   ├── rvos-rt/                  # Runtime crate for std programs
│   │   └── src/lib.rs            # _start, lang items, syscall FFI
│   └── user.ld                   # Shared user linker script
├── lib/
│   ├── rvos-wire/                # Serialization library (no_std)
│   └── rust-std/                 # Patched Rust std library sources
├── vendor/
│   ├── rust/                     # Custom Rust compiler (rvOS target)
│   ├── qemu/                     # QEMU source (device reference)
│   └── riscv-isa-manual/         # RISC-V ISA specification
└── docs/
    ├── architecture.md           # System architecture (this area)
    ├── kernel-abi.md             # Syscall and IPC reference
    └── building.md               # Build system guide (this file)
```

---

## 5. Adding a New User Program

### Option A: No-std (raw syscalls, like the shell)

1. Create `user/myapp/` with a `Cargo.toml` targeting `riscv64gc-unknown-none-elf`
2. Implement `_start` as `#[no_mangle] pub extern "C" fn`
3. Use syscall wrappers (copy from `user/shell/src/syscall.rs`)
4. Add a linker script (copy `user/shell/linker.ld`)
5. Add a `build-myapp` target to the Makefile
6. Add `.incbin` directive in `kernel/src/arch/user_programs.S`
7. Add `user_myapp_code()` accessor in `kernel/src/main.rs`
8. Spawn with `task::spawn_user_elf_with_boot_channel()`

### Option B: With std (like hello-std)

1. Create `user/myapp/` with a `Cargo.toml`
2. Set `[build] target = "riscv64gc-unknown-rvos"` or use the target JSON
3. Add `rvos-rt` as a dependency (provides `_start` and runtime)
4. Use standard Rust: `println!()`, `Vec`, `String`, etc.
5. Build with `cargo +rvos build --release`
6. Embed and spawn as above

### Embedding User Binaries

In `kernel/src/arch/user_programs.S`:

```asm
.section .rodata
.global _user_myapp_start
.global _user_myapp_end
.balign 8
_user_myapp_start:
    .incbin "user/myapp/target/riscv64gc-unknown-none-elf/release/myapp"
_user_myapp_end:
```

---

## 6. Debugging

### GDB

```bash
make debug
```

This starts QEMU with `-s -S` (GDB stub on port 1234, paused at entry) and
launches `gdb-multiarch` connected to it. Useful commands:

```gdb
break kmain
continue
info registers
x/10i $pc
```

### Serial Output

All `println!()` output goes to the UART, which is connected to stdio in
`make run`. Kernel panics print a register dump including `sepc`, `scause`,
`stval`, and `sstatus`.

### Common Issues

- **"Unknown syscall: N"** — the user program is calling a syscall number
  the kernel doesn't handle. Check syscall numbers match between
  `kernel/src/arch/trap.rs` and the user-side syscall wrappers.
- **Page fault in U-mode** — the user program accessed an unmapped address.
  Check that ELF segments were loaded correctly and the stack is mapped.
- **Hang after boot** — likely a blocking receive with no sender. Check that
  all service channels are wired up correctly in `kmain`.
