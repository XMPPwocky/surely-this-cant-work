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

User programs that use Rust `std` require a custom Rust compiler with the
`riscv64gc-unknown-rvos` target. This compiler lives at `vendor/rust/` and
must be built once:

```bash
make build-std-lib                              # builds std + clippy via x.py
rustup toolchain link rvos vendor/rust/build/host/stage1
```

After this, `cargo +rvos` will use the custom toolchain. Re-run
`make build-std-lib` after modifying `lib/rvos-wire/`, `lib/rvos-proto/`, or
the std PAL at `vendor/rust/library/std/src/sys/pal/rvos/`.

**Dependency chain**: `lib/rvos`, `lib/rvos-wire`, `lib/rvos-proto` are
symlinked into `vendor/rust/library/`. The Rust std PAL depends on
`rvos-wire` and `rvos-proto` for IPC-based I/O. See the Makefile comment
on `build-std-lib` for the full diagram.

### QEMU

```bash
sudo apt-get install -y qemu-system-misc
```

The project vendors QEMU source at `vendor/qemu/` for driver reference, but
the system QEMU package is used for running.

### Test and Benchmark Dependencies

```bash
sudo apt-get install -y expect socat
```

- `expect` — required for `make test`, `make bench`, `make bench-check`
  (drives serial console interaction)
- `socat` — required for `make run-gpu-screenshot` (sends commands to QEMU
  monitor socket)

---

## 2. Build System

The top-level `Makefile` orchestrates building all components.

### Components

| Component | Location | Target | Toolchain |
|-----------|----------|--------|-----------|
| Kernel | `kernel/` | `riscv64gc-unknown-none-elf` | nightly (with `-Zbuild-std`) |
| User crates | `user/` (shell, bench, ktest, etc.) | `riscv64gc-unknown-rvos` | `cargo +rvos` |
| FS server | `user/fs/` | `riscv64gc-unknown-rvos` | `cargo +rvos` |
| Wire format | `lib/rvos-wire/` | (library) | Built as dependency |
| Protocol defs | `lib/rvos-proto/` | (library) | Built as dependency |
| Std support | `lib/rvos/` | (library) | Built as dependency |

### Build Order

```
build-user (all user crates except fs)
       ↓
build-fs (embeds user binaries via include_bytes!)
       ↓
build (kernel, embeds fs ELF via .incbin)  →  objcopy (ELF → raw binary)
```

The FS server embeds all other user binaries via `include_bytes!`. The kernel
embeds the FS ELF via `.incbin` in `arch/user_programs.S`. This two-stage
embedding means `make build` must build user crates first.

### Key Build Details

**User crates**: Built with `cargo +rvos --target riscv64gc-unknown-rvos`.
The custom toolchain provides a full Rust `std` with rvOS-specific PAL.

**Kernel**: Built with nightly Rust and `-Zbuild-std=core,alloc` since it
targets bare metal (`riscv64gc-unknown-none-elf`). The ELF is converted to
a raw binary via `rust-objcopy --strip-all -O binary`. QEMU's `-kernel`
flag loads this binary at `0x80200000`.

---

## 3. Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build everything (user crates, fs, kernel, objcopy) |
| `make build-user` | Build all user crates except fs |
| `make build-fs` | Build fs server (embeds user binaries) |
| `make build-std-lib` | Rebuild custom std library + clippy via x.py |
| `make run` | Build and boot in QEMU with serial on stdio |
| `make run-gui` | Build and boot with VirtIO GPU (requires X/GTK display) |
| `make run-vnc` | Build and boot with VirtIO GPU on VNC port 5900 |
| `make run-gpu-screenshot` | Headless GPU boot + PPM screenshot |
| `make debug` | Build and boot with GDB stub (`-s -S`) |
| `make test` | Run kernel tests via expect scripts |
| `make bench` | Run benchmark suite |
| `make bench-save` | Run benchmarks and save baseline |
| `make bench-check` | Run benchmarks and check for regressions |
| `make clippy` | Run clippy on kernel + user crates |
| `make clippy-kernel` | Run clippy on kernel only |
| `make clippy-user` | Run clippy on user crates only |
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
│       │   ├── heap.rs           # Buddy allocator kernel heap
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
    .incbin "user/target/riscv64gc-unknown-rvos/release/myapp"
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
