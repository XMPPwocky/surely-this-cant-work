# rvOS — RISC-V 64-bit Microkernel

A from-scratch RISC-V 64-bit microkernel OS written in Rust, targeting qemu-system-riscv64 (virt machine).

## Build & Run
- `make build` — build kernel binary
- `make run` — boot in QEMU with serial
- `make run-gui` — boot with virtio-gpu display
- `make bench` — build and run benchmark suite (boots QEMU, runs /bin/bench, shuts down)
- `make debug` — QEMU with GDB attach

## Linting
- `make clippy` — run clippy on all crates (kernel + user)
- `make clippy-kernel` — run clippy on the kernel only
- `make clippy-user` — run clippy on all user-space crates

Run `make clippy` after any code changes. Clippy uses `-W clippy::all` so all
default lints are warnings. Fix warnings rather than suppressing them unless
there is a good reason (document why with `#[allow(clippy::lint_name)]`).

## Conventions
- No external crates — only `core` and `alloc`
- All hardware access through typed wrappers (not raw pointer math)
- Address types are newtypes (PhysAddr/VirtAddr)
- Interrupt disable/restore via RAII guard
- Assembly limited to boot.S, trap.S, switch.S

## QEMU Source Reference
QEMU source is available as a shallow git submodule at `vendor/qemu/`. This is useful
for understanding how QEMU implements virtual devices, especially when debugging drivers.

Key reference paths:
- `vendor/qemu/hw/virtio/` — VirtIO core (virtqueue, MMIO transport)
- `vendor/qemu/hw/display/virtio-gpu*.c` — VirtIO GPU device implementation
- `vendor/qemu/hw/char/serial.c` — UART 16550A implementation
- `vendor/qemu/hw/intc/sifive_plic.c` — PLIC implementation
- `vendor/qemu/hw/riscv/virt.c` — QEMU "virt" machine definition (memory map, device tree)
- `vendor/qemu/include/hw/virtio/` — VirtIO headers and struct definitions

When debugging virtio or device driver issues, spawn a subagent (Explore type) to read
the relevant QEMU source and understand expected device behavior, register layouts, or
command formats.

## RISC-V ISA Manual Reference
The official RISC-V ISA specification is available at `vendor/riscv-isa-manual/`. This is
the authoritative source for instruction encodings, CSR definitions, privilege levels,
virtual memory, and trap behavior.

Key reference files (AsciiDoc sources):
- `vendor/riscv-isa-manual/src/supervisor.adoc` — Supervisor mode: CSRs (sstatus, scause, stvec, satp, etc.), trap handling, Sv39/Sv48 virtual memory, page table entry format
- `vendor/riscv-isa-manual/src/priv-csrs.adoc` — All privileged CSR definitions and bit fields
- `vendor/riscv-isa-manual/src/priv-insns.adoc` — Privileged instructions (sret, wfi, sfence.vma, etc.)
- `vendor/riscv-isa-manual/src/riscv-privileged.adoc` — Top-level privileged spec (includes all chapters)
- `vendor/riscv-isa-manual/src/riscv-unprivileged.adoc` — Unprivileged spec (base ISA, extensions)

Useful when:
- Debugging trap/interrupt issues (scause values, delegation, sstatus fields)
- Implementing or debugging Sv39 page table walks (PTE format, permission bits, A/D bits)
- Understanding CSR bit layouts (sstatus.SIE, sstatus.SPP, satp mode field)
- Verifying correct use of privileged instructions (sret, sfence.vma semantics)
- Checking ecall/exception cause codes

Spawn a subagent (Explore type) to grep or read these files when you need to verify
architectural behavior — the spec is the ground truth.

## Testing Serial Console
For interactive testing (sending commands to the shell and checking output),
use `expect` scripts — **never pipe stdin** to `make run` (the shell won't be
ready). See `docs/testing-serial.md` for patterns and examples.

## Key Addresses (QEMU virt)
- RAM_BASE: 0x80000000
- KERNEL_BASE: 0x80200000
- UART: 0x10000000
- PLIC: 0x0C000000
- VIRTIO: 0x10001000
- CLINT: 0x02000000
