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
- **RAII for ref-counted resources:** Channel endpoints, shared memory, etc.
  must use RAII wrappers (inc_ref on clone, close on drop). Manual ref counting
  only when RAII is impossible — flag it, explain why, and ask for confirmation.
  (Bugs 0002, 0007, 0008 were all manual ref counting mistakes.)

## Vendor References
Use an Explore subagent to search these when debugging device or architectural issues.

**QEMU source** (`vendor/qemu/`): device implementation reference.
- `hw/virtio/` — VirtIO core; `hw/display/virtio-gpu*.c` — GPU
- `hw/char/serial.c` — UART; `hw/intc/sifive_plic.c` — PLIC
- `hw/riscv/virt.c` — machine definition (memory map, device tree)

**RISC-V ISA manual** (`vendor/riscv-isa-manual/src/`): ground truth for ISA behavior.
- `supervisor.adoc` — S-mode CSRs, traps, Sv39 page tables
- `priv-csrs.adoc` — all privileged CSR definitions
- `priv-insns.adoc` — sret, wfi, sfence.vma, etc.

## Testing Serial Console
Use `expect` scripts for interactive testing — **never pipe stdin** to `make run`.
See `docs/testing-serial.md`.

## Key Addresses (QEMU virt)
RAM_BASE: 0x80000000, KERNEL_BASE: 0x80200000, UART: 0x10000000,
PLIC: 0x0C000000, VIRTIO: 0x10001000, CLINT: 0x02000000
