# rvOS — RISC-V 64-bit Microkernel

A from-scratch RISC-V 64-bit microkernel OS written in Rust, targeting qemu-system-riscv64 (virt machine).

## Build & Run
- `make build` — build kernel binary
- `make run` — boot in QEMU with serial
- `make run-gui` — boot with virtio-gpu display
- `make bench` — build and run benchmark suite (boots QEMU, runs /bin/bench, shuts down)
- `make test-quick` — fast smoke test (~15s): core kernel tests, no child spawning or test.img. **Use this after code changes to confirm the system boots and core functionality works.**
- `make test` — full test suite (~80 tests, 300s timeout), includes spawn/block device tests
- `make debug` — QEMU with GDB attach
- `make mcp-setup` — create Python venv for the QEMU MCP server
- `make mcp-server` — start the QEMU MCP server (for agent interaction)

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

## Debugging & Observability
See `docs/debugging-and-observability.md` for the full reference. Key tools:
- `ps` — process list with blocked-on reason
- `mem` — kernel heap + per-process memory
- `kstat` — global atomic counters (scheduler, IPC, IRQs, pages)
- `chstat` — per-channel message/byte statistics
- `schedlat` — scheduler runqueue latency histogram
- `ipclat` — IPC delivery latency histogram
- `trace` / `trace-clear` — kernel trace ring buffer
- `dbg <pid>` — interactive user-process debugger

## Bug Tracking
When you find a bug incidentally while testing, or when the user reports a bug
(even without explicitly using `/bug`), **use the `/bug` skill** to report and
track it. If the bug isn't the main task you're working on, use a subagent to
file it so the main context stays clean.

If you encounter a pre-existing issue, check `docs/bugs/open/` for an existing
bug report first. If you can't find one, use the `/bug` skill to report it (in
a subagent to keep context clean).

## Interactive QEMU (MCP Server)
For interactive debugging and exploratory testing, use the QEMU MCP server.
It provides structured tools for booting QEMU, sending serial commands,
taking screenshots, injecting input, and capturing network traffic.

**When to use the MCP server** vs. other testing methods:
- **`make test` / `make test-quick`**: Use for automated regression testing
  ("does my change break anything?"). Prefer writing ktests for new features.
- **MCP server**: Use for interactive debugging, exploratory testing, or
  scenarios that need dynamic decision-making (e.g., "boot, check ps output,
  then decide what to investigate based on what you see"). Also useful for
  GUI testing (screenshots + input events) and network debugging (PCAP).
- **Writing a ktest**: Prefer this over MCP interaction for "verify this new
  feature works" — ktests are permanent, reproducible, and run in CI.

**Important:** Even if you reproduce a bug using the MCP server, strongly
consider writing a ktest afterwards once you understand how to reproduce it.
Regression tests are critical — an MCP session is ephemeral but a ktest
catches the bug forever.

## Testing Serial Console
Use `expect` scripts for interactive testing — **never pipe stdin** to `make run`.
See `docs/testing-serial.md`.

## Key Addresses (QEMU virt)
RAM_BASE: 0x80000000, KERNEL_BASE: 0x80200000, UART: 0x10000000,
PLIC: 0x0C000000, VIRTIO: 0x10001000, CLINT: 0x02000000
