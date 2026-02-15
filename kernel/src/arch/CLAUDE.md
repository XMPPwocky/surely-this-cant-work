# Syscall Implementation

Syscall handling is split across `syscall/`:

- `syscall/mod.rs` — dispatch table (`handle_syscall`), syscall number
  constants, shared utilities (validate_user_buffer, cap translate/rollback)
- `syscall/chan.rs` — channel IPC syscalls (create, send, recv, close, poll)
- `syscall/mem.rs` — memory mapping (mmap, munmap, shm_create, shm_dup_ro, meminfo)
- `syscall/misc.rs` — process lifecycle (exit), tracing

`trap.rs` handles the trap entry point, timer ticks, external interrupts,
exception dispatch (page faults, illegal instructions), and backtrace printing.

**If you change anything user-facing about syscalls** (add a syscall, change
arguments, change semantics, rename, renumber), you **must** also update:

1. `lib/rvos/src/raw.rs` — the user-space `rvos` crate's raw syscall wrappers
   and syscall number constants (must stay in sync with the constants here)
2. `docs/kernel-abi.md` — the syscall ABI reference documentation
3. Any high-level wrappers in `lib/rvos/` that build on the changed syscall
