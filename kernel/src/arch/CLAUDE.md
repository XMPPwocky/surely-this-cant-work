# Syscall Implementation

Syscall handling is split across `syscall/`:

- `syscall/mod.rs` — dispatch table (`handle_syscall`), syscall number
  constants, `SyscallError` enum, `SyscallResult` type, shared utilities
  (validate_user_buffer, cap translate/rollback)
- `syscall/chan.rs` — channel IPC syscalls (create, send, recv, close, poll)
- `syscall/mem.rs` — memory mapping (mmap, munmap, shm_create, shm_dup_ro, meminfo)
- `syscall/misc.rs` — process lifecycle (exit), tracing

`trap.rs` handles the trap entry point, timer ticks, external interrupts,
exception dispatch (page faults, illegal instructions), and backtrace printing.

## Syscall Error Handling

All syscall handlers return `SyscallResult` (= `Result<usize, SyscallError>`).
The dispatch table in `handle_syscall` converts these to raw `usize` values
via `result_to_a0()` at the ABI boundary. **Never return raw sentinel values**
(like `usize::MAX` or bare integer codes) from a handler — always use
`Err(SyscallError::Error)`, `Err(SyscallError::QueueFull)`, etc.

`result_to_a0()` includes a debug assert that `Ok(v)` values don't collide
with any error code. If a syscall's success value could theoretically overlap,
that's a bug in the ABI design.

The `SyscallError` variants and their ABI encodings:
- `Error` → `usize::MAX` (generic: invalid handle, bad address, OOM)
- `Empty` → `1` (non-blocking recv found nothing)
- `ChannelClosed` → `2` (channel deactivated)
- `QueueFull` → `5` (non-blocking send: queue full)

## Updating Syscalls

**If you change anything user-facing about syscalls** (add a syscall, change
arguments, change semantics, rename, renumber), you **must** also update:

1. `lib/rvos/src/raw.rs` — the user-space `rvos` crate's raw syscall wrappers
   and syscall number constants (must stay in sync with the constants here)
2. `docs/kernel-abi.md` — the syscall ABI reference documentation
3. Any high-level wrappers in `lib/rvos/` that build on the changed syscall
