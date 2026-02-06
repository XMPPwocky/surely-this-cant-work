# Syscall Implementation

`trap.rs` contains the syscall dispatch (the `match` on `a7`) and all syscall
number constants (`SYS_EXIT`, `SYS_CHAN_SEND`, `SYS_MMAP`, etc.).

**If you change anything user-facing about syscalls** (add a syscall, change
arguments, change semantics, rename, renumber), you **must** also update:

1. `lib/rvos/src/raw.rs` — the user-space `rvos` crate's raw syscall wrappers
   and syscall number constants (must stay in sync with the constants here)
2. `docs/kernel-abi.md` — the syscall ABI reference documentation
3. Any high-level wrappers in `lib/rvos/` that build on the changed syscall
