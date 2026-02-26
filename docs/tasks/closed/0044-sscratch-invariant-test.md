# 0044: Add sscratch invariant verification test

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** kernel/arch

## Description

The sscratch register must always point to the current task's TrapContext.
This invariant is maintained by schedule(), preempt(), trampolines, and
init(). A violation causes the wrong task's registers to be saved/restored,
corrupting state silently.

## Resolution

Added `debug_assert_eq!` checks at two key points:

1. **scheduler init**: After writing sscratch for the idle task, verify
   read-back matches the expected TrapContext pointer.
2. **schedule() resume**: After switch_context returns and sscratch is
   restored for the old task, verify it matches the expected pointer.

Also added `read_sscratch()` to `kernel/src/arch/csr.rs` (previously only
`write_sscratch` existed).

These assertions fire in debug builds and catch any sscratch corruption
during context switching. The preempt() path does not need a separate
assertion because sscratch is restored by the trap.S epilogue (csrw
sscratch, t0) before sret, and the trap entry path implicitly verifies
correctness by saving to whatever sscratch points to.

Verified: 69/69 tests pass with assertions enabled.
