# 0044: Add sscratch invariant verification test

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** kernel/arch
**Source:** Arch review 7, backlog item 22

## Description

The sscratch register must always point to the current task's TrapContext.
This invariant is maintained by schedule(), preempt(), trampolines, and
init(). A violation causes the wrong task's registers to be saved/restored,
corrupting state silently.

Add a debug assertion or ktest that verifies sscratch points to the expected
TrapContext after key operations (context switch, trap return, first-run
trampoline).
