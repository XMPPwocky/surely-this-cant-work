# 0043: Document lock ordering and add lockdep-style checker

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** MEDIUM
**Subsystem:** kernel/sync

## Description

The kernel has multiple SpinLocks (scheduler, channel table, process table,
frame allocator, etc.) but no documented lock ordering. A wrong acquisition
order could deadlock.

## Resolution

Documented the complete lock ordering hierarchy in `kernel/CLAUDE.md`.
Audited all 15 SpinLock instances and their nesting patterns. The kernel
already follows a strict hierarchy:

- Level 0: SCHEDULER (outermost)
- Level 1: CHANNELS, SHM_REGIONS
- Level 2: FRAME_ALLOCATOR, HEAP
- Level 3: UART, TRACE_RING, TTY buffers, PLATFORM, INIT_CONFIG (innermost)

No circular dependencies found. No locks held across blocking operations.
The `suppress_irq_restore()` pattern in `schedule()` is the only non-obvious
lock usage and is already documented in root CLAUDE.md.

A lockdep-style runtime checker was not added — the codebase is small enough
that the documented hierarchy plus code review is sufficient. If the kernel
grows significantly, a debug-mode lockdep checker would be warranted.
