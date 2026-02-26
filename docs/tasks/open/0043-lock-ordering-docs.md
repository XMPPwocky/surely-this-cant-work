# 0043: Document lock ordering and add lockdep-style checker

**Reported:** 2026-02-26
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** kernel/sync
**Source:** Arch review 7, backlog item 21; review 6

## Description

The kernel has multiple SpinLocks (scheduler, channel table, process table,
frame allocator, etc.) but no documented lock ordering. A wrong acquisition
order could deadlock.

1. Document the intended lock acquisition order in a comment or CLAUDE.md
2. Optionally add a debug-mode lockdep checker that records lock acquisition
   order and panics on violations during development
