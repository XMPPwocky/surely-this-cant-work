# 0051: Add #[must_use] to IPC functions returning Result

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** kernel/ipc, lib/rvos
**Source:** Arch review 6, carried through reviews 7-8

## Description

Several IPC functions return `Result` or error codes that callers sometimes
ignore (e.g., `channel_send_blocking`, `channel_close`). Add `#[must_use]`
annotations to these functions so the compiler warns when return values are
silently discarded. Audit both kernel-side `ipc::*` functions and user-side
`lib/rvos` wrappers.
