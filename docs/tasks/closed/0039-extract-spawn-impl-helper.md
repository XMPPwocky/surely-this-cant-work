# 0039: Extract spawn_impl() helper in init server

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26) — won't fix
**Severity:** LOW
**Subsystem:** kernel/services/init

## Description

Extract a shared spawn_impl() helper to reduce duplication between
boot-time and dynamic spawn paths.

## Resolution

Won't fix. Code audit shows the spawning logic already converges into
shared functions:

- `poll_fs_launch()` (157 lines) — FS load state machine, shared by both paths
- `finish_fs_launch()` (167 lines) — process creation and finalization, shared

The only real duplication is ~30 lines of FS connection + Stat request
code between `init_fs_launches()` and `handle_spawn_request()`. Extracting
a helper would save ~18 lines net (30 → 12-line helper + 2 call sites)
while adding indirection to a sensitive initialization code path. Not
worth the risk-to-benefit ratio.
