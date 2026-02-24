# 0013: No per-process channel limit allows global IPC slot exhaustion

**Reported:** 2026-02-20
**Status:** Closed
**Severity:** HIGH (affects system availability, not just the offending process)
**Subsystem:** ipc

## Symptoms

A user-space process that creates many channels (e.g., spawning many child
processes, or directly calling `sys_chan_create` in a loop) can consume all
channel slots in the global IPC channel table. Once exhausted, NO process in the
system can create new channels -- including kernel services, the init server, and
the fs server. This is a system-wide denial of service.

## Reproduction Steps

1. Write a user-space program that calls `sys_chan_create` in a tight loop
   without closing the returned handles.
2. After exhausting the per-process limit (32 handles) or the global pool,
   `sys_chan_create` returns `(usize::MAX, usize::MAX)`.

## Investigation

The bug surfaced during development of the persistent ext2 filesystem feature.
After adding VirtIO block device support, `make test` was run to verify the new
block device tests. The test suite printed multiple "done" lines from hello-std
child processes but never exited. The user killed the hung process and asked why
it had not terminated.

Examining the serial console output revealed `[ipc] channel_create_pair: all 64
slots exhausted` messages appearing repeatedly during the "Regression -- Cap Ref
Counting" section. Tracing the test execution showed:

1. The `run_test()` framework runs each test twice (warmup + real run).
2. `ns_override_cap_delivery` and `two_children_shared_override` each spawn 2+
   hello-std child processes per run, totalling 8+ spawned processes across the
   two tests.
3. Those processes exit asynchronously and had not yet released their channel
   endpoints by the time `cap_delivery_via_spawn` ran.
4. With all 64 slots consumed, `sys_chan_create()` returned
   `(usize::MAX, usize::MAX)`. The test then called
   `sys_chan_recv_blocking(usize::MAX, ...)` on the invalid handle, which blocked
   forever.

Code inspection confirmed the root cause immediately: `MAX_CHANNELS = 64` in
`kernel/src/ipc/mod.rs:12`, and `channel_create_pair()` (lines 316-333) scans
for a free slot with no per-process accounting whatsoever. The `sys_chan_create`
syscall in `kernel/src/arch/syscall/chan.rs:8-31` likewise has no quota check.

This was filed as Bug 0012 (the ktest-specific hang symptom). The user then
noted that the ability for any single process to exhaust all 64 global slots
was itself a deeper design bug, prompting Bug 0013 to be filed immediately as
the underlying resource-exhaustion issue.

## Root Cause

The IPC channel table was a fixed-size global array of 64 slots (`MAX_CHANNELS`)
with no per-process limit on channel creation. Any single process could allocate
channels until the global pool was exhausted.

**Bug class:** Resource exhaustion (no per-process resource limits).

## Fix

Two changes:

1. **Increased `MAX_CHANNELS` from 64 to 1024** (`kernel/src/ipc/mod.rs`).
   The previous limit of 64 was too low for a system that uses channels
   extensively. The new limit of 1024 covers the theoretical maximum
   (MAX_PROCS=64 * MAX_HANDLES=32) with headroom. Memory cost ~128 KB.

2. **Added per-process channel limit of 32** (`MAX_CHANNELS_PER_PROCESS`).
   - Added `channel_handle_count: u16` field to `Process` struct
     (`kernel/src/task/process.rs`).
   - Incremented in `alloc_handle()` when allocating a `Channel` handle.
   - Decremented in `take_handle()` when taking a `Channel` handle.
   - Also set correctly in spawn functions that directly assign handles.
   - `sys_chan_create()` (`kernel/src/arch/syscall/chan.rs`) checks
     `current_process_channel_count() + 2 > MAX_CHANNELS_PER_PROCESS`
     before creating a pair, returning `Err(SyscallError::Error)` if exceeded.
   - The per-process limit of 32 matches the handle table size (MAX_HANDLES=32).

## Related

- Bug 0012 (`ktest-channel-exhaustion`) was a direct symptom of this
  underlying design issue.

## Verification

1. `make clippy` — no new warnings.
2. `make build` — builds successfully.
3. `make test` — ktest suite completes, all tests pass.

## Lessons Learned

- Shared global resource pools need per-consumer quotas to prevent any single
  process from starving the entire system. Analogous to Unix `RLIMIT_NOFILE`.
