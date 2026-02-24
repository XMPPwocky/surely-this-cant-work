# 0012: ktest channel exhaustion hangs test suite

**Reported:** 2026-02-20
**Status:** Closed
**Severity:** MEDIUM (test-only, does not affect production)
**Subsystem:** ipc, ktest

## Symptoms

`make test` hangs after the "Regression -- Cap Ref Counting" section completes
its first two tests. The `cap_delivery_via_spawn` test never completes. The
kernel console shows repeated `[ipc] channel_create_pair: all 64 slots exhausted`
messages. Spawned hello-std child processes from earlier tests continue printing
output (they are still running), but ktest is stuck and never reaches the
"Block Device" section or prints final results.

The hang occurs specifically after the `two_children_shared_override` test
prints its LEAK message and before `cap_delivery_via_spawn` can complete.

## Reproduction Steps

1. Run `make test`.
2. Observe the test output. The "Regression -- Cap Ref Counting" section begins
   with `ns_override_cap_delivery` and `two_children_shared_override`.
3. After `two_children_shared_override` completes (possibly with a LEAK
   message), `cap_delivery_via_spawn` starts but never finishes.
4. The console shows `[ipc] channel_create_pair: all 64 slots exhausted`.
5. The test suite hangs indefinitely. It never reaches the "Block Device"
   section or prints final pass/fail results.

## Investigation

The bug was discovered incidentally during a session adding block device support
and block device ktests. After adding the new test section, `make test` was run
to verify the changes. The test suite hung and never produced final pass/fail
results.

**Initial observation:** The console showed a stream of output from hello-std
child processes (printing "done"), but ktest itself was stuck. This was
initially confusing because the output looked like activity, but none of it
was ktest progress messages.

**Identifying where the hang was:** The test output showed the "Cap Ref
Counting" section had started (`ns_override_cap_delivery` and
`two_children_shared_override` completed or partially completed) with a LEAK
message, but `cap_delivery_via_spawn` never printed its result. The block
device section was never reached.

**Reading the kernel log:** The console showed repeated
`[ipc] channel_create_pair: all 64 slots exhausted` messages. This identified
the proximate cause: the IPC channel pool (`MAX_CHANNELS = 64`) was full.

**Tracing why channels were exhausted:** The Cap Ref Counting tests spawn
hello-std child processes. The test framework's `run_test()` helper runs each
test twice (warmup pass + measured pass), doubling the number of spawned
processes. Each spawned process consumes multiple channel slots (boot channel,
stdio channels, etc.). Processes from earlier tests had not fully exited and
released their channels by the time the next test started. With 64 total
slots, the cumulative allocation from successive spawn-heavy tests caused
exhaustion.

**Tracing why the hang was permanent:** `sys_chan_create()` returns
`(usize::MAX, usize::MAX)` when the pool is exhausted. The `cap_delivery_via_spawn`
test did not check this return value. It proceeded to call
`sys_chan_recv_blocking(usize::MAX, ...)` on the invalid handle, which blocked
forever because `usize::MAX` is not a valid channel handle.

**Confirming the root cause was pre-existing:** The issue was confirmed to be
unrelated to the new block device code; the block device section appears later
in the test order and was simply never reached. The fix for the main session's
goal (verifying block device tests) was temporarily to reorder the block device
section earlier in ktest, before the spawn-heavy Cap Ref Counting section.

**Determining the fix:** Two approaches were considered: (1) increase
`MAX_CHANNELS` to give enough headroom, and (2) add explicit yield loops
between spawn-heavy sections so child processes can exit and release slots
before the next test runs. Both were applied. The increase to `MAX_CHANNELS`
(64 → 1024) also addressed Bug 0013 (per-process channel limit) which was
filed at the same time. The `yield_drain()` helper (50 yields) was added
before and after the Cap Ref Counting section as a belt-and-suspenders
safeguard.

## Root Cause

**Channel slot exhaustion from spawn-heavy tests without draining.**

The system had a hard limit of 64 IPC channel slots (`MAX_CHANNELS = 64`).
The Cap Ref Counting test section spawns multiple hello-std child processes,
each consuming multiple channel slots. With each test run twice by `run_test()`
(warmup + real), child processes from earlier tests hadn't fully exited and
released their channels before the next test ran. By the time
`cap_delivery_via_spawn` ran, all 64 slots were consumed.

**Bug class:** Resource exhaustion + silent failure propagation.

## Fix

Three changes, addressing both the immediate symptom and underlying cause:

1. **Increased `MAX_CHANNELS` from 64 to 1024** (`kernel/src/ipc/mod.rs`).
   Covers the theoretical maximum (MAX_PROCS=64 * MAX_HANDLES=32) with
   headroom. Memory cost ~128 KB.

2. **Added per-process channel limit** (Bug 0013 fix). Prevents any single
   process from exhausting the global pool.

3. **Added `yield_drain()` helper to ktest** (`user/ktest/src/main.rs`).
   Yields 50 times before and after spawn-heavy test sections to let child
   processes finish exiting and release their channel slots.

## Verification

1. `make clippy` — no new warnings.
2. `make build` — builds successfully.
3. `make test` — ktest suite completes without hanging, all tests pass.

## Lessons Learned

- Fixed-size global resource pools need headroom for concurrent usage patterns,
  especially in test suites that rapidly spawn and exit processes.
- Tests that spawn child processes should include explicit drain points to
  allow asynchronous cleanup to complete.
