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
