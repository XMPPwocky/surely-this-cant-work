# 0012: ktest channel exhaustion hangs test suite

**Reported:** 2026-02-20
**Status:** Open
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

Preliminary analysis — not yet confirmed by reproduction.

**Channel slot exhaustion from spawn-heavy tests without draining.**

The system has a hard limit of 64 IPC channel slots
(`kernel/src/ipc/mod.rs:12`, `MAX_CHANNELS = 64`). The Cap Ref Counting test
section (`user/ktest/src/main.rs:2017-2021`) runs three tests, each of which
spawns hello-std child processes with namespace overrides:

- `test_ns_override_cap_delivery` (line 1304): spawns 1 hello-std process
- `test_two_children_shared_override` (line 1341): spawns 2 hello-std processes
  sequentially

Each test is run **twice** by `run_test()` (line 40-87) — once as a warmup
(line 44), once as the real run (line 50). That is 6 hello-std spawns across
the first two tests alone. Each spawn consumes multiple channel slots:

1. The ktest process creates a channel pair for the override endpoint (1 slot)
2. The `spawn_impl` RPC to the init server creates a process-watcher channel
   pair returned to ktest (1 slot)
3. The spawned child's boot channel (1 slot)
4. The child connects to namespace services (stdout, etc.) during startup
   (1+ slots each)

While the tests do call `sys_chan_close` on their handles, the spawned
hello-std processes take time to run to completion and release their own
channel endpoints. Process exit and cleanup is asynchronous — the child must
finish execution, the init server must process the exit, and channels must be
freed.

By the time `cap_delivery_via_spawn` runs (line 1377), all 64 channel slots
are consumed by still-exiting processes from earlier tests. The call to
`raw::sys_chan_create()` at line 1380 returns `(usize::MAX, usize::MAX)`
because `channel_create_pair()` returns `None`
(`kernel/src/ipc/mod.rs:331-332`).

The test does not check for `sys_chan_create` failure. It proceeds to:

1. `sys_chan_send(usize::MAX, &cmd)` — silently fails (handle lookup returns
   `None`, kernel returns `Err(SyscallError::Error)`, return value ignored)
2. `spawn_process_with_cap("/bin/ktest-helper", usize::MAX)` — sends an
   invalid cap handle to the init server via `spawn_impl`
   (`lib/rvos/src/service.rs:45-60`). The `rpc_call_with_cap` itself may block
   if the init server's internal channel creation also fails due to exhaustion.
3. If the spawn somehow succeeds, `sys_chan_recv_blocking(our_ep, &mut reply)`
   at line 1394 is called with `our_ep = usize::MAX`. The kernel's
   `sys_chan_recv_blocking` (`kernel/src/arch/syscall/chan.rs:162-164`) checks
   the handle table and returns `Err(SyscallError::Error)` for invalid handles,
   so this particular call should not block.

The most likely hang point is inside `spawn_impl` → `rpc_call_with_cap` →
`UserTransport::send` / `recv` — the init server RPC itself requires channels
for the process-watcher pair and boot channel, and if those allocations fail
internally in the init server (a kernel task), the init server may block or
fail to respond, causing the ktest process to block forever in the RPC
recv_blocking.

**Bug class:** Resource exhaustion + silent failure propagation.

The fundamental issues are:

1. **Finite channel pool with no back-pressure.** 64 slots is enough for
   normal operation but not for rapid sequential spawn-and-exit test patterns
   where cleanup is asynchronous.
2. **No error checking on `sys_chan_create` return.** The user-space raw
   wrapper returns `(usize::MAX, usize::MAX)` on failure but the test code
   does not check for this.
3. **No yield/drain between spawn-heavy tests.** The tests do not wait for
   previously-spawned processes to fully exit and release their channels before
   starting the next test.

## Fix

(To be filled in during fix phase. Preliminary ideas below.)

Possible fixes, not mutually exclusive:

1. **Increase `MAX_CHANNELS`** from 64 to 128 or 256 in
   `kernel/src/ipc/mod.rs`. This is a band-aid but would give more headroom.

2. **Add yield loops between spawn-heavy tests.** Insert calls to
   `sys_yield()` or a small busy-wait loop after tests that spawn child
   processes, giving the system time to clean up exiting processes and free
   channel slots before the next test begins.

3. **Make `sys_chan_recv_blocking` (and the init server RPC path) return an
   error immediately for invalid handles** instead of potentially blocking.
   This would turn the hang into a test failure, which is easier to diagnose.

4. **Check `sys_chan_create` return values in ktest.** The tests should detect
   `(usize::MAX, usize::MAX)` and return an error rather than proceeding with
   invalid handles.

5. **Add a `sys_yield`-based drain helper** to ktest that yields until channel
   slot pressure drops, called between sections that spawn processes.

## Verification

(To be filled in during fix phase.)

## Lessons Learned

(To be filled in during fix phase.)
