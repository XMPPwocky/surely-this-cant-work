# 0013: No per-process channel limit allows global IPC slot exhaustion

**Reported:** 2026-02-20
**Status:** Open
**Severity:** HIGH (affects system availability, not just the offending process)
**Subsystem:** ipc

## Symptoms

A user-space process that creates many channels (e.g., spawning many child
processes, or directly calling `sys_chan_create` in a loop) can consume all 64
channel slots in the global IPC channel table. Once exhausted, NO process in the
system can create new channels -- including kernel services, the init server, and
the fs server. This is a system-wide denial of service.

Specific observable effects when the channel table is full:

1. `channel_create_pair()` returns `None` for every caller in the system
   (`kernel/src/ipc/mod.rs:331`).
2. The kernel prints `[ipc] channel_create_pair: all 64 slots exhausted`.
3. Any process attempting to spawn a child hangs, because the init server
   cannot allocate the process-watcher channel pair needed for the spawn
   protocol.
4. Namespace service connections fail, because `connect_service` in the init
   server requires channel creation.
5. The system is effectively dead -- no new IPC is possible until existing
   channels are closed by process exit or explicit `sys_chan_close`.

## Reproduction Steps

1. Build the system: `. ~/.cargo/env && make build`
2. Write (or use) a user-space program that calls `sys_chan_create` in a tight
   loop without closing the returned handles.
3. After 64 iterations, `sys_chan_create` returns `(usize::MAX, usize::MAX)` --
   the global pool is exhausted.
4. Attempt any operation that requires a new channel (e.g., spawning a process,
   connecting to a namespace service). It will fail or hang.
5. Alternatively, run `make test` -- the ktest suite's spawn-heavy Cap Ref
   Counting section exhausts the pool as documented in Bug 0012.

## Root Cause

The IPC channel table is a fixed-size global array of 64 slots (`MAX_CHANNELS`
in `kernel/src/ipc/mod.rs:12`). There is no per-process limit on channel
creation. Any single process can allocate channels until the global pool is
exhausted.

The `sys_chan_create` syscall (`kernel/src/arch/syscall/chan.rs:8-31`) calls
`channel_create_pair()` (`kernel/src/ipc/mod.rs:316-333`) which performs a
linear scan for a free slot. If none is found, it returns `None` which becomes
`Err(SyscallError::Error)` at the ABI boundary. There is no quota enforcement,
no per-process accounting, and no mechanism to reclaim channels from greedy
processes.

**Code locations:**
- Global channel limit: `kernel/src/ipc/mod.rs:12` (`const MAX_CHANNELS: usize = 64`)
- Channel allocation: `kernel/src/ipc/mod.rs:316-333` (`channel_create_pair`)
- Syscall entry: `kernel/src/arch/syscall/chan.rs:8-31` (`sys_chan_create`)

**Bug class:** Resource exhaustion (no per-process resource limits).

The fundamental design issue is that a shared global resource pool (channel
slots) has no per-consumer quotas. A single misbehaving or buggy process can
starve the entire system. This is analogous to a process exhausting all file
descriptors in a Unix system that lacks `RLIMIT_NOFILE`.

## Fix

Possible fixes, not mutually exclusive:

1. **Add a per-process channel limit** (e.g., `MAX_CHANNELS_PER_PROCESS = 16`).
   Track the number of channels owned by each process in the task struct. Reject
   `sys_chan_create` with `Err(SyscallError::Error)` when the per-process limit
   is reached, even if global slots remain. This prevents any single process
   from monopolizing the pool.

2. **Increase `MAX_CHANNELS` significantly** (e.g., 256 or 512). The current
   limit of 64 is too low for a system that uses channels extensively (each
   process spawn requires multiple channels for the watcher pair, boot channel,
   and namespace connections). A larger pool provides headroom for legitimate
   use while reducing the probability of exhaustion.

3. **Both -- increase the global pool AND add per-process limits.** This is the
   most robust approach: the larger pool handles legitimate peak load, while
   per-process limits contain misbehaving processes.

## Related

- Bug 0012 (`ktest-channel-exhaustion`) is a direct symptom of this underlying
  design issue. The ktest suite's spawn-heavy tests exhaust the 64-slot pool
  because there is no per-process limit and the global pool is too small.

## Verification

(To be filled in during fix phase.)

## Lessons Learned

(To be filled in during fix phase.)
