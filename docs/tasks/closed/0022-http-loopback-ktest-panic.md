# 0022: Kernel panic in channel_inc_ref during HTTP loopback ktest

**Reported:** 2026-02-24
**Status:** Closed
**Severity:** HIGH
**Subsystem:** ipc, init, net-stack

## Symptoms

Running `make test` (full test suite) with the `test_http_loopback` ktest
causes a kernel panic:

```
--- HTTP Loopback ---
[init] Loaded http-server from fs (356376 bytes)
  Spawned user ELF [15] "http-server" (PID 15, boot_ep=72)

!!! KERNEL PANIC !!!
panicked at kernel/src/ipc/mod.rs:596:5:
channel_inc_ref: channel 40 is inactive
```

## Root Cause

The init server's `handle_service_request` function creates a fresh channel
pair `(client_ep, server_ep)` to broker a connection between a user process
and a named service. It sends `server_ep` (via clone/inc_ref) to the
service's control channel, then sends `client_ep` (via clone_from_raw) back
to the requesting process.

When the service process has exited (e.g. net-stack exits because there is
no VirtIO net device), the control channel is inactive. The sequence:

1. `server_ep.clone()` into message cap (ref_b: 1 -> 2)
2. `send_and_wake(ctl_ep, msg)` fails (ChannelClosed) -- message dropped,
   cap closed (ref_b: 2 -> 1)
3. `drop(server_ep)` closes original (ref_b: 1 -> 0) -- **channel deactivated**
4. `send_ok_with_cap(boot_ep_b, client_ep.raw(), ...)` calls
   `clone_from_raw(client_ep)` which calls `channel_inc_ref` on the A side
   of the now-inactive channel -- **PANIC**

The same pattern exists in `handle_stdio_request` (console server control
channels), though console servers are kernel tasks that never exit so it
was not triggered in practice.

## Fix

Added `ipc::channel_is_active(ctl_ep)` check in `handle_service_request`
before attempting to send to the control channel. If the control channel is
inactive (service process has exited), both endpoints are dropped and an
error response ("service not ready") is sent to the requesting process.

Applied the same defensive check to `handle_stdio_request`.

File: `kernel/src/services/init.rs`

## Verification

- `make test-quick` passes (69/69, 0 failures)
- Manually spawning http-server on a system with no net device gracefully
  reports "failed to connect to net service" instead of panicking
- `make clippy` clean

## Lessons Learned

When a kernel service function creates a channel pair for brokering a
connection, it must verify the target control channel is active before
attempting the send. A failed send on an inactive channel causes the
message's RAII caps to be cleaned up, which can cascade into deactivating
the freshly-created channel pair. Subsequent operations on the pair's other
endpoint then panic on the inc_ref assertion.
