# 0031: blk_server drains new connection after previous client disconnects

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** MEDIUM
**Subsystem:** services/blk_server

## Symptoms

Full test suite (`make test`) shows 5 blk test failures:
- `blk_device_info` — "recv DeviceInfo failed"
- `blk_read_write` — "recv DeviceInfo failed"
- `blk_multi_sector` — "recv DeviceInfo failed"
- `blk_read_beyond_capacity` — "recv DeviceInfo failed"
- `blk_flush` — "recv DeviceInfo failed"

Console output shows the server accepting and immediately disconnecting:
```
[blk2] client connected
[blk2] client disconnected
[blk2] client connected
[blk2] client disconnected
  [FAIL] blk_device_info                  recv DeviceInfo failed
```

## Reproduction Steps

1. `make test` (full suite, requires test.img)
2. Observe "Block Device" test section — all 5 tests fail with "recv DeviceInfo failed"

## Investigation

The Task 0024 fix added a drain of `control_ep` in the `'client` loop to reject
new connections while the server is busy. The drain runs on every iteration of
the loop, including the iteration where the previous client has already
disconnected but the server hasn't detected it yet.

## Root Cause

Race in `blk_server.rs`'s `'client` loop. The control_ep drain (lines 170-189)
runs *before* the client disconnect check (line 192). When the sequence is:

1. `blk_find_by_serial` probes blk2: connects, sends GetDeviceInfo, receives
   response, closes handle
2. ktest immediately calls `blk_connect("blk2")` which triggers a new
   `ConnectService` → init routes → new connection message on `control_ep`
3. blk_server's `'client` loop iteration: inner recv on `client_ep` returns
   `None` (empty queue). Then drain of `control_ep` **drops the new connection**.
   Then `did_work` is false → `channel_is_active(client_ep)` returns false →
   `break 'client`. Server loops back to `accept_client`, but the new
   connection was already destroyed.

**Bug class:** Ordering error — the drain runs unconditionally before checking
whether the current client is still alive.

## Fix

Move the `channel_is_active` check to *before* the control_ep drain. Only
drain control_ep when the current client is still active. When the client
has disconnected, break immediately without draining — the queued connection
on control_ep will be picked up by `accept_client` on the next outer loop
iteration.

## Verification

- `make clippy` — clean
- `make test` — 82 passed, 0 failed (all 5 blk tests pass)
- `make test-quick` — 69 passed, 0 failed

## Lessons Learned

The control_ep drain pattern introduced in Task 0024 is correct in principle
but the ordering matters: always check whether the current client is still
alive *before* draining queued connections. If the client is gone, those
queued connections are the *next* client and must not be dropped.

This is a general pattern for single-client servers with connection draining:
the drain should be guarded by a liveness check on the current session.
