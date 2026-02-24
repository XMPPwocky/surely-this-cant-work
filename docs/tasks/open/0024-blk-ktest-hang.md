# 0024: Block device ktest hangs when connecting to busy blk_server

- **Status:** open
- **Severity:** medium
- **Found:** 2026-02-24 (during Bug 0022 investigation)

## Symptoms

During `make test`, the "Block Device" ktest section hangs indefinitely. The
test suite times out (300s) before reaching later sections (Process Spawn,
HTTP Loopback, Debugger, etc.). The last visible serial output from the block
device section is `[blk2] client connected / [blk2] client disconnected` from
`blk_find_by_serial` probing, after which the system freezes with no output.

## Root Cause

`blk_server` is single-client by design (`kernel/src/services/blk_server.rs:4`).
It has an outer loop that calls `ipc::accept_client(control_ep, pid)` to wait
for a new connection from the control channel, and an inner `'client` loop that
serves that client until disconnect.

When an ext2-server is connected to a blk_server (e.g., blk0 serves the bin.img
filesystem, blk1 serves persist.img), the blk_server is stuck in the inner
client loop polling `channel_recv(client_ep)` on the ext2 client's channel. It
never reads the control channel.

The `blk_find_by_serial` function in `user/ktest/src/main.rs:1705` probes block
devices by calling `connect_to_service("blkN")` for each one. This goes through
init's `handle_service_request`, which:

1. Creates a fresh channel pair (client_ep, server_ep)
2. Sends server_ep to the blk_server's control channel as a NewConnection message
3. Returns client_ep to the ktest process

The NewConnection message sits unread in the control channel queue because the
blk_server is busy serving ext2. The ktest then sends GetDeviceInfo on the new
client channel and calls `sys_chan_recv_blocking` waiting for the response.
Nobody ever reads the GetDeviceInfo because the blk_server hasn't accepted the
connection. The ktest process blocks forever.

The comment on `blk_find_by_serial` acknowledges this:
```
/// Tries devices in reverse order (highest index first) because lower-indexed
/// devices may already have ext2-server clients connected, and connecting
/// to a busy blk_server would block until that client disconnects.
```

The mitigation (probing highest index first) works in the default QEMU test
configuration because the test drive (serial=test) gets the highest blk index.
However, this is fragile — it fails if:
- QEMU MMIO probe order changes
- A different block device layout is used
- The test drive isn't the last declared device

## Reproduction

1. `make test` — observe that the Block Device section completes normally
   (because test drive happens to be the highest index)
2. To force the hang: modify `blk_find_by_serial` to probe in forward order
   (`["blk0", "blk1", "blk2", "blk3"]`) — it will hang on blk0 or blk1.

## Possible Fixes

### Option A: Timeout on `connect_to_service` + recv (user-space)

Add a timeout or non-blocking probe to `blk_find_by_serial` so it doesn't
block forever on a busy server. This requires either:
- A `sys_chan_recv_with_timeout` syscall (doesn't exist yet)
- A non-blocking recv + yield-and-retry loop with a retry limit

### Option B: Multi-client blk_server (kernel)

Make blk_server multiplex its control channel and client channels. Accept new
connections even while serving an existing client. This is a larger change but
fixes the architectural limitation.

### Option C: Reject second connection at init level

When init's `handle_service_request` sends a NewConnection to a single-client
service's control channel, the service has no way to reject it synchronously.
A protocol addition could let the service declare max_clients=1, and init would
reject additional connections with an error.

### Option D: Non-blocking serial probe (user-space, simplest)

Use non-blocking send/recv in `blk_find_by_serial` to probe devices. If no
response arrives after a few yields, skip to the next device. This works within
the existing syscall API.

## Files

- `kernel/src/services/blk_server.rs` — single-client server loop (lines 52-183)
- `kernel/src/ipc/mod.rs:528` — `accept_client` blocks on control channel
- `user/ktest/src/main.rs:1705` — `blk_find_by_serial` probe logic
- `user/ktest/src/main.rs:1642` — `blk_connect` helper
- `kernel/src/services/init.rs:577` — `handle_service_request` creates connection
