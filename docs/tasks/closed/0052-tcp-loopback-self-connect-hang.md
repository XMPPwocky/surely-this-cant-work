# 0052: TCP loopback self-connect hangs

**Reported:** 2026-02-26
**Closed:** 2026-02-26
**Severity:** MEDIUM
**Subsystem:** user/net-stack

## Description

When a single-threaded process creates a TcpListener on 127.0.0.1:N and then
calls TcpStream::connect("127.0.0.1:N"), accept() hangs forever after
connect() returns. The 3-way handshake completes successfully, but the
subsequent accept() call never receives a response.

## Root Cause

In `tcp.rs`, the `SocketRequest::Accept` handler has two branches:

1. `accept_count > 0`: A connection is already in the accept queue — deliver
   immediately by calling `tcp_deliver_accept()`.
2. `accept_count == 0`: No connection yet — set `accept_pending = true` and
   wait for SynReceived → Established to trigger delivery.

The bug is in branch 1: `tcp_deliver_accept()` checks
`!sock.accept_pending || sock.accept_count == 0` as a guard and returns early
if `accept_pending` is false. But branch 1 never sets `accept_pending = true`
before calling `tcp_deliver_accept()`, so the function always returns
immediately without delivering anything.

In the normal server flow (accept called before any client connects), branch 2
runs first, setting `accept_pending = true`. When the handshake completes,
`tcp_deliver_accept()` is called from the SynReceived → Established handler
where `accept_pending` is already true — so it works. But in any scenario
where the handshake completes before accept() is called (self-connect, fast
connect, slow server), branch 1 hits the bug.

## Fix

Set `accept_pending = true` before calling `tcp_deliver_accept()` in the
`accept_count > 0` branch of the Accept handler. The function clears the flag
after delivering, so this is safe and idempotent.

## Verification

- ktest `tcp_loopback_self_connect` passes (bind, connect, accept on same port)
- `make test-quick` passes (68/68, 0 failures)
- All existing TCP tests still pass
