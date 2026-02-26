# 0052: TCP loopback self-connect hangs

**Reported:** 2026-02-26
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** user/net-stack
**Commit:** 02ff7e9

## Description

When a single-threaded process creates a TcpListener on 127.0.0.1:N and then
calls TcpStream::connect("127.0.0.1:N"), the connect hangs forever. The
expected behavior is that the net-stack completes the 3-way handshake via the
loopback interface (SYN → SYN_ACK → ACK) without requiring the listener to
call accept() first, since the SYN_RECEIVED connection should sit in the
listener's accept backlog.

## Reproduction

```rust
let _listener = std::net::TcpListener::bind("127.0.0.1:11001").unwrap();
let _stream = std::net::TcpStream::connect("127.0.0.1:11001").unwrap(); // hangs
```

## Analysis

The connect sends a Connect request on the per-socket channel. The net-stack
processes it (event loop step d), creates a SynSent connection, and sends SYN
to the loopback queue. The SYN should be drained in the next event loop
iteration (step a2), matched to the listener, and the SYN_ACK/ACK handshake
should complete within the loopback drain loop.

Possible causes:
- The net-stack's loopback drain loop doesn't re-process packets added during
  the same drain iteration (but code review shows it does loop until empty)
- The SYN_ACK or ACK doesn't match the expected connection (port/IP mismatch)
- The `handled` flag isn't set correctly, causing the net-stack to sleep
  between the Connect processing and the loopback drain

The tcp_connect_refused test (SYN → RST via loopback) works, so loopback
processing fundamentally works. The difference is that the 3-way handshake
requires multiple round-trips through the loopback queue.
