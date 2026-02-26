# 0048: Add TCP state machine tests

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** MEDIUM
**Subsystem:** user/net-stack, user/ktest

## Description

TCP state machine transitions had only indirect coverage via the HTTP loopback
integration test.

## Resolution

Added two targeted TCP tests to ktest:

1. **`test_tcp_connect_refused`**: Connects to a port with no listener on
   the loopback interface (127.0.0.1:9999). Verifies the net-stack sends
   RST in response to the SYN and the connect fails with ConnectionReset
   or ConnectionRefused (not a hang).

2. **`test_tcp_listener_reuse`**: Creates and drops a TcpListener, then
   rebinds to the same port. Verifies port reuse after listener close.

The more advanced tests (simultaneous open, half-close, TIME_WAIT cleanup,
data during handshake) require either multi-process coordination or packet-
level control, which is beyond the current ktest single-threaded model.

A TCP loopback self-connect test was attempted (listener + connect in the
same process) but hangs — filed as a separate issue.
