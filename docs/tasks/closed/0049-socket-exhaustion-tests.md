# 0049: Add socket exhaustion tests

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** user/net-stack, user/ktest

## Description

There were no tests for what happens when the socket table fills up.

## Resolution

Added two tests to ktest:

1. **`test_socket_exhaustion_udp`**: Creates UDP sockets (bind 0.0.0.0:0) in
   a loop until the net-stack returns an error. Verifies at least 8 sockets
   were created, then drops one, yields to let the net-stack process the
   close, and verifies a new socket can be created (slot reuse).

2. **`test_socket_exhaustion_tcp`**: Same pattern with TCP listeners bound
   to ports 10000+. Tests that stream socket slots exhaust and recover.

Also added `QEMU_NET_USER` to the Makefile (`-netdev user`) so the test
environment has a virtio-net device (required for net-stack to start)
without needing TAP/root setup.
