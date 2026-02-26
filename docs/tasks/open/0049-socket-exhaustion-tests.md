# 0049: Add socket exhaustion tests

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/net-stack, user/ktest
**Source:** Arch review 6, carried through reviews 7-8

## Description

There are no tests for what happens when the socket table fills up. The
net-stack has a fixed-size connection/socket table. Test that: (1) opening
sockets up to the limit works, (2) opening one more returns an error,
(3) closing a socket frees the slot for reuse.
