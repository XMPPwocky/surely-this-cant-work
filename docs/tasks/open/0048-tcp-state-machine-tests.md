# 0048: Add TCP state machine tests

**Reported:** 2026-02-26
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** user/net-stack, user/ktest
**Source:** Arch review 6, carried through reviews 7-8

## Description

TCP state machine transitions (SYN→SYN_RECEIVED→ESTABLISHED→FIN_WAIT→etc.)
have only indirect coverage via the HTTP loopback integration test. Add
targeted tests that exercise specific state transitions, especially edge
cases: simultaneous open, data during handshake, RST in various states,
half-close, and TIME_WAIT cleanup.
