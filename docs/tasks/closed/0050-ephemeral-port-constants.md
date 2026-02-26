# 0050: Define EPHEMERAL_PORT_MIN/MAX constants in net-stack

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/net-stack
**Source:** Arch review 6, carried through reviews 7-8

## Description

Ephemeral port range boundaries are magic numbers in the net-stack code.
Define named constants `EPHEMERAL_PORT_MIN` and `EPHEMERAL_PORT_MAX` for
clarity and to make the range easy to find and change.
