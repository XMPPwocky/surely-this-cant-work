# 0040: Add socket port access control

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26) — deferred
**Severity:** LOW
**Subsystem:** user/net-stack
**Source:** Arch review 5, carried through reviews 6-8

## Description

Any user process can bind to any port (including well-known ports < 1024).
There's no access control or policy enforcement.

## Resolution

Deferred. This requires design decisions about the capability model:

- What mechanism authorizes privileged port access? (init-granted
  capability, per-process flag, process group, etc.)
- How does the net-stack verify authorization? (The net-stack is a
  user-space service with no kernel privilege — it would need the
  kernel to provide per-process capability info.)
- Is this a real security concern? In rvOS's current model, all user
  processes are started by init and effectively trusted. Port access
  control is relevant for multi-tenant scenarios which rvOS doesn't
  currently support.

Not blocking any other work.
