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

Deferred — no current motivation.

All rvOS processes are spawned by init and effectively trusted. There is
no untrusted code execution (no downloaded binaries, sandboxed plugins,
or multi-tenant scenarios). A rogue process binding port 53 before the
DNS server is a startup ordering bug, not a security issue — and
accidental port collisions are already caught by `AddrInUse` errors.

The implementation would also be non-trivial. The net-stack is a
user-space service with no kernel privilege. It receives `client_pid` in
the `NewConnection` message (and could read `msg.sender_pid` on socket
requests), but there's no per-process privilege level, UID, or group
membership in the kernel's `Process` struct to check against. The only
existing access control mechanism is binary namespace restriction
(init can block a process from reaching the net-stack entirely via
`NsOverride::Remove("net")`), which is too coarse for per-port policy.

Designing this properly requires:

1. A privilege/group model in the kernel (`Process` struct changes)
2. A policy format (which ports map to which privilege levels)
3. An enforcement point in the net-stack's Bind handler
4. A way for init to assign privilege levels at spawn time

All of this is worth doing if/when rvOS adds untrusted process execution.
Until then, it's solving a problem that doesn't exist.

Not blocking any other work.
