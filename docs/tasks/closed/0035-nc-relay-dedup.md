# 0035: Deduplicate nc TCP/UDP relay loops

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26) — won't fix
**Severity:** LOW
**Subsystem:** user/nc

## Description

`relay_tcp` and `relay_udp` share the reactor loop structure but differ
in the core data path. Proposed extracting a generic relay function.

## Resolution

Won't fix. The two functions share structure but differ in substantive ways:
- TCP uses Recv/Send; UDP uses RecvFrom/SendTo
- TCP has half-close (Shutdown) on stdin EOF; UDP doesn't
- TCP parses SocketData::Data; UDP parses SocketData::Datagram
- TCP uses wire tag dispatch (0=data, 1=error, 4=sent); UDP has
  different tag semantics (1 with len>2 = datagram)

At ~180 total lines (97 TCP + 83 UDP), extracting a common function
with callbacks or a trait would add complexity without meaningful
benefit. The current code is clear and easy to modify independently.
