# 0035: Deduplicate nc TCP/UDP relay loops

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/nc
**Source:** Arch review 8, item 7

## Description

`relay_tcp` and `relay_udp` in `user/nc/src/main.rs` are ~80% identical
(both use Reactor to multiplex stdin/socket, copy data bidirectionally).
Factor into a generic relay function parameterized by socket type or a
trait that abstracts send/recv.
