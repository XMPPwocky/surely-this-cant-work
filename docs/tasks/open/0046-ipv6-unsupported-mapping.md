# 0046: Map IPv6 to Unsupported in std::net backend

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** vendor/rust/library/std
**Source:** Arch review 6, carried through reviews 7-8

## Description

The std::net PAL backend doesn't handle IPv6 addresses. If user code attempts
to use IPv6 (e.g., `SocketAddrV6`), the behavior is undefined or panics.
Map IPv6 operations to return `ErrorKind::Unsupported` with a clear message.
