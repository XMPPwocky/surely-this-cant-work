# 0033: Unify error types across lib/rvos

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26) — won't fix
**Severity:** LOW
**Subsystem:** lib/rvos

## Description

SysError, RecvError, and RpcError are separate types with no From impls.
Proposed adding From impls or a unified AppError.

## Resolution

Won't fix. Audit of all user-space code shows this is a theoretical issue:

- Zero user-space callsites need to convert between SysError/RecvError/RpcError
- 77 .map_err() calls in user/ code, but none convert between these types
- Each service defines its own error enum (SocketError, DnsError, etc.)
  that wraps both SysError and RecvError as needed
- The architecture naturally avoids mixing these types in the same Result
  context

Adding From impls would be dead code. The current error type separation
correctly reflects the different abstraction levels (syscall, channel recv,
RPC transport).
