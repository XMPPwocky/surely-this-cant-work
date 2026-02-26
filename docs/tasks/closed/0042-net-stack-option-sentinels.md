# 0042: Replace usize::MAX sentinels in net-stack with Option

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** user/net-stack

## Description

Net-stack uses `usize::MAX` as a sentinel value for "no handle" / "no
connection" in several places. Replace these with `Option<usize>` for
type safety and to prevent bugs where a sentinel value is accidentally
used as a real handle.

## Resolution

Replaced all internal sentinel patterns with `Option<usize>`:

- `TcpConn.socket_idx`: `usize` → `Option<usize>` (owning socket index)
- `TcpConn.listener_sock_idx`: `usize` → `Option<usize>` (listener socket)
- `Socket.tcp_conn_idx`: `usize` → `Option<usize>` (TCP connection index)
- `Socket.accept_queue`: `[usize; N]` → `[Option<usize>; N]` (pending accepts)

All 24 sentinel check sites (`!= usize::MAX`, `== usize::MAX`) replaced
with `if let Some(idx)` / `let Some(idx) = ... else` pattern matching.
Removed redundant bounds checks (`si < MAX_SOCKETS`) that were defensive
against sentinel confusion — `Option` eliminates this class of bug.

Left the `sys_mmap` return check (`== usize::MAX`) unchanged since it's
at the syscall ABI boundary.
