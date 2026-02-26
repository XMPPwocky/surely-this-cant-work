# 0033: Unify error types across lib/rvos

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** lib/rvos
**Source:** Arch review 8, item 5

## Description

`SysError`, `RecvError`, and `RpcError` are separate types with no `From` impls
connecting them. App code that calls both channel operations and RPC operations
needs manual error mapping or `.map_err()` chains.

Compose them via `From` impls or introduce a unified `AppError` that wraps all
three, so apps can use `?` naturally across syscall/channel/rpc boundaries.
