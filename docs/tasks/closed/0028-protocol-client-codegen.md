# 0028: Auto-generate protocol client stubs from define_protocol!

**Reported:** 2026-02-26
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** lib/rvos-wire, lib/rvos

## Problem

`define_protocol!` generates server-side dispatch (deserialize request,
match variant, call handler) but no client-side caller. Every app that
talks to a service must manually: allocate a `Message`, serialize the
request with `rvos_wire::to_bytes`, call `sys_chan_send_blocking`, allocate
another `Message`, call `sys_chan_recv_blocking`, deserialize the response
with `rvos_wire::from_bytes`. This is 6 lines of boilerplate per RPC call.

`dbg.rs` has 10 identical RPC methods (attach, suspend, resume, regs,
setreg, mem, write, breakpoint, clear, backtrace) — 60 lines of pure
boilerplate that should be one-liners. `shell.rs` has the same pattern
for sysinfo. `nc.rs` has it for socket operations.

`MathClient` exists as a hand-written proof-of-concept but the pattern
was never generalized.

See: Architecture Review 8, sections 2b, 4 ("HIGH: Auto-Generated Protocol
Clients").

## Scope

Affected apps: `user/dbg` (10 stubs), `user/shell` (sysinfo interaction),
`user/nc` (socket RPC). Future services would also benefit.

## Proposed Design

Extend `define_protocol!` (or add a companion `define_client!` macro) to
emit a typed client struct:

```rust
// Auto-generated from protocol definition:
pub struct DebugClient {
    transport: UserTransport,
}

impl DebugClient {
    pub fn new(transport: UserTransport) -> Self { ... }

    pub fn attach(&mut self, pid: usize)
        -> Result<DebugAttachResponse, RpcError>
    {
        self.transport.rpc_call(&DebugRequest::Attach { pid })
    }

    pub fn suspend(&mut self) -> Result<SuspendResponse, RpcError> {
        self.transport.rpc_call(&DebugRequest::Suspend {})
    }

    // ... one method per request variant
}
```

The `UserTransport::rpc_call` method already exists and handles
serialize/send/recv/deserialize. The macro just needs to generate the
thin wrapper methods.

## Acceptance Criteria

1. `define_protocol!` (or companion macro) generates client stubs.
2. `dbg.rs` converted to use generated `DebugClient` — manual RPC
   boilerplate removed.
3. Shell's sysinfo interaction converted to use generated client.
4. `MathClient` replaced by generated version (or confirmed equivalent).
5. `make build` + `make clippy` clean.
6. `make test-quick` passes.
