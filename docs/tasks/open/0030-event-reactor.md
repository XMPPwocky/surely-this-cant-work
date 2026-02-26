# 0030: Add event Reactor wrapper to lib/rvos

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** lib/rvos, ipc

## Problem

Apps that multiplex multiple channels must manually call
`sys_chan_poll_add()` for each handle, then `sys_block()`, then check each
handle for readiness. This poll/block/check pattern is verbose and
error-prone:

```rust
raw::sys_chan_poll_add(stdin_h);
if let Some(eh) = dbg.event_handle {
    raw::sys_chan_poll_add(eh);
}
raw::sys_block();
// ... manually try_recv on each handle to see which is ready
```

This appears in `dbg.rs` (stdin + debug events), `nc.rs` (stdin + socket,
3 separate relay functions), `window-server` (ctl + kbd + mouse), and
poll-loop servers like `fs` and `ext2-server`.

See: Architecture Review 8, section 4 ("MEDIUM: Event Multiplexer").

## Proposed API

```rust
// lib/rvos/src/reactor.rs (new file)

pub struct Reactor {
    handles: Vec<usize>,
}

impl Reactor {
    pub fn new() -> Self;

    /// Register a channel handle to be polled.
    pub fn add(&mut self, handle: usize);

    /// Remove a channel handle from the poll set.
    pub fn remove(&mut self, handle: usize);

    /// Block until at least one registered channel has data.
    /// Returns the set of ready handles.
    pub fn wait(&self) -> SmallVec<usize>;

    /// Non-blocking: register all handles for polling and block.
    /// Caller then uses try_recv on returned ready handles.
    pub fn poll_and_block(&self);
}
```

Usage:
```rust
let mut reactor = Reactor::new();
reactor.add(stdin_handle);
reactor.add(event_handle);

loop {
    reactor.poll_and_block();
    // try_recv on each handle...
}
```

The implementation is thin — it just wraps the `sys_chan_poll_add` +
`sys_block` pattern — but it prevents forgetting to register a handle
and centralizes the poll set management.

## Acceptance Criteria

1. `Reactor` type added to `lib/rvos`.
2. `dbg.rs` converted to use `Reactor` for stdin + event multiplexing.
3. At least one other app (nc or window-server) converted as proof.
4. `make build` + `make clippy` clean.
5. `make test-quick` passes.
