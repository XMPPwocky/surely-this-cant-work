# 0011: net_server uses 1534-byte frame buffer on kernel stack

**Reported:** 2026-02-20
**Status:** Closed
**Severity:** LOW
**Subsystem:** kernel/services/net_server

## Symptoms

No crash observed yet, but `net_server.rs:223` allocates a `[u8; 1534]`
frame buffer on the kernel task stack for TX frame copies. This violates the
project convention ("No large buffers on the stack") and risks stack overflow
if nested calls or additional locals increase total stack depth.

## Context

Found during code review while implementing blk_server (step 4 of the ext2
filesystem feature). The design rules in MEMORY.md and kernel CLAUDE.md
explicitly prohibit putting packet-sized arrays on the stack.

The net_server doesn't use any heap allocations at all -- its SHM pages come
from `frame_alloc_contiguous` (page-level allocator), not the heap. The
`NetsAlloc` heap tag was pre-defined but is `#[allow(dead_code)]` and unused.

## Code Location

`kernel/src/services/net_server.rs:223`:
```rust
let mut frame_buf = [0u8; 1534];
```

## Root Cause

Latent code quality issue -- the frame buffer was placed on the stack
without considering the kernel task stack size constraints.

## Fix

Replaced the stack-allocated `[0u8; 1534]` with a `Vec<u8>` allocated
once before the main loop using the `NETS_ALLOC` tagged allocator. The
buffer is reused across all TX iterations via `&mut` reference. Also
removed `#[allow(dead_code)]` from the `NetsAlloc` type and `NETS_ALLOC`
const since they are now used.

## Verification

`make test-quick` passes (69/69 tests). `make clippy` clean.

## Lessons Learned

Pre-defined allocator tags should be used when the subsystem needs heap
allocations. The `NETS_ALLOC` tag was already defined for this purpose.
