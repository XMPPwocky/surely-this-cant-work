# 0011: net_server uses 1534-byte frame buffer on kernel stack

**Reported:** 2026-02-20
**Status:** Open
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

The net_server doesn't use any heap allocations at all — its SHM pages come
from `frame_alloc_contiguous` (page-level allocator), not the heap. The
`NetsAlloc` heap tag was pre-defined but is `#[allow(dead_code)]` and unused.

## Code Location

`kernel/src/services/net_server.rs:223`:
```rust
let mut frame_buf = [0u8; 1534];
```

## Suggested Fix

Replace the stack-allocated frame buffer with a DMA buffer allocated once
at init time (like `tx_buf` in the VirtIO net driver), or use a heap
allocation via `NetsAlloc` and pass `&mut` down.

## Root Cause

(Not applicable — latent code quality issue, not a triggered bug.)

## Fix

(Deferred — low severity, no crash observed.)

## Verification

(Pending fix.)

## Lessons Learned

(Pending fix.)
