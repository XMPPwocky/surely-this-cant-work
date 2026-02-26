# 0038: Extract SHM volatile helpers to shared lib

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** kernel/drivers

## Description

VirtIO drivers use `read_volatile`/`write_volatile` for DMA shared memory
access. The patterns are repeated across blk, gpu, net, and input drivers.
Extract common volatile accessor helpers to reduce boilerplate and ensure
correctness.

## Resolution

- Added `clear_status()` and `read_status()` helpers to blk.rs, replacing
  8 inline volatile accesses for the status buffer.
- Fixed queue.rs init code: replaced non-volatile `&mut *` references with
  `addr_of_mut!` + `write_volatile` for DMA memory initialization
  (avail ring and used ring zeroing).
- queue.rs already had good abstractions (write_desc, free_desc, push_avail,
  pop_used) — no further extraction needed there.
- A shared lib-level extraction was not warranted: each driver's volatile
  patterns are specific to its device type, and queue.rs already centralizes
  the common virtqueue operations.
