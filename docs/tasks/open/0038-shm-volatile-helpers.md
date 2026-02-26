# 0038: Extract SHM volatile helpers to shared lib

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** kernel/drivers, lib/rvos
**Source:** Arch review 6, carried through reviews 7-8

## Description

VirtIO drivers use `read_volatile`/`write_volatile` for DMA shared memory
access. The patterns are repeated across blk, gpu, net, and input drivers.
Extract common volatile accessor helpers (e.g., for ring buffer operations)
into a shared utility module to reduce boilerplate and ensure correctness.
