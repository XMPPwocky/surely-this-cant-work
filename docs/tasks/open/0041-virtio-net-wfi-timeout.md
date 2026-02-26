# 0041: Add WFI timeout to VirtIO net transmit

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** kernel/drivers/virtio
**Source:** Arch review 5, carried through reviews 6-8

## Description

VirtIO net transmit uses a WFI (wait-for-interrupt) spin loop waiting for
the device to consume a descriptor. If the device never completes (e.g.,
misconfiguration, device error), this hangs the kernel task forever. Add
a timeout so the transmit path returns an error instead of hanging
indefinitely.
