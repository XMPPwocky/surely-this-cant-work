# 0041: Add WFI timeout to VirtIO net transmit

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** kernel/drivers/virtio

## Description

VirtIO net transmit uses a WFI spin loop waiting for the device to consume
a descriptor. If the device never completes, this hangs the kernel task
forever.

## Resolution

Added a 10,000-iteration timeout to the WFI poll loop in `net::transmit()`.
On timeout, the descriptor is freed and the function returns false (failure)
with a diagnostic message. This prevents the kernel from hanging
indefinitely on a misbehaving or misconfigured VirtIO net device.

The GPU driver already had a similar timeout (via an attempts counter).
The block driver's WFI loops were not changed since block I/O failures
typically manifest quickly (device error status) rather than as infinite
hangs.
