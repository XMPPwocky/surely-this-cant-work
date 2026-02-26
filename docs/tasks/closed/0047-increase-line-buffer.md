# 0047: Increase shell line buffer from 256 chars

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/shell
**Source:** Arch review 5, carried through review 7

## Description

The shell's line input buffer is 256 bytes. Long commands (e.g., paths with
many components, long arguments) get silently truncated. Increase to at least
1024 bytes, or make the buffer dynamically growable via Vec.
