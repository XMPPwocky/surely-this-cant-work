# 0026: Sysinfo service single-client design

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** services/sysinfo

## Description

The sysinfo service handles one client at a time using `accept_client` +
`channel_recv_blocking`. While serving a request (e.g., a slow `ps` or
`trace` command that generates large output), other clients block waiting
for the service to loop back and accept them.

This is similar to the blk_server single-client issue (0024) but lower
severity because sysinfo commands are fast and infrequent.

## Impact

Under normal usage: negligible. Could cause visible delays if multiple
processes query sysinfo simultaneously (unlikely in practice).

## Potential Fix

Convert to poll-based multiplexing (like the console server) or add a small
client queue. Low priority — the current design works fine for interactive use.
