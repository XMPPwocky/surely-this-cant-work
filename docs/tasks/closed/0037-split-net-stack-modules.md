# 0037: Split net-stack into modules

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26)
**Severity:** LOW
**Subsystem:** user/net-stack

## Description

`user/net-stack/src/main.rs` is ~3100 lines containing ARP, IP, ICMP, UDP,
TCP, DHCP, DNS, and the socket server all in one file. Split into separate
modules for maintainability.

## Resolution

Split the monolithic main.rs into 7 files:

| Module | Lines | Contents |
|--------|-------|----------|
| eth.rs | 40 | Ethernet frame parse/build |
| arp.rs | 183 | ARP table, request/response handling |
| ipv4.rs | 97 | IPv4 header parse/build, checksum |
| udp.rs | 111 | UDP parse/build, checksum |
| tcp.rs | 1482 | TCP state machine, connections, sockets, client handlers |
| dhcp.rs | 422 | DHCP client (discover, offer, request, ack) |
| main.rs | 863 | Shared constants, interfaces, packet dispatch, main loop |

main.rs went from 3125 to 863 lines. Each protocol layer is now in its
own module with clear pub(crate) boundaries.
