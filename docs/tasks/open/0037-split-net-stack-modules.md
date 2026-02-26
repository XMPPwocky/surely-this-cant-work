# 0037: Split net-stack into modules

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/net-stack
**Source:** Arch review 7, backlog item 15

## Description

`user/net-stack/src/main.rs` is ~3100 lines containing ARP, IP, ICMP, UDP,
TCP, DHCP, DNS, and the socket server all in one file. Split into separate
modules (e.g., `tcp.rs`, `udp.rs`, `dhcp.rs`, `arp.rs`, `dns.rs`,
`socket_server.rs`) for maintainability.
