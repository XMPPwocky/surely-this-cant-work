# 0034: Add PacketCodec trait for net-stack header parsing

**Reported:** 2026-02-26
**Status:** Open
**Severity:** LOW
**Subsystem:** user/net-stack
**Source:** Arch review 8, item 6

## Description

Net-stack manually parses packet headers using raw byte-offset indexing
(e.g., `buf[12..14]` for EtherType, `buf[20..22]` for TCP port). This is
error-prone and hard to audit.

Add a `PacketCodec` trait or typed header structs (`EthHeader`, `IpHeader`,
`TcpHeader`, `UdpHeader`) that encode/decode via named fields. Replace manual
byte-offset parsing across the ~3100-line net-stack with structured accessors.
