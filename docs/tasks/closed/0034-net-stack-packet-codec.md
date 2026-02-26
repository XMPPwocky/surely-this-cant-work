# 0034: Add PacketCodec trait for net-stack header parsing

**Reported:** 2026-02-26
**Status:** Closed (2026-02-26) — addressed by 0037
**Severity:** LOW
**Subsystem:** user/net-stack

## Description

Net-stack manually parses packet headers using raw byte-offset indexing.
Add typed header structs or a PacketCodec trait to replace manual parsing.

## Resolution

Already addressed by the module split (task 0037). Each protocol module
now has typed header structs with named fields:

- `eth::EthHdr` — dst, src, ethertype
- `ipv4::IpHdr` — src, dst, proto, total_len
- `udp::UdpHdr` — src_port, dst_port, len
- `tcp::TcpHdr` — src_port, dst_port, seq, ack, flags, window

All byte-offset parsing is encapsulated in `parse_*()`/`build_*()`
functions within each module. Adding a trait on top would not provide
additional safety or clarity — the current approach is already
well-structured with type-safe accessors.
