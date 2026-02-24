# 0016: Multi-Interface Net-Stack with Loopback

**Date:** 2026-02-24
**Status:** Design
**Subsystem:** user/net-stack, lib/rvos

## Motivation

The net-stack is hardcoded to a single VirtIO NIC. There is no loopback
interface, so processes on the VM cannot communicate with each other via
TCP/IP using the VM's own IP address or 127.0.0.1. This blocks:

- http-client fetching from http-server on the same VM
- Any localhost-based service communication
- Testing network services without an external client

The user wants multi-interface support where loopback is "just another
NIC" and packets destined for any of our own IPs are delivered directly
to that interface's receive path.

## Design

### Overview

Introduce an `Interface` abstraction in net-stack that bundles per-NIC
state (IP config, MAC, ARP table, SHM handles, loopback queue). The
loopback interface is a virtual NIC with no SHM/driver — its TX path
pushes packets directly into its own RX queue. A simple routing table
selects which interface handles each outbound packet.

**No kernel changes required.** The loopback interface exists entirely
within the net-stack process. The kernel net-server and VirtIO driver
are unchanged.

### Interface Struct

```rust
const MAX_INTERFACES: usize = 4;
const IFACE_LOOPBACK: usize = 0;  // loopback is always interface 0

struct Interface {
    active: bool,
    name: &'static str,         // "lo", "eth0", etc.
    mac: [u8; 6],               // all-zeros for loopback
    config: NetConfig,          // IP, gateway, mask, DNS
    arp_table: ArpTable,        // per-interface (unused for loopback)
    // Hardware NIC fields (None for loopback)
    shm_base: Option<usize>,
    raw_handle: Option<usize>,
    // Loopback RX queue — packets "transmitted" on loopback land here
    loopback_rx: Vec<Vec<u8>>,
}
```

The existing `NetConfig`, `ArpTable` types are unchanged — they just
move from standalone variables into `Interface`.

### Routing

A new `route()` function selects the outgoing interface:

```rust
fn route(interfaces: &[Interface], dst_ip: &[u8; 4]) -> usize {
    // 1. Loopback: 127.x.x.x → IFACE_LOOPBACK
    if dst_ip[0] == 127 {
        return IFACE_LOOPBACK;
    }
    // 2. Any of our own IPs → IFACE_LOOPBACK
    for (i, iface) in interfaces.iter().enumerate() {
        if iface.active && iface.config.our_ip == *dst_ip {
            return IFACE_LOOPBACK;
        }
    }
    // 3. Default: first active non-loopback interface
    for (i, iface) in interfaces.iter().enumerate() {
        if iface.active && i != IFACE_LOOPBACK {
            return i;
        }
    }
    IFACE_LOOPBACK // fallback (will fail gracefully)
}
```

### TX Path Changes

`send_ip_packet()` gains an interface index parameter. The function
checks if the interface is loopback:

- **Loopback TX:** Wrap the IP packet in a minimal Ethernet frame
  (src=dst=`[0;6]`) and push it onto `iface.loopback_rx`. No ARP,
  no SHM, no driver interaction.
- **Hardware TX:** Existing behavior — ARP resolve, build Ethernet
  frame, write to SHM TX ring, send doorbell.

`tcp_send_segment()` similarly gains the interface index, forwarded
from the TCP connection's routing decision.

### RX Path Changes

The main event loop drains two sources:

1. **SHM RX ring** (existing) — for hardware NIC frames
2. **Loopback RX queue** (new) — drain `interfaces[IFACE_LOOPBACK].loopback_rx`

Both feed into the same `process_ip_packet()` function (extracted from
`process_frame()`'s IPv4 branch). The loopback path skips Ethernet
parsing and ARP learning since loopback frames have synthetic headers.

### process_frame Refactor

Extract the IPv4 processing logic from `process_frame()` into a
standalone `process_ip_packet()` function:

```rust
fn process_ip_packet(
    ip: &Ipv4Header, ip_payload: &[u8],
    interfaces: &mut [Interface],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    // ... other params ...
) { ... }
```

`process_frame()` calls this after Ethernet parsing.
The loopback drain calls this after parsing the IP header from the
loopback queue entry.

### TCP Connection Routing

TCP connections need to know which interface to use for their segments.
Add `iface_idx: usize` to `TcpConn`. Set it during:

- **Active open (Connect):** `route(interfaces, &dst_addr)`
- **Passive open (SYN received):** Interface index from whichever
  interface received the SYN

All subsequent `tcp_send_segment()` calls for that connection use
`conn.iface_idx` to select the interface.

### UDP Routing

For `SendTo`, route each datagram: `route(interfaces, &dst_ip)`.
No per-socket interface binding — route per-packet.

### IP Destination Check

Currently (line 1086):
```rust
if ip.dst != config.our_ip && !config.is_broadcast(&ip.dst) && ip.dst != ZERO_IP {
    return;
}
```

Change to check against **all** interface IPs:
```rust
let accepted = interfaces.iter().any(|iface| {
    iface.active && (ip.dst == iface.config.our_ip || iface.config.is_broadcast(&ip.dst))
}) || ip.dst == ZERO_IP;
if !accepted { return; }
```

### GetConfig Response

Currently returns a single IP/gateway/mask/dns. With multiple
interfaces, return the **primary** (first non-loopback) interface's
config. No protocol change needed.

### Loopback IP Assignment

The loopback interface gets `127.0.0.1/8` with no gateway:
```rust
interfaces[IFACE_LOOPBACK] = Interface {
    active: true,
    name: "lo",
    mac: [0; 6],
    config: NetConfig {
        our_ip: [127, 0, 0, 1],
        gateway: [0; 4],
        subnet_mask: [255, 0, 0, 0],
        dns_server: [0; 4],
    },
    arp_table: ArpTable::new(),
    shm_base: None,
    raw_handle: None,
    loopback_rx: Vec::new(),
};
```

### Interface Changes

**No wire protocol changes.** No syscall changes. No std rebuild needed.

| Change | Scope |
|--------|-------|
| New `Interface` struct | net-stack internal |
| `loopback_rx: Vec<Vec<u8>>` field | net-stack internal |
| `route()` function | net-stack internal |
| `iface_idx` on `TcpConn` | net-stack internal |
| Extract `process_ip_packet()` | refactor within net-stack |

### Resource Limits

- `MAX_INTERFACES = 4` (1 loopback + up to 3 hardware NICs)
- Loopback RX queue: unbounded `Vec` (bounded in practice by single-
  threaded processing — items are drained every main loop iteration)
- No new channels, handles, or kernel resources

## Blast Radius

All changes are within `user/net-stack/src/main.rs`. No kernel, protocol,
or library changes.

| Change | Scope | Risk |
|--------|-------|------|
| Replace standalone `config`/`arp_table`/`shm_base`/`raw_handle`/`our_mac` with `interfaces[]` array | ~30 functions in net-stack | Medium — mechanical but large; every function that takes these params needs updating |
| Add `iface_idx` to `TcpConn` | `TcpConn` struct + all `tcp_send_segment` call sites | Low — additive field, index passed through |
| Extract `process_ip_packet()` from `process_frame()` | `process_frame()` split into two functions | Low — pure refactor, same logic |
| Add loopback drain to main event loop | Main loop (lines 2818-2855) | Low — additive, after existing SHM drain |
| Route selection in `send_ip_packet()` | `send_ip_packet()` + callers | Medium — must not break existing single-NIC path |

### Key Functions to Update (callers/signatures)

Functions that currently take `(shm_base, raw_handle, our_mac, config, arp_table, ...)`:

- `send_ip_packet()` — 2 call sites
- `tcp_send_segment()` — 18 call sites
- `tcp_send_rst()` — 5 call sites
- `process_frame()` — 1 call site
- `drain_pending()` — 2 call sites
- `handle_client_message()` — 1 call site
- `tcp_input()` — 1 call site
- `tcp_check_retransmit()` — 1 call site
- `send_arp_request()` — 4 call sites
- `handle_arp()` — 1 call site

**Strategy:** Pass `interfaces: &mut [Interface; MAX_INTERFACES]` and
`iface_idx: usize` instead of the 5 separate params. This actually
**reduces** parameter count for most functions.

## Acceptance Criteria

- [ ] `make build` succeeds
- [ ] `make clippy` clean
- [ ] `make test-quick` passes (no regressions)
- [ ] `make test` passes (no regressions)
- [ ] Boot with MCP + network: DHCP works, `http-client http://example.com/` works (external traffic through eth0 still works)
- [ ] `http-server 80 &` then `http-client http://10.0.2.X/` succeeds (loopback via own IP)
- [ ] `http-client http://127.0.0.1:80/` succeeds (loopback via 127.0.0.1)
- [ ] `curl http://10.0.2.X/` from host still works (external→VM path unchanged)
- [ ] Write ktest: http-client fetches from http-server on same VM

## Deferred

| Item | Rationale |
|------|-----------|
| Multiple hardware NICs | Kernel VirtIO net driver only supports one device; needs driver refactor |
| Per-socket interface binding | Not needed yet; route-per-packet is sufficient |
| Configurable routing table | Only two interfaces (lo + eth0); hardcoded routing is fine |
| IPv6 loopback (::1) | No IPv6 support anywhere |

## Implementation Notes

(Updated during implementation)

## Verification

(Updated after implementation)
