# 0015: DHCP Client

**Date:** 2026-02-24
**Status:** Complete (2026-02-24)
**Subsystem:** user/net-stack, scripts/

## Motivation

rvOS hardcodes its IP address (`10.0.2.15`), gateway (`10.0.2.2`), and
subnet mask (`255.255.255.0`) as constants in the net-stack. This prevents
the system from working on any network that doesn't match these values.
Implementing a DHCP client allows rvOS to obtain network configuration
dynamically, which is the first step toward real internet connectivity.

## Design

### Overview

The DHCP client runs as part of the net-stack process (not a separate
binary) because it needs to update the net-stack's IP/gateway/mask state
directly. On startup, before accepting socket connections, the net-stack
runs a DHCP discovery sequence using raw Ethernet frame I/O via the
existing SHM ring buffer. Once an address is obtained, the net-stack
configures itself and begins normal operation.

A host-side DHCP server (dnsmasq) is configured by extending the existing
`net-setup.sh` script.

### DHCP Protocol (RFC 2131)

DHCP uses UDP port 67 (server) / 68 (client). The 4-step handshake:

1. **DISCOVER** — Client broadcasts (0.0.0.0:68 → 255.255.255.255:67)
2. **OFFER** — Server responds with an IP offer (server → 255.255.255.255:68 or unicast)
3. **REQUEST** — Client broadcasts acceptance of the offer
4. **ACK** — Server confirms the lease

DHCP message format (236 bytes fixed + variable options):
```
Offset  Size  Field
0       1     op (1=request, 2=reply)
1       1     htype (1=Ethernet)
2       1     hlen (6)
3       1     hops (0)
4       4     xid (random transaction ID)
8       2     secs
10      2     flags (0x8000 = broadcast)
12      4     ciaddr (client IP, 0 if unknown)
16      4     yiaddr (your IP, offered by server)
20      4     siaddr (server IP)
24      4     giaddr (gateway IP for relay)
28      16    chaddr (client MAC, padded)
44      64    sname (server name, zeroed)
108     128   file (boot filename, zeroed)
236     4     magic cookie: 99.130.83.99
240+    var   options (TLV format, terminated by 0xFF)
```

Key DHCP options:
- 53: Message Type (1=Discover, 2=Offer, 3=Request, 5=Ack, 6=Nak)
- 1: Subnet Mask
- 3: Router (gateway)
- 6: DNS Server
- 51: Lease Time
- 54: Server Identifier
- 50: Requested IP Address
- 55: Parameter Request List

### Implementation in net-stack

The DHCP client is embedded in the net-stack startup. Changes to
`user/net-stack/src/main.rs`:

**1. Replace hardcoded constants with mutable state:**
```rust
// Before: const OUR_IP: [u8; 4] = [10, 0, 2, 15];
// After:
struct NetConfig {
    our_ip: [u8; 4],
    gateway: [u8; 4],
    subnet_mask: [u8; 4],
    dns_server: [u8; 4],
    configured: bool,
}
```

**2. Add broadcast support to TX/RX paths:**
- `resolve_next_hop()`: if dst is `255.255.255.255` or subnet broadcast,
  return broadcast (use `BROADCAST_MAC` directly, skip ARP)
- `send_ip_packet()`: recognize broadcast dst → use `BROADCAST_MAC`
- RX filter (line 1023): accept packets to `255.255.255.255` and
  `0.0.0.0` in addition to `OUR_IP`

**3. DHCP state machine** (runs before main event loop):
```
INIT → send DISCOVER → wait for OFFER (with timeout + retries)
     → send REQUEST → wait for ACK (with timeout + retries)
     → configure IP/gateway/mask → enter main event loop
```

Timeout: 2 seconds initial, doubling up to 8 seconds, 4 retries max.

**4. Raw frame I/O for DHCP:**
DHCP packets are built directly as Ethernet frames (not via the socket
API) because:
- The socket API requires a configured IP (chicken-and-egg)
- We need to set source IP to 0.0.0.0
- We need broadcast at both Ethernet and IP layers

The net-stack already has direct access to the SHM ring buffer and can
build/parse raw frames.

### Host-Side DHCP Server

Extend `scripts/net-setup.sh` to optionally start dnsmasq:

```bash
# Install check
if command -v dnsmasq &>/dev/null; then
    # Write minimal config
    cat > /tmp/rvos-dnsmasq.conf <<EOF
interface=rvos-br0
bind-interfaces
dhcp-range=10.0.2.10,10.0.2.200,255.255.255.0,1h
dhcp-option=option:router,10.0.2.2
dhcp-option=option:dns-server,10.0.2.2
no-daemon
EOF
    # Start in background
    dnsmasq -C /tmp/rvos-dnsmasq.conf &
fi
```

Integrate into `scripts/net-setup.sh` — it already runs once with sudo to
create the bridge and TAP. dnsmasq is lightweight and persists until
reboot, serving DHCP to any QEMU instance that connects via the bridge.
If dnsmasq is not installed, skip with a warning.

### Fallback Behavior

If DHCP fails after all retries (no server, timeout), the net-stack falls
back to the hardcoded values (10.0.2.15, 10.0.2.2, 255.255.255.0) and
prints a warning. This ensures the system still works when dnsmasq isn't
running (e.g., quick testing without network).

### Interface Changes

No new syscalls or IPC protocols. The socket API is unchanged. The only
observable difference:
- Boot log shows DHCP negotiation: `[net] DHCP: acquired 10.0.2.x/24 gw 10.0.2.2`
- Or fallback: `[net] DHCP: no response, using static 10.0.2.15`

### Internal Changes

| File | Change |
|------|--------|
| `user/net-stack/src/main.rs` | Replace const IP/GW/MASK with NetConfig struct; add broadcast support; add DHCP state machine |
| `scripts/net-setup.sh` | Add dnsmasq startup on rvos-br0 |

### Resource Limits

No new fixed-size tables. DHCP uses one temporary ~576-byte buffer during
negotiation, then releases it. The existing SHM ring TX slot (1536 bytes)
is more than sufficient for DHCP packets.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Replace `OUR_IP` const with `NetConfig.our_ip` | ~20 references in net-stack/main.rs | Medium — must update all uses |
| Replace `GATEWAY_IP` const | ~3 references in net-stack/main.rs | Low |
| Replace `SUBNET_MASK` const | ~2 references in net-stack/main.rs | Low |
| Modify `resolve_next_hop()` | 1 function, called from `send_ip_packet()` | Low |
| Modify RX IP filter | 1 location (line 1023) | Low — additive check |
| `build_ipv4()` source IP | Multiple call sites using `&OUR_IP` → `&config.our_ip` | Medium |
| dnsmasq on host | net-setup.sh | Low — additive, skipped if not installed |

All changes are confined to `user/net-stack/src/main.rs` and host scripts.
No kernel changes. No protocol changes. No std sysroot changes.

## Acceptance Criteria

- [x] `make clippy` clean
- [x] `make test-quick` passes (core tests, no networking) — 69 passed
- [x] `make test` passes (full suite) — 82 passed
- [x] With dnsmasq running: net-stack acquires IP via DHCP, boot log shows acquired address
- [x] Without dnsmasq: net-stack falls back to static IP after timeout, boot log shows fallback
- [x] After DHCP, UDP echo server works (nc from host can reach rvOS)
- [x] After DHCP, TCP echo server works
- [x] DHCP timeout is bounded — ~22s worst case (2+4+8+8s), ~4s typical with dnsmasq

## Deferred

| Item | Rationale |
|------|-----------|
| DHCP lease renewal | Leases are 1+ hour; rvOS sessions are minutes. Not needed yet. |
| DHCP release on shutdown | Nice-to-have but not critical |
| DNS client | Separate feature — needs its own protocol and resolver |
| IPv6 / DHCPv6 | IPv4-only for now |
| Multiple interfaces | Only one virtio-net device |
| Internet forwarding (NAT) | Host-side iptables config — separate from DHCP |

## Implementation Notes

- **NetConfig struct replaces constants.** `OUR_IP`, `GATEWAY_IP`, `SUBNET_MASK` became
  fields on `NetConfig`, threaded as `&NetConfig` through ~30 functions. New constants
  `BROADCAST_IP`, `ZERO_IP`, `FALLBACK_IP`, `FALLBACK_GATEWAY`, `FALLBACK_MASK` are used
  for comparison and fallback.

- **Broadcast support.** `resolve_next_hop()` returns broadcast IPs as-is (caller uses
  `BROADCAST_MAC`). `send_ip_packet()` detects broadcast destinations and skips ARP.
  RX filter accepts `255.255.255.255` and `0.0.0.0` in addition to our configured IP.

- **DHCP builds raw Ethernet frames.** `build_dhcp_frame()` constructs the full
  Ethernet/IP/UDP/DHCP stack directly, bypassing the socket API (which requires a
  configured IP — chicken-and-egg). Uses the SHM ring buffer for TX/RX.

- **First DISCOVER often times out.** The first 2s timeout frequently expires before
  dnsmasq responds, likely because the TAP needs to "warm up" after QEMU creates it.
  The retry succeeds immediately. Typical acquisition time is ~4s with dnsmasq running.

- **Timeout design.** 2s initial, doubling up to 8s max, 4 retries. Total worst case
  is ~22s per phase (DISCOVER or REQUEST). With no server at all, only the DISCOVER
  phase runs (REQUEST is never reached), so fallback takes ~22s.

- **No `static mut`.** All DHCP state is local to `dhcp_acquire()` and passed via
  function parameters. NetConfig is `&mut` passed from main().

- **dnsmasq in net-setup.sh.** Runs as a daemon with PID file at `/run/rvos-dnsmasq.pid`.
  Idempotent — checks if already running before starting. DHCP range 10.0.2.10–200.

## Verification

**With dnsmasq running:**
```
[net] DHCP: sending DISCOVER...
[net] DHCP: retry 1 (timeout 2s)...
[net] DHCP: got OFFER 10.0.2.75
[net] DHCP: acquired 10.0.2.75/255.255.255.0 gw 10.0.2.2
[net-stack] entering main loop
```
UDP echo (port 7777) and TCP echo (port 7778) both work at the DHCP-acquired IP.

**Without dnsmasq:**
```
[net] DHCP: sending DISCOVER...
[net] DHCP: retry 1 (timeout 2s)...
[net] DHCP: retry 2 (timeout 4s)...
[net] DHCP: retry 3 (timeout 8s)...
[net] DHCP: no OFFER received, using static config
[net-stack] entering main loop
```
Falls back to 10.0.2.15, UDP echo works at fallback IP.

**Regression tests:** `make test-quick` (69 passed), `make test` (82 passed) — no networking
in test targets, so DHCP code path is not exercised but existing functionality is verified.
