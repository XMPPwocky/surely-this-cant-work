# DHCP Protocol

The net-stack includes a built-in DHCP client that runs at boot to acquire
network configuration for the eth0 interface. It operates at the raw Ethernet
frame level via the `net-raw` shared memory ring, before the socket layer is
initialized.

Implementation: `user/net-stack/src/main.rs` (DHCP section)

## Overview

The DHCP client implements the standard 4-message exchange (RFC 2131):

```
net-stack                          DHCP Server
    |                                   |
    |-- DISCOVER (broadcast) --------->|
    |<-- OFFER (your_ip, options) -----|
    |-- REQUEST (your_ip, server) ---->|
    |<-- ACK (confirmed config) ------|
    |                                   |
    (configure eth0 interface)
```

If no OFFER is received after retries with exponential backoff, the
net-stack falls back to a static IP configuration.

## DHCP Message Format

Messages are sent as raw Ethernet frames containing:
- Ethernet header (broadcast destination `FF:FF:FF:FF:FF:FF`)
- IPv4 header (src `0.0.0.0`, dst `255.255.255.255`)
- UDP header (src port 68, dst port 67)
- DHCP payload (576 bytes, BOOTP format)

### DHCP Payload Fields

| Offset | Size | Field    | Value                          |
|--------|------|----------|--------------------------------|
| 0      | 1    | op       | 1 (BOOTREQUEST)                |
| 1      | 1    | htype    | 1 (Ethernet)                   |
| 2      | 1    | hlen     | 6 (MAC length)                 |
| 4-7    | 4    | xid      | Transaction ID (from MAC)       |
| 10     | 1    | flags    | 0x80 (broadcast)               |
| 28-33  | 6    | chaddr   | Client MAC address             |
| 236-239| 4    | cookie   | 99.130.83.99 (DHCP magic)      |

### DHCP Options Sent

| Option | Name            | DISCOVER | REQUEST |
|--------|-----------------|----------|---------|
| 53     | Message Type    | 1 (DISCOVER) | 3 (REQUEST) |
| 50     | Requested IP    | --       | offered IP |
| 54     | Server ID       | --       | server IP  |
| 55     | Param Request   | 1 (subnet), 3 (router), 6 (DNS) | same |

### DHCP Options Parsed from Response

| Option | Name         | Used For           |
|--------|--------------|--------------------|
| 53     | Message Type | OFFER (2) / ACK (5) |
| 1      | Subnet Mask  | Interface config   |
| 3      | Router       | Default gateway    |
| 6      | DNS Server   | DNS resolver       |

## Configuration Applied

On successful ACK, the net-stack configures:
- **IP address**: `yiaddr` from the DHCP response
- **Subnet mask**: from option 1 (default: `255.255.255.0`)
- **Gateway**: from option 3 (fallback: server IP)
- **DNS server**: from option 6 (fallback: gateway IP)

## Retry Behavior

Each phase (DISCOVER and REQUEST) uses exponential backoff:
- Initial timeout: 2 seconds
- Doubles each retry
- Maximum 3 retries per phase
- If all retries fail, falls back to static configuration

## Constants

```
DHCP_SERVER_PORT  = 67
DHCP_CLIENT_PORT  = 68
DHCP_MAGIC_COOKIE = [99, 130, 83, 99]
```
