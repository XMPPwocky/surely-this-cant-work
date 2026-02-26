// ---------------------------------------------------------------------------
// DHCP Client
// ---------------------------------------------------------------------------

use rvos::raw;
use rvos::rvos_wire;
use rvos_proto::net::NetRawRequest;

use crate::eth::{parse_eth, ETH_HDR_SIZE, ETHERTYPE_IPV4};
use crate::ipv4::parse_ipv4;
use crate::udp::parse_udp;
use crate::{
    now_ticks, shm_read_u16, shm_read_u32, shm_write_u32, tx_frame,
    NetConfig, TxScratch, RxScratch,
    BROADCAST_IP, BROADCAST_MAC, ZERO_IP,
    PROTO_UDP, TICK_HZ,
    CTRL_RX_HEAD, CTRL_RX_TAIL, RX_RING_OFFSET, RX_SLOT_SIZE, RX_SLOTS,
};

// ---------------------------------------------------------------------------
// DHCP constants
// ---------------------------------------------------------------------------

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// DHCP message types
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

// DHCP options
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST: u8 = 55;
const OPT_END: u8 = 255;

// ---------------------------------------------------------------------------
// DHCP types and functions
// ---------------------------------------------------------------------------

/// Parsed DHCP response.
pub struct DhcpOffer {
    pub your_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns_server: [u8; 4],
    pub msg_type: u8,
}

/// Build a DHCP message (DISCOVER or REQUEST) as a raw Ethernet frame.
/// Returns the frame length written to `frame_buf`.
pub fn build_dhcp_frame(
    our_mac: &[u8; 6],
    xid: u32,
    msg_type: u8,
    requested_ip: Option<[u8; 4]>,
    server_ip: Option<[u8; 4]>,
    frame_buf: &mut [u8],
) -> usize {
    // Build DHCP payload
    let mut dhcp = [0u8; 576];
    dhcp[0] = 1; // op: BOOTREQUEST
    dhcp[1] = 1; // htype: Ethernet
    dhcp[2] = 6; // hlen: MAC length
    // dhcp[3] = 0; // hops
    dhcp[4..8].copy_from_slice(&xid.to_be_bytes());
    // secs = 0, flags = 0x8000 (broadcast)
    dhcp[10] = 0x80;
    // ciaddr, yiaddr, siaddr, giaddr = 0
    // chaddr: our MAC padded to 16 bytes
    dhcp[28..34].copy_from_slice(our_mac);
    // sname (64 bytes) and file (128 bytes) are zero

    // Magic cookie at offset 236
    dhcp[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    // Options start at offset 240
    let mut opt_pos = 240;

    // Option 53: DHCP Message Type
    dhcp[opt_pos] = OPT_MESSAGE_TYPE;
    dhcp[opt_pos + 1] = 1;
    dhcp[opt_pos + 2] = msg_type;
    opt_pos += 3;

    // Option 50: Requested IP (for REQUEST)
    if let Some(ip) = requested_ip {
        dhcp[opt_pos] = OPT_REQUESTED_IP;
        dhcp[opt_pos + 1] = 4;
        dhcp[opt_pos + 2..opt_pos + 6].copy_from_slice(&ip);
        opt_pos += 6;
    }

    // Option 54: Server Identifier (for REQUEST)
    if let Some(ip) = server_ip {
        dhcp[opt_pos] = OPT_SERVER_ID;
        dhcp[opt_pos + 1] = 4;
        dhcp[opt_pos + 2..opt_pos + 6].copy_from_slice(&ip);
        opt_pos += 6;
    }

    // Option 55: Parameter Request List
    dhcp[opt_pos] = OPT_PARAM_REQUEST;
    dhcp[opt_pos + 1] = 3;
    dhcp[opt_pos + 2] = OPT_SUBNET_MASK;
    dhcp[opt_pos + 3] = OPT_ROUTER;
    dhcp[opt_pos + 4] = OPT_DNS;
    opt_pos += 5;

    // End
    dhcp[opt_pos] = OPT_END;
    opt_pos += 1;

    let dhcp_len = opt_pos;

    // Build UDP header
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    let udp_total = 8 + dhcp_len;
    udp[4..6].copy_from_slice(&(udp_total as u16).to_be_bytes());
    // UDP checksum = 0 (optional for IPv4)

    // Build IPv4 header
    let mut ip = [0u8; 20];
    ip[0] = 0x45; // version 4, IHL 5
    let ip_total = 20 + udp_total;
    ip[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
    ip[6] = 0x40; // Don't Fragment
    ip[8] = 64;   // TTL
    ip[9] = PROTO_UDP;
    // src = 0.0.0.0, dst = 255.255.255.255
    ip[16..20].copy_from_slice(&BROADCAST_IP);
    // Checksum
    let cksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    // Build Ethernet frame
    let frame_len = ETH_HDR_SIZE + ip_total;
    if frame_buf.len() < frame_len {
        return 0;
    }
    frame_buf[0..6].copy_from_slice(&BROADCAST_MAC);
    frame_buf[6..12].copy_from_slice(our_mac);
    frame_buf[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame_buf[14..34].copy_from_slice(&ip);
    frame_buf[34..42].copy_from_slice(&udp);
    frame_buf[42..42 + dhcp_len].copy_from_slice(&dhcp[..dhcp_len]);

    frame_len
}

/// Parse a received frame as a DHCP response. Returns None if not a DHCP reply
/// matching our xid/MAC.
pub fn parse_dhcp_response(frame: &[u8], our_mac: &[u8; 6], xid: u32) -> Option<DhcpOffer> {
    let (eth, payload) = parse_eth(frame)?;
    if eth.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let (_ip, ip_payload) = parse_ipv4(payload)?;
    let (udp, udp_data) = parse_udp(ip_payload)?;
    if udp.dst_port != DHCP_CLIENT_PORT {
        return None;
    }
    // DHCP minimum: 236 bytes fixed + 4 bytes magic cookie
    if udp_data.len() < 240 {
        return None;
    }
    // op must be BOOTREPLY (2)
    if udp_data[0] != 2 {
        return None;
    }
    // Check xid
    let resp_xid = u32::from_be_bytes([udp_data[4], udp_data[5], udp_data[6], udp_data[7]]);
    if resp_xid != xid {
        return None;
    }
    // Check chaddr matches our MAC
    if udp_data[28..34] != *our_mac {
        return None;
    }
    // Check magic cookie
    if udp_data[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    let your_ip = [udp_data[16], udp_data[17], udp_data[18], udp_data[19]];
    let server_ip = [udp_data[20], udp_data[21], udp_data[22], udp_data[23]];

    // Parse options
    let mut msg_type = 0u8;
    let mut subnet_mask = [255, 255, 255, 0]; // default
    let mut gateway = [0u8; 4];
    let mut dns_server = [0u8; 4];
    let mut i = 240;
    while i < udp_data.len() {
        let opt = udp_data[i];
        if opt == OPT_END {
            break;
        }
        if opt == 0 {
            // Padding
            i += 1;
            continue;
        }
        if i + 1 >= udp_data.len() {
            break;
        }
        let len = udp_data[i + 1] as usize;
        if i + 2 + len > udp_data.len() {
            break;
        }
        let data = &udp_data[i + 2..i + 2 + len];
        match opt {
            OPT_MESSAGE_TYPE if len >= 1 => msg_type = data[0],
            OPT_SUBNET_MASK if len >= 4 => subnet_mask.copy_from_slice(&data[..4]),
            OPT_ROUTER if len >= 4 => gateway.copy_from_slice(&data[..4]),
            OPT_DNS if len >= 4 => dns_server.copy_from_slice(&data[..4]),
            OPT_SERVER_ID if len >= 4 => {
                // Use server identifier from option (more reliable than siaddr)
                let _ = server_ip; // siaddr is fallback
            }
            _ => {}
        }
        i += 2 + len;
    }

    Some(DhcpOffer {
        your_ip,
        server_ip,
        subnet_mask,
        gateway,
        dns_server,
        msg_type,
    })
}

/// Run the DHCP client: DISCOVER -> OFFER -> REQUEST -> ACK.
/// Returns true if an address was acquired, false if we should use fallback.
pub fn dhcp_acquire(
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    config: &mut NetConfig,
    tx: &mut TxScratch,
    rx: &mut RxScratch,
) -> bool {
    // Generate a transaction ID from our MAC
    let xid = u32::from_be_bytes([our_mac[2], our_mac[3], our_mac[4], our_mac[5]]);

    println!("[net] DHCP: sending DISCOVER...");

    // --- Phase 1: DISCOVER -> OFFER ---
    let offer = match dhcp_transact(
        shm_base, raw_handle, our_mac, xid,
        DHCP_DISCOVER, None, None,
        DHCP_OFFER, tx, rx,
    ) {
        Some(o) => o,
        None => {
            println!("[net] DHCP: no OFFER received, using static config");
            return false;
        }
    };

    println!(
        "[net] DHCP: got OFFER {}.{}.{}.{}",
        offer.your_ip[0], offer.your_ip[1], offer.your_ip[2], offer.your_ip[3],
    );

    // --- Phase 2: REQUEST -> ACK ---
    let ack = match dhcp_transact(
        shm_base, raw_handle, our_mac, xid,
        DHCP_REQUEST, Some(offer.your_ip), Some(offer.server_ip),
        DHCP_ACK, tx, rx,
    ) {
        Some(a) => a,
        None => {
            println!("[net] DHCP: no ACK received, using static config");
            return false;
        }
    };

    // Apply configuration
    config.our_ip = ack.your_ip;
    config.subnet_mask = ack.subnet_mask;
    if ack.gateway != ZERO_IP {
        config.gateway = ack.gateway;
    } else {
        config.gateway = offer.server_ip;
    }
    if ack.dns_server != ZERO_IP {
        config.dns_server = ack.dns_server;
    } else {
        config.dns_server = config.gateway; // fallback: gateway is often the DNS server
    }

    println!(
        "[net] DHCP: acquired {}.{}.{}.{}/{}.{}.{}.{} gw {}.{}.{}.{} dns {}.{}.{}.{}",
        config.our_ip[0], config.our_ip[1], config.our_ip[2], config.our_ip[3],
        config.subnet_mask[0], config.subnet_mask[1], config.subnet_mask[2], config.subnet_mask[3],
        config.gateway[0], config.gateway[1], config.gateway[2], config.gateway[3],
        config.dns_server[0], config.dns_server[1], config.dns_server[2], config.dns_server[3],
    );

    true
}

/// Send a DHCP message and wait for a response of the expected type.
/// Retries with exponential backoff. Returns None on timeout.
#[allow(clippy::too_many_arguments)]
fn dhcp_transact(
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    xid: u32,
    send_type: u8,
    requested_ip: Option<[u8; 4]>,
    server_ip: Option<[u8; 4]>,
    expect_type: u8,
    tx: &mut TxScratch,
    rx: &mut RxScratch,
) -> Option<DhcpOffer> {
    let mut timeout_ticks = 2 * TICK_HZ; // 2 seconds initial
    const MAX_RETRIES: usize = 4;

    for attempt in 0..MAX_RETRIES {
        // Send DHCP message
        let frame_len = build_dhcp_frame(
            our_mac, xid, send_type, requested_ip, server_ip,
            &mut tx.frame_buf,
        );
        if frame_len > 0 {
            tx_frame(shm_base, raw_handle, &tx.frame_buf[..frame_len], &mut tx.msg);
        }

        // Wait for response
        let deadline = now_ticks() + timeout_ticks;
        loop {
            let now = now_ticks();
            if now >= deadline {
                break;
            }

            // Poll RX ring
            let rx_head = shm_read_u32(shm_base, CTRL_RX_HEAD);
            let rx_tail = shm_read_u32(shm_base, CTRL_RX_TAIL);
            if rx_head == rx_tail {
                // No packets -- yield and retry
                std::thread::yield_now();
                continue;
            }

            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let slot_idx = (rx_tail % RX_SLOTS as u32) as usize;
            let slot_offset = RX_RING_OFFSET + slot_idx * RX_SLOT_SIZE;
            let frame_len = shm_read_u16(shm_base, slot_offset) as usize;
            if frame_len > RX_SLOT_SIZE - 2 {
                // Bogus length from device -- skip frame
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                shm_write_u32(shm_base, CTRL_RX_TAIL, rx_tail.wrapping_add(1));
                continue;
            }
            let copy_len = frame_len.min(rx.rx_buf.len());
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (shm_base + slot_offset + 2) as *const u8,
                    rx.rx_buf.as_mut_ptr(),
                    copy_len,
                );
            }
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            shm_write_u32(shm_base, CTRL_RX_TAIL, rx_tail.wrapping_add(1));

            // Tell kernel we consumed the frame
            rx.doorbell = rvos::Message::new();
            rx.doorbell.len = rvos_wire::to_bytes(
                &NetRawRequest::RxConsumed {},
                &mut rx.doorbell.data,
            ).expect("serialize");
            let _ = raw::sys_chan_send(raw_handle, &rx.doorbell);

            // Try to parse as DHCP response
            if let Some(offer) = parse_dhcp_response(&rx.rx_buf[..copy_len], our_mac, xid) {
                if offer.msg_type == expect_type {
                    return Some(offer);
                }
            }
            // Not a DHCP response -- discard and keep polling
        }

        if attempt + 1 < MAX_RETRIES {
            println!("[net] DHCP: retry {} (timeout {}s)...", attempt + 1, timeout_ticks / TICK_HZ);
        }
        timeout_ticks = (timeout_ticks * 2).min(8 * TICK_HZ);
    }

    None
}

/// Compute IPv4 header checksum.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
