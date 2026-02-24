// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::net::{NetRawRequest, NetRawResponse};
use rvos_proto::socket::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CONTROL_HANDLE: usize = 1;

const CTRL_RX_HEAD: usize = 0x00;
const CTRL_RX_TAIL: usize = 0x04;
const CTRL_TX_HEAD: usize = 0x08;
const CTRL_TX_TAIL: usize = 0x0C;
const RX_RING_OFFSET: usize = 0x0040;
const TX_RING_OFFSET: usize = 0x3040;
const RX_SLOT_SIZE: usize = 1536;
const TX_SLOT_SIZE: usize = 1536;
const RX_SLOTS: usize = 8;
const TX_SLOTS: usize = 4;
const SHM_PAGE_COUNT: usize = 5;

const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const BROADCAST_IP: [u8; 4] = [255, 255, 255, 255];
const ZERO_IP: [u8; 4] = [0, 0, 0, 0];

/// Fallback static configuration (used when DHCP times out).
const FALLBACK_IP: [u8; 4] = [10, 0, 2, 15];
const FALLBACK_GATEWAY: [u8; 4] = [10, 0, 2, 2];
const FALLBACK_MASK: [u8; 4] = [255, 255, 255, 0];

/// Runtime network configuration, populated by DHCP or fallback.
struct NetConfig {
    our_ip: [u8; 4],
    gateway: [u8; 4],
    subnet_mask: [u8; 4],
    dns_server: [u8; 4],
}

impl NetConfig {
    fn new_unconfigured() -> Self {
        NetConfig {
            our_ip: ZERO_IP,
            gateway: ZERO_IP,
            subnet_mask: ZERO_IP,
            dns_server: ZERO_IP,
        }
    }

    fn apply_fallback(&mut self) {
        self.our_ip = FALLBACK_IP;
        self.gateway = FALLBACK_GATEWAY;
        self.subnet_mask = FALLBACK_MASK;
        self.dns_server = FALLBACK_GATEWAY; // gateway is also the DNS server
    }

    /// Resolve next-hop IP for a destination. Broadcast destinations
    /// are returned as-is (caller must use BROADCAST_MAC).
    fn resolve_next_hop(&self, dst_ip: &[u8; 4]) -> [u8; 4] {
        if *dst_ip == BROADCAST_IP {
            return BROADCAST_IP;
        }
        // Subnet-directed broadcast (e.g. 10.0.2.255 for /24)
        let is_subnet_bcast = dst_ip.iter().zip(&self.subnet_mask).all(|(&d, &m)| d & !m == !m);
        if is_subnet_bcast {
            return *dst_ip;
        }
        // Off-subnet → gateway
        let off_subnet = dst_ip.iter().zip(&self.our_ip).zip(&self.subnet_mask)
            .any(|((&d, &o), &m)| (d & m) != (o & m));
        if off_subnet {
            return self.gateway;
        }
        *dst_ip
    }

    /// Check if an IP is a broadcast address.
    fn is_broadcast(&self, ip: &[u8; 4]) -> bool {
        if *ip == BROADCAST_IP {
            return true;
        }
        // Subnet-directed broadcast
        ip.iter().zip(&self.subnet_mask).all(|(&b, &m)| b & !m == !m)
    }
}

const ETH_HDR_SIZE: usize = 14;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;

const ARP_HLEN: usize = 28;

const IPV4_HDR_SIZE: usize = 20;
const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;

const UDP_HDR_SIZE: usize = 8;
const TCP_HDR_SIZE: usize = 20;
const TCP_MSS: u16 = 1460;
const TCP_WINDOW: u16 = 4096;
const MAX_TCP_CONNS: usize = 16;
const TCP_INITIAL_RTO: u64 = TICK_HZ; // 1 second
const TCP_MAX_RETX: u8 = 8;
const TCP_ACCEPT_BACKLOG: usize = 4;

// TCP flags
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

const MAX_SOCKETS: usize = 16;
const MAX_PENDING: usize = 4;
const MAX_PENDING_CLIENTS: usize = 4;

/// Heap-allocated scratch buffers for packet TX, avoiding large stack frames.
struct TxScratch {
    frame_buf: [u8; 1534],
    ip_buf: [u8; 1534],
    tcp_buf: [u8; 1500],
    /// Reusable Message buffer for building responses (avoids 1080-byte stack allocs).
    msg: Message,
}

/// Heap-allocated buffers for receiving in the main event loop.
struct RxScratch {
    rx_buf: [u8; 1534],
    doorbell: Message,
    ctrl_msg: Message,
    client_msg: Message,
}

// ---------------------------------------------------------------------------
// Volatile SHM access
// ---------------------------------------------------------------------------

fn shm_read_u32(base: usize, offset: usize) -> u32 {
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn shm_write_u32(base: usize, offset: usize, val: u32) {
    unsafe { ((base + offset) as *mut u32).write_volatile(val) }
}

fn shm_read_u16(base: usize, offset: usize) -> u16 {
    unsafe { ((base + offset) as *const u16).read_volatile() }
}

fn shm_write_u16(base: usize, offset: usize, val: u16) {
    unsafe { ((base + offset) as *mut u16).write_volatile(val) }
}

// ---------------------------------------------------------------------------
// Ethernet
// ---------------------------------------------------------------------------

struct EthHdr {
    #[allow(dead_code)] // protocol header field; useful for future broadcast/multicast checks
    dst: [u8; 6],
    src: [u8; 6],
    ethertype: u16,
}

fn parse_eth(frame: &[u8]) -> Option<(EthHdr, &[u8])> {
    if frame.len() < ETH_HDR_SIZE {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some((EthHdr { dst, src, ethertype }, &frame[ETH_HDR_SIZE..]))
}

fn build_eth(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8], buf: &mut [u8]) -> usize {
    let total = ETH_HDR_SIZE + payload.len();
    if total > buf.len() {
        return 0;
    }
    buf[0..6].copy_from_slice(dst);
    buf[6..12].copy_from_slice(src);
    let et = ethertype.to_be_bytes();
    buf[12] = et[0];
    buf[13] = et[1];
    buf[ETH_HDR_SIZE..ETH_HDR_SIZE + payload.len()].copy_from_slice(payload);
    total
}

// ---------------------------------------------------------------------------
// ARP
// ---------------------------------------------------------------------------

const TICK_HZ: u64 = 10_000_000; // QEMU virt aclint-mtimer @ 10MHz
const ARP_ENTRY_TTL: u64 = 60 * TICK_HZ; // 60 seconds
const PENDING_TIMEOUT: u64 = 3 * TICK_HZ; // 3 seconds
const ARP_RETRY_INTERVAL: u64 = TICK_HZ; // 1 second between retries

fn now_ticks() -> u64 {
    raw::sys_clock().0
}

struct ArpEntry {
    ip: [u8; 4],
    mac: [u8; 6],
    valid: bool,
    timestamp: u64,
}

struct ArpTable {
    entries: [ArpEntry; 8],
}

impl ArpTable {
    fn new() -> Self {
        ArpTable {
            entries: [const {
                ArpEntry {
                    ip: [0; 4],
                    mac: [0; 6],
                    valid: false,
                    timestamp: 0,
                }
            }; 8],
        }
    }

    fn lookup(&self, ip: &[u8; 4], now: u64) -> Option<[u8; 6]> {
        for e in &self.entries {
            if e.valid && e.ip == *ip && now.wrapping_sub(e.timestamp) < ARP_ENTRY_TTL {
                return Some(e.mac);
            }
        }
        None
    }

    fn insert(&mut self, ip: [u8; 4], mac: [u8; 6], now: u64) {
        // Update existing entry
        for e in &mut self.entries {
            if e.valid && e.ip == ip {
                e.mac = mac;
                e.timestamp = now;
                return;
            }
        }
        // Find empty slot
        for e in &mut self.entries {
            if !e.valid {
                e.ip = ip;
                e.mac = mac;
                e.valid = true;
                e.timestamp = now;
                return;
            }
        }
        // Evict oldest entry
        let mut oldest_idx = 0;
        let mut oldest_age = 0u64;
        for (i, e) in self.entries.iter().enumerate() {
            let age = now.wrapping_sub(e.timestamp);
            if age > oldest_age {
                oldest_age = age;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx].ip = ip;
        self.entries[oldest_idx].mac = mac;
        self.entries[oldest_idx].valid = true;
        self.entries[oldest_idx].timestamp = now;
    }

    /// Remove entries older than ARP_ENTRY_TTL.
    fn expire(&mut self, now: u64) {
        for e in &mut self.entries {
            if e.valid && now.wrapping_sub(e.timestamp) >= ARP_ENTRY_TTL {
                e.valid = false;
            }
        }
    }
}

/// Handle an incoming ARP packet: update ARP table, optionally build a reply frame.
/// Returns the total frame length (including Ethernet header) if a reply should be sent.
fn handle_arp(
    arp_table: &mut ArpTable,
    our_mac: &[u8; 6],
    our_ip: &[u8; 4],
    payload: &[u8],
    reply_buf: &mut [u8],
    now: u64,
) -> Option<usize> {
    if payload.len() < ARP_HLEN {
        return None;
    }
    // Validate hardware type (Ethernet) and protocol type (IPv4)
    let hw_type = u16::from_be_bytes([payload[0], payload[1]]);
    let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
    if hw_type != 0x0001 || proto_type != 0x0800 {
        return None;
    }
    let hw_len = payload[4];
    let proto_len = payload[5];
    if hw_len != 6 || proto_len != 4 {
        return None;
    }

    let operation = u16::from_be_bytes([payload[6], payload[7]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&payload[8..14]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&payload[14..18]);
    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&payload[24..28]);

    // Always learn the sender
    arp_table.insert(sender_ip, sender_mac, now);

    // If this is a request targeting our IP, send a reply
    if operation == 1 && target_ip == *our_ip {
        // Build ARP reply payload
        let mut arp_payload = [0u8; ARP_HLEN];
        // Hardware type: Ethernet
        arp_payload[0] = 0x00;
        arp_payload[1] = 0x01;
        // Protocol type: IPv4
        arp_payload[2] = 0x08;
        arp_payload[3] = 0x00;
        // Hardware addr len
        arp_payload[4] = 6;
        // Protocol addr len
        arp_payload[5] = 4;
        // Operation: reply
        arp_payload[6] = 0x00;
        arp_payload[7] = 0x02;
        // Sender MAC (ours)
        arp_payload[8..14].copy_from_slice(our_mac);
        // Sender IP (ours)
        arp_payload[14..18].copy_from_slice(our_ip);
        // Target MAC
        arp_payload[18..24].copy_from_slice(&sender_mac);
        // Target IP
        arp_payload[24..28].copy_from_slice(&sender_ip);

        let frame_len = build_eth(&sender_mac, our_mac, ETHERTYPE_ARP, &arp_payload, reply_buf);
        if frame_len > 0 {
            return Some(frame_len);
        }
    }

    None
}

fn send_arp_request(our_mac: &[u8; 6], our_ip: &[u8; 4], target_ip: &[u8; 4], buf: &mut [u8]) -> usize {
    let mut arp_payload = [0u8; ARP_HLEN];
    // Hardware type: Ethernet
    arp_payload[0] = 0x00;
    arp_payload[1] = 0x01;
    // Protocol type: IPv4
    arp_payload[2] = 0x08;
    arp_payload[3] = 0x00;
    // Hardware addr len
    arp_payload[4] = 6;
    // Protocol addr len
    arp_payload[5] = 4;
    // Operation: request
    arp_payload[6] = 0x00;
    arp_payload[7] = 0x01;
    // Sender MAC (ours)
    arp_payload[8..14].copy_from_slice(our_mac);
    // Sender IP (ours)
    arp_payload[14..18].copy_from_slice(our_ip);
    // Target MAC: zeroed (unknown)
    // arp_payload[18..24] already zero
    // Target IP
    arp_payload[24..28].copy_from_slice(target_ip);

    build_eth(&BROADCAST_MAC, our_mac, ETHERTYPE_ARP, &arp_payload, buf)
}

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

struct IpHdr {
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    #[allow(dead_code)] // protocol header field; kept for completeness
    total_len: u16,
}

fn parse_ipv4(packet: &[u8]) -> Option<(IpHdr, &[u8])> {
    if packet.len() < IPV4_HDR_SIZE {
        return None;
    }
    let ver_ihl = packet[0];
    let version = ver_ihl >> 4;
    let ihl = (ver_ihl & 0x0F) as usize;
    if version != 4 || ihl < 5 {
        return None;
    }
    let hdr_len = ihl * 4;
    if packet.len() < hdr_len {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    if (total_len as usize) > packet.len() || (total_len as usize) < hdr_len {
        return None;
    }
    let proto = packet[9];
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    dst.copy_from_slice(&packet[16..20]);
    let payload = &packet[hdr_len..total_len as usize];
    Some((IpHdr { src, dst, proto, total_len }, payload))
}

fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ipv4(src: &[u8; 4], dst: &[u8; 4], proto: u8, payload: &[u8], buf: &mut [u8]) -> usize {
    let total_len = IPV4_HDR_SIZE + payload.len();
    if total_len > buf.len() || total_len > 0xFFFF {
        return 0;
    }
    // Version + IHL
    buf[0] = 0x45;
    // DSCP/ECN
    buf[1] = 0;
    // Total length
    let tl = (total_len as u16).to_be_bytes();
    buf[2] = tl[0];
    buf[3] = tl[1];
    // Identification
    buf[4] = 0;
    buf[5] = 0;
    // Flags (DF) + Fragment offset
    buf[6] = 0x40;
    buf[7] = 0x00;
    // TTL
    buf[8] = 64;
    // Protocol
    buf[9] = proto;
    // Checksum placeholder
    buf[10] = 0;
    buf[11] = 0;
    // Source IP
    buf[12..16].copy_from_slice(src);
    // Dest IP
    buf[16..20].copy_from_slice(dst);
    // Compute checksum
    let cksum = ip_checksum(&buf[..IPV4_HDR_SIZE]);
    let ck = cksum.to_be_bytes();
    buf[10] = ck[0];
    buf[11] = ck[1];
    // Payload
    buf[IPV4_HDR_SIZE..total_len].copy_from_slice(payload);
    total_len
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    #[allow(dead_code)] // protocol header field; kept for completeness
    len: u16,
}

/// Verify the UDP checksum over the pseudo-header + UDP segment.
/// Returns true if the checksum is correct or zero (not computed, valid in IPv4).
fn udp_checksum_ok(src_ip: &[u8; 4], dst_ip: &[u8; 4], udp_segment: &[u8]) -> bool {
    let cksum_field = u16::from_be_bytes([udp_segment[6], udp_segment[7]]);
    if cksum_field == 0 {
        return true; // RFC 768: zero means no checksum computed
    }
    // Build pseudo-header and sum it together with the UDP segment.
    let udp_len = udp_segment.len() as u16;
    let mut sum: u32 = 0;
    // Pseudo-header: src IP (4), dst IP (4), zero (1), protocol (1), UDP length (2)
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += PROTO_UDP as u32; // 0x00 || protocol
    sum += udp_len as u32;
    // Sum UDP segment (header + data)
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum == 0xFFFF
}

fn parse_udp(packet: &[u8]) -> Option<(UdpHdr, &[u8])> {
    if packet.len() < UDP_HDR_SIZE {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
    let len = u16::from_be_bytes([packet[4], packet[5]]);
    if (len as usize) < UDP_HDR_SIZE || (len as usize) > packet.len() {
        return None;
    }
    let data = &packet[UDP_HDR_SIZE..len as usize];
    Some((UdpHdr { src_port, dst_port, len }, data))
}

fn build_udp(
    src_ip: &[u8; 4], dst_ip: &[u8; 4],
    src_port: u16, dst_port: u16,
    payload: &[u8], buf: &mut [u8],
) -> usize {
    let total_len = UDP_HDR_SIZE + payload.len();
    if total_len > buf.len() || total_len > 0xFFFF {
        return 0;
    }
    let sp = src_port.to_be_bytes();
    buf[0] = sp[0];
    buf[1] = sp[1];
    let dp = dst_port.to_be_bytes();
    buf[2] = dp[0];
    buf[3] = dp[1];
    let l = (total_len as u16).to_be_bytes();
    buf[4] = l[0];
    buf[5] = l[1];
    // Checksum field = 0 during computation
    buf[6] = 0;
    buf[7] = 0;
    buf[UDP_HDR_SIZE..total_len].copy_from_slice(payload);
    // Compute UDP checksum over pseudo-header + segment
    let udp_len = total_len as u16;
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += PROTO_UDP as u32;
    sum += udp_len as u32;
    let mut i = 0;
    while i + 1 < total_len {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < total_len {
        sum += (buf[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    // RFC 768: if computed checksum is 0, transmit as 0xFFFF
    let cksum = if cksum == 0 { 0xFFFF } else { cksum };
    let cb = cksum.to_be_bytes();
    buf[6] = cb[0];
    buf[7] = cb[1];
    total_len
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)] // all states are part of the TCP FSM even if not all are constructed yet
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
}

fn parse_tcp(packet: &[u8]) -> Option<(TcpHdr, &[u8])> {
    if packet.len() < TCP_HDR_SIZE {
        return None;
    }
    let src_port = u16::from_be_bytes([packet[0], packet[1]]);
    let dst_port = u16::from_be_bytes([packet[2], packet[3]]);
    let seq = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let ack = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let data_offset = (packet[12] >> 4) as usize;
    let hdr_len = data_offset * 4;
    if hdr_len < TCP_HDR_SIZE || hdr_len > packet.len() {
        return None;
    }
    let flags = packet[13];
    let window = u16::from_be_bytes([packet[14], packet[15]]);
    let data = &packet[hdr_len..];
    Some((TcpHdr { src_port, dst_port, seq, ack, flags, window }, data))
}

/// Compute TCP checksum over pseudo-header + TCP segment.
fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    let tcp_len = tcp_segment.len() as u16;
    let mut sum: u32 = 0;
    // Pseudo-header
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += PROTO_TCP as u32;
    sum += tcp_len as u32;
    // Sum TCP segment
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 { 0xFFFF } else { cksum }
}

/// Verify TCP checksum. Returns true if valid.
fn tcp_checksum_ok(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> bool {
    let tcp_len = tcp_segment.len() as u16;
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += PROTO_TCP as u32;
    sum += tcp_len as u32;
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum == 0xFFFF
}

#[allow(clippy::too_many_arguments)]
fn build_tcp(
    src_ip: &[u8; 4], dst_ip: &[u8; 4],
    src_port: u16, dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16,
    payload: &[u8], buf: &mut [u8],
) -> usize {
    let total_len = TCP_HDR_SIZE + payload.len();
    if total_len > buf.len() || total_len > 0xFFFF {
        return 0;
    }
    // Source port
    let sp = src_port.to_be_bytes();
    buf[0] = sp[0]; buf[1] = sp[1];
    // Dest port
    let dp = dst_port.to_be_bytes();
    buf[2] = dp[0]; buf[3] = dp[1];
    // Sequence number
    let sq = seq.to_be_bytes();
    buf[4] = sq[0]; buf[5] = sq[1]; buf[6] = sq[2]; buf[7] = sq[3];
    // Ack number
    let ak = ack.to_be_bytes();
    buf[8] = ak[0]; buf[9] = ak[1]; buf[10] = ak[2]; buf[11] = ak[3];
    // Data offset (5 words = 20 bytes) + reserved
    buf[12] = 0x50;
    // Flags
    buf[13] = flags;
    // Window
    let wn = window.to_be_bytes();
    buf[14] = wn[0]; buf[15] = wn[1];
    // Checksum placeholder
    buf[16] = 0; buf[17] = 0;
    // Urgent pointer
    buf[18] = 0; buf[19] = 0;
    // Payload
    if !payload.is_empty() {
        buf[TCP_HDR_SIZE..total_len].copy_from_slice(payload);
    }
    // Compute checksum
    let cksum = tcp_checksum(src_ip, dst_ip, &buf[..total_len]);
    let cb = cksum.to_be_bytes();
    buf[16] = cb[0]; buf[17] = cb[1];
    total_len
}

struct TcpConn {
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    state: TcpState,
    // Send state
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u16,
    // Receive state
    rcv_nxt: u32,
    // Buffers
    recv_buf: [u8; 4096],
    recv_len: usize,
    send_buf: [u8; 4096],
    send_len: usize,
    // Retransmission
    rto_ticks: u64,
    retx_count: u8,
    retx_deadline: u64, // 0 = no pending retransmit
    // Owning socket index
    socket_idx: usize,
    // For listening: index of the listener socket that spawned this conn
    listener_sock_idx: usize,
    active: bool,
    // TimeWait deadline
    time_wait_deadline: u64,
}

impl TcpConn {
    const fn new() -> Self {
        TcpConn {
            local_port: 0,
            remote_addr: [0; 4],
            remote_port: 0,
            state: TcpState::Closed,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            rcv_nxt: 0,
            recv_buf: [0; 4096],
            recv_len: 0,
            send_buf: [0; 4096],
            send_len: 0,
            rto_ticks: 0,
            retx_count: 0,
            retx_deadline: 0,
            socket_idx: usize::MAX,
            listener_sock_idx: usize::MAX,
            active: false,
            time_wait_deadline: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Initial sequence number from clock.
fn tcp_initial_seq() -> u32 {
    (now_ticks() & 0xFFFF_FFFF) as u32
}

type TcpConns = [TcpConn; MAX_TCP_CONNS];

/// Find a TCP connection matching a 4-tuple.
fn tcp_find_conn(conns: &TcpConns, local_port: u16, remote_addr: &[u8; 4], remote_port: u16) -> Option<usize> {
    for (i, c) in conns.iter().enumerate() {
        if c.active && c.local_port == local_port
            && c.remote_addr == *remote_addr
            && c.remote_port == remote_port
        {
            return Some(i);
        }
    }
    None
}

/// Allocate a free TCP connection slot.
fn tcp_alloc_conn(conns: &TcpConns) -> Option<usize> {
    conns.iter().position(|c| !c.active)
}

// ---------------------------------------------------------------------------
// Socket table
// ---------------------------------------------------------------------------

struct Socket {
    port: u16,
    handle: usize,
    recv_pending: bool,
    active: bool,
    is_stream: bool,
    // TCP-specific
    tcp_conn_idx: usize,        // index into tcp_conns (usize::MAX = none)
    tcp_listening: bool,
    accept_queue: [usize; TCP_ACCEPT_BACKLOG], // conn indices waiting to be accepted
    accept_count: usize,
    accept_pending: bool,       // client has called Accept, waiting for connection
    recv_max_len: u32,          // for TCP Recv: max bytes to return
}

impl Socket {
    const fn new() -> Self {
        Socket {
            port: 0,
            handle: 0,
            recv_pending: false,
            active: false,
            is_stream: false,
            tcp_conn_idx: usize::MAX,
            tcp_listening: false,
            accept_queue: [usize::MAX; TCP_ACCEPT_BACKLOG],
            accept_count: 0,
            accept_pending: false,
            recv_max_len: 0,
        }
    }

    /// Clean up a socket whose client channel is dead.
    fn deactivate(&mut self, tcp_conns: &mut TcpConns) {
        if self.active {
            raw::sys_chan_close(self.handle);
            // Clean up associated TCP connection
            if self.tcp_conn_idx != usize::MAX {
                tcp_conns[self.tcp_conn_idx].reset();
            }
            // Clean up accept queue connections
            for i in 0..self.accept_count {
                let ci = self.accept_queue[i];
                if ci != usize::MAX {
                    tcp_conns[ci].reset();
                }
            }
            *self = Self::new();
        }
    }
}

/// A pending client that has connected to the sockets control channel
/// but hasn't yet sent a SocketsRequest::Socket message.
struct PendingClient {
    handle: usize,
    active: bool,
}

impl PendingClient {
    const fn new() -> Self {
        PendingClient { handle: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// Pending ARP queue
// ---------------------------------------------------------------------------

struct PendingPacket {
    dst_ip: [u8; 4],
    data: Vec<u8>,
    active: bool,
    timestamp: u64,
    last_arp: u64,
}

impl PendingPacket {
    fn new() -> Self {
        PendingPacket {
            dst_ip: [0; 4],
            data: Vec::new(),
            active: false,
            timestamp: 0,
            last_arp: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TX via SHM ring buffer
// ---------------------------------------------------------------------------

fn tx_frame(shm_base: usize, raw_handle: usize, frame: &[u8], msg: &mut Message) {
    let tx_head = shm_read_u32(shm_base, CTRL_TX_HEAD);
    let tx_tail = shm_read_u32(shm_base, CTRL_TX_TAIL);
    if tx_head.wrapping_sub(tx_tail) >= TX_SLOTS as u32 {
        return; // TX ring full
    }
    let slot_idx = (tx_head % TX_SLOTS as u32) as usize;
    let slot_offset = TX_RING_OFFSET + slot_idx * TX_SLOT_SIZE;
    let copy_len = frame.len().min(TX_SLOT_SIZE - 2);
    shm_write_u16(shm_base, slot_offset, copy_len as u16);
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            (shm_base + slot_offset + 2) as *mut u8,
            copy_len,
        );
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    shm_write_u32(shm_base, CTRL_TX_HEAD, tx_head.wrapping_add(1));

    // Send TxReady doorbell (fire-and-forget: kernel polls regardless)
    *msg = Message::new();
    msg.len = rvos_wire::to_bytes(&NetRawRequest::TxReady {}, &mut msg.data).expect("serialize");
    let _ = raw::sys_chan_send(raw_handle, msg); // fire-and-forget doorbell
}

// ---------------------------------------------------------------------------
// Send a fully built IP packet: resolve MAC, wrap in Ethernet, TX
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn send_ip_packet(
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    config: &NetConfig,
    arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING],
    ip_packet: &[u8],
    dst_ip: &[u8; 4],
    now: u64,
    frame_buf: &mut [u8; 1534],
    msg: &mut Message,
) {
    let next_hop = config.resolve_next_hop(dst_ip);

    // Broadcast destinations use broadcast MAC directly (no ARP)
    if config.is_broadcast(&next_hop) {
        let frame_len = build_eth(&BROADCAST_MAC, our_mac, ETHERTYPE_IPV4, ip_packet, frame_buf);
        if frame_len > 0 {
            tx_frame(shm_base, raw_handle, &frame_buf[..frame_len], msg);
        }
        return;
    }

    if let Some(dst_mac) = arp_table.lookup(&next_hop, now) {
        // Have MAC -- send immediately
        let frame_len = build_eth(&dst_mac, our_mac, ETHERTYPE_IPV4, ip_packet, frame_buf);
        if frame_len > 0 {
            tx_frame(shm_base, raw_handle, &frame_buf[..frame_len], msg);
        }
    } else {
        // Queue packet and send ARP request
        let mut queued = false;
        for p in pending.iter_mut() {
            if !p.active {
                p.data = ip_packet.to_vec();
                p.dst_ip = *dst_ip;
                p.active = true;
                p.timestamp = now;
                p.last_arp = 0; // trigger immediate ARP in main loop
                queued = true;
                break;
            }
        }
        if !queued {
            println!("[net-stack] pending ARP queue full, dropping packet");
        }

        let mut arp_buf = [0u8; 64];
        let arp_len = send_arp_request(our_mac, &config.our_ip, &next_hop, &mut arp_buf);
        if arp_len > 0 {
            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len], msg);
        }
    }
}

// ---------------------------------------------------------------------------
// Drain pending ARP queue: try to send queued packets whose MAC is now known
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn drain_pending(
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    config: &NetConfig,
    arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING],
    now: u64,
    frame_buf: &mut [u8; 1534],
    msg: &mut Message,
) {
    for p in pending.iter_mut() {
        if !p.active {
            continue;
        }
        // Expire timed-out entries
        if now.wrapping_sub(p.timestamp) >= PENDING_TIMEOUT {
            println!("[net-stack] ARP timeout for {}.{}.{}.{}, dropping packet",
                p.dst_ip[0], p.dst_ip[1], p.dst_ip[2], p.dst_ip[3]);
            p.active = false;
            continue;
        }
        let next_hop = config.resolve_next_hop(&p.dst_ip);
        if let Some(dst_mac) = arp_table.lookup(&next_hop, now) {
            let frame_len = build_eth(&dst_mac, our_mac, ETHERTYPE_IPV4, &p.data, frame_buf);
            if frame_len > 0 {
                tx_frame(shm_base, raw_handle, &frame_buf[..frame_len], msg);
            }
            p.active = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Process a received Ethernet frame
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn process_frame(
    frame: &[u8],
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    config: &NetConfig,
    arp_table: &mut ArpTable,
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    pending: &mut [PendingPacket; MAX_PENDING],
    now: u64,
    tx: &mut TxScratch,
) {
    let (eth, payload) = match parse_eth(frame) {
        Some(e) => e,
        None => return,
    };

    match eth.ethertype {
        ETHERTYPE_ARP => {
            let mut reply_buf = [0u8; 64];
            if let Some(reply_len) = handle_arp(arp_table, our_mac, &config.our_ip, payload, &mut reply_buf, now) {
                tx_frame(shm_base, raw_handle, &reply_buf[..reply_len], &mut tx.msg);
            }
            // After learning new MACs, try to drain pending queue
            drain_pending(shm_base, raw_handle, our_mac, config, arp_table, pending, now, &mut tx.frame_buf, &mut tx.msg);
        }
        ETHERTYPE_IPV4 => {
            let (ip, ip_payload) = match parse_ipv4(payload) {
                Some(i) => i,
                None => return,
            };
            // Accept packets addressed to us, or broadcast
            if ip.dst != config.our_ip && !config.is_broadcast(&ip.dst) && ip.dst != ZERO_IP {
                return;
            }
            // Learn sender MAC for future replies
            arp_table.insert(ip.src, eth.src, now);

            if ip.proto == PROTO_UDP {
                let (udp, udp_data) = match parse_udp(ip_payload) {
                    Some(u) => u,
                    None => return,
                };
                if !udp_checksum_ok(&ip.src, &ip.dst, ip_payload) {
                    println!("net-stack: dropped UDP packet from {}.{}.{}.{}:{} (bad checksum)",
                        ip.src[0], ip.src[1], ip.src[2], ip.src[3], udp.src_port);
                    return;
                }
                // Find socket bound to this destination port
                for sock in sockets.iter_mut() {
                    if sock.active && sock.port == udp.dst_port {
                        if sock.recv_pending {
                            // Send SocketData::Datagram to client
                            tx.msg = Message::new();
                            let truncated_len = udp_data.len().min(900);
                            let addr = SocketAddr::Inet4 {
                                a: ip.src[0], b: ip.src[1],
                                c: ip.src[2], d: ip.src[3],
                                port: udp.src_port,
                            };
                            tx.msg.len = rvos_wire::to_bytes(
                                &SocketData::Datagram {
                                    addr,
                                    data: &udp_data[..truncated_len],
                                },
                                &mut tx.msg.data,
                            ).expect("serialize");
                            let ret = raw::sys_chan_send(sock.handle, &tx.msg);
                            sock.recv_pending = false;
                            if ret == raw::CHAN_CLOSED {
                                // Client channel closed — clean up socket
                                sock.deactivate(tcp_conns);
                            }
                        }
                        // Only deliver to the first matching socket
                        break;
                    }
                }
            } else if ip.proto == PROTO_TCP {
                if !tcp_checksum_ok(&ip.src, &ip.dst, ip_payload) {
                    return;
                }
                let (tcp, tcp_data) = match parse_tcp(ip_payload) {
                    Some(t) => t,
                    None => return,
                };
                tcp_input(
                    &ip.src, &ip.dst,
                    &tcp, tcp_data,
                    sockets, tcp_conns, pending_accept,
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
        }
        _ => {} // Ignore other ethertypes
    }
}

// ---------------------------------------------------------------------------
// TCP input processing
// ---------------------------------------------------------------------------

/// Send a TCP segment (helper wrapping build_tcp + build_ipv4 + send_ip_packet).
#[allow(clippy::too_many_arguments)]
fn tcp_send_segment(
    src_port: u16, dst_addr: &[u8; 4], dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16,
    payload: &[u8],
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    tx: &mut TxScratch,
) {
    let tcp_len = build_tcp(
        &config.our_ip, dst_addr, src_port, dst_port,
        seq, ack, flags, window, payload, &mut tx.tcp_buf,
    );
    if tcp_len == 0 { return; }
    let ip_len = build_ipv4(&config.our_ip, dst_addr, PROTO_TCP, &tx.tcp_buf[..tcp_len], &mut tx.ip_buf);
    if ip_len == 0 { return; }
    send_ip_packet(shm_base, raw_handle, our_mac, config, arp_table, pending, &tx.ip_buf[..ip_len], dst_addr, now, &mut tx.frame_buf, &mut tx.msg);
}

/// Send a RST in response to an unexpected segment.
#[allow(clippy::too_many_arguments)]
fn tcp_send_rst(
    src_ip: &[u8; 4], tcp: &TcpHdr,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    tx: &mut TxScratch,
) {
    let (seq, ack, flags) = if tcp.flags & TCP_ACK != 0 {
        (tcp.ack, 0, TCP_RST)
    } else {
        (0, tcp.seq.wrapping_add(1), TCP_RST | TCP_ACK)
    };
    tcp_send_segment(
        tcp.dst_port, src_ip, tcp.src_port,
        seq, ack, flags, 0, &[],
        shm_base, raw_handle, our_mac, config, arp_table, pending, now,
        tx,
    );
}

/// Deliver buffered data to a client waiting on Recv.
fn tcp_try_deliver_recv(sock: &mut Socket, tcp_conns: &mut TcpConns, msg: &mut Message) {
    if !sock.recv_pending || sock.tcp_conn_idx == usize::MAX {
        return;
    }
    let conn = &mut tcp_conns[sock.tcp_conn_idx];
    if conn.recv_len == 0 {
        // If connection is in CloseWait/LastAck (remote sent FIN) and buffer is empty,
        // deliver zero-length read to signal EOF
        if conn.state == TcpState::CloseWait || conn.state == TcpState::LastAck
            || conn.state == TcpState::Closed
        {
            *msg = Message::new();
            msg.len = rvos_wire::to_bytes(
                &SocketData::Data { data: &[] },
                &mut msg.data,
            ).expect("serialize");
            let ret = raw::sys_chan_send(sock.handle, msg);
            sock.recv_pending = false;
            if ret == raw::CHAN_CLOSED {
                sock.deactivate(tcp_conns);
            }
        }
        return;
    }
    let deliver_len = (conn.recv_len).min(sock.recv_max_len as usize);
    *msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &SocketData::Data { data: &conn.recv_buf[..deliver_len] },
        &mut msg.data,
    ).expect("serialize");
    let ret = raw::sys_chan_send(sock.handle, msg);
    sock.recv_pending = false;
    if ret == raw::CHAN_CLOSED {
        sock.deactivate(tcp_conns);
        return;
    }
    // Remove delivered data from buffer
    if deliver_len < conn.recv_len {
        conn.recv_buf.copy_within(deliver_len..conn.recv_len, 0);
    }
    conn.recv_len -= deliver_len;
}

/// Try to send data from the send buffer.
#[allow(clippy::too_many_arguments)]
fn tcp_try_send_data(
    conn_idx: usize,
    tcp_conns: &mut TcpConns,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    tx: &mut TxScratch,
) {
    let conn = &mut tcp_conns[conn_idx];
    if conn.state != TcpState::Established && conn.state != TcpState::CloseWait {
        return;
    }
    // How much data can we send?
    let in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
    let window = conn.snd_wnd as usize;
    let can_send = window.saturating_sub(in_flight);
    let unsent = conn.send_len - (conn.snd_nxt.wrapping_sub(conn.snd_una) as usize);
    let send_len = unsent.min(can_send).min(TCP_MSS as usize);
    if send_len == 0 {
        return;
    }
    let offset = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
    let payload = &conn.send_buf[offset..offset + send_len];
    tcp_send_segment(
        conn.local_port, &conn.remote_addr, conn.remote_port,
        conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW,
        payload,
        shm_base, raw_handle, our_mac, config, arp_table, pending, now,
        tx,
    );
    conn.snd_nxt = conn.snd_nxt.wrapping_add(send_len as u32);
    // Set retransmit timer
    if conn.retx_deadline == 0 {
        conn.rto_ticks = TCP_INITIAL_RTO;
        conn.retx_count = 0;
        conn.retx_deadline = now + conn.rto_ticks;
    }
}

/// Process an incoming TCP segment.
#[allow(clippy::too_many_arguments)]
fn tcp_input(
    src_ip: &[u8; 4], _dst_ip: &[u8; 4],
    tcp: &TcpHdr, data: &[u8],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    tx: &mut TxScratch,
) {
    // 1. Try to find an existing connection
    if let Some(ci) = tcp_find_conn(tcp_conns, tcp.dst_port, src_ip, tcp.src_port) {
        tcp_input_conn(
            ci, src_ip, tcp, data,
            sockets, tcp_conns, pending_accept, shm_base, raw_handle, our_mac, config, arp_table, pending, now,
            tx,
        );
        return;
    }

    // 2. Check for a listening socket
    let listener_idx = sockets.iter().position(|s| {
        s.active && s.tcp_listening && s.port == tcp.dst_port
    });
    if let Some(li) = listener_idx {
        // Only SYN should arrive for a listening socket
        if tcp.flags & TCP_SYN == 0 || tcp.flags & TCP_ACK != 0 {
            tcp_send_rst(src_ip, tcp, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
            return;
        }
        // Check accept backlog
        if sockets[li].accept_count >= TCP_ACCEPT_BACKLOG {
            tcp_send_rst(src_ip, tcp, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
            return;
        }
        // Allocate a connection
        let Some(ci) = tcp_alloc_conn(tcp_conns) else {
            tcp_send_rst(src_ip, tcp, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
            return;
        };
        let conn = &mut tcp_conns[ci];
        conn.active = true;
        conn.local_port = tcp.dst_port;
        conn.remote_addr = *src_ip;
        conn.remote_port = tcp.src_port;
        conn.state = TcpState::SynReceived;
        conn.rcv_nxt = tcp.seq.wrapping_add(1);
        conn.snd_una = tcp_initial_seq();
        conn.snd_nxt = conn.snd_una.wrapping_add(1); // SYN consumes one seq
        conn.snd_wnd = tcp.window;
        conn.socket_idx = usize::MAX; // not yet associated with a socket
        conn.listener_sock_idx = li;
        conn.rto_ticks = TCP_INITIAL_RTO;
        conn.retx_count = 0;
        conn.retx_deadline = now + conn.rto_ticks;
        // Send SYN-ACK
        tcp_send_segment(
            conn.local_port, &conn.remote_addr, conn.remote_port,
            conn.snd_una, conn.rcv_nxt, TCP_SYN | TCP_ACK, TCP_WINDOW, &[],
            shm_base, raw_handle, our_mac, config, arp_table, pending, now,
            tx,
        );
        return;
    }

    // 3. No match — send RST
    if tcp.flags & TCP_RST == 0 {
        tcp_send_rst(src_ip, tcp, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
    }
}

/// Process TCP input for an existing connection.
#[allow(clippy::too_many_arguments)]
fn tcp_input_conn(
    ci: usize,
    src_ip: &[u8; 4],
    tcp: &TcpHdr, data: &[u8],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    tx: &mut TxScratch,
) {
    // Handle RST
    if tcp.flags & TCP_RST != 0 {
        let conn = &mut tcp_conns[ci];
        let si = conn.socket_idx;
        conn.reset();
        if si != usize::MAX && si < MAX_SOCKETS && sockets[si].active {
            // Notify client of reset; deactivate if channel already closed
            tx.msg = Message::new();
            tx.msg.len = rvos_wire::to_bytes(
                &SocketResponse::Error { code: SocketError::ConnReset {} },
                &mut tx.msg.data,
            ).expect("serialize");
            if raw::sys_chan_send(sockets[si].handle, &tx.msg) == raw::CHAN_CLOSED {
                sockets[si].deactivate(tcp_conns);
            }
        }
        return;
    }

    // Read state before the match so we can reborrow tcp_conns within each arm
    let state = tcp_conns[ci].state;
    match state {
        TcpState::SynSent => {
            let conn = &mut tcp_conns[ci];
            // We sent SYN (client connect), expecting SYN-ACK
            if tcp.flags & TCP_SYN != 0 && tcp.flags & TCP_ACK != 0 {
                if tcp.ack != conn.snd_nxt {
                    tcp_send_rst(src_ip, tcp, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
                    return;
                }
                conn.snd_una = tcp.ack;
                conn.rcv_nxt = tcp.seq.wrapping_add(1);
                conn.snd_wnd = tcp.window;
                conn.state = TcpState::Established;
                conn.retx_deadline = 0;
                conn.retx_count = 0;
                // Send ACK
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
                // Notify waiting Connect call
                if conn.socket_idx != usize::MAX && conn.socket_idx < MAX_SOCKETS {
                    let sock = &mut sockets[conn.socket_idx];
                    tx.msg = Message::new();
                    tx.msg.len = rvos_wire::to_bytes(
                        &SocketResponse::Ok {},
                        &mut tx.msg.data,
                    ).expect("serialize");
                    if raw::sys_chan_send(sock.handle, &tx.msg) == raw::CHAN_CLOSED {
                        sock.deactivate(tcp_conns);
                    }
                }
            }
        }
        TcpState::SynReceived => {
            // We sent SYN-ACK (server side), expecting ACK
            if tcp.flags & TCP_ACK != 0 {
                let conn = &mut tcp_conns[ci];
                if tcp.ack != conn.snd_nxt {
                    return;
                }
                conn.snd_una = tcp.ack;
                conn.snd_wnd = tcp.window;
                conn.state = TcpState::Established;
                conn.retx_deadline = 0;
                conn.retx_count = 0;
                // RFC 793: the handshake ACK may carry data — buffer it
                if !data.is_empty() && tcp.seq == conn.rcv_nxt {
                    let space = conn.recv_buf.len() - conn.recv_len;
                    let copy_len = data.len().min(space);
                    if copy_len > 0 {
                        conn.recv_buf[conn.recv_len..conn.recv_len + copy_len]
                            .copy_from_slice(&data[..copy_len]);
                        conn.recv_len += copy_len;
                        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(copy_len as u32);
                    }
                    tcp_send_segment(
                        conn.local_port, &conn.remote_addr, conn.remote_port,
                        conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
                        shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                        tx,
                    );
                }
                // Add to listener's accept queue
                let li = conn.listener_sock_idx;
                if li != usize::MAX && li < MAX_SOCKETS && sockets[li].active
                    && sockets[li].accept_count < TCP_ACCEPT_BACKLOG
                {
                    let cnt = sockets[li].accept_count;
                    sockets[li].accept_queue[cnt] = ci;
                    sockets[li].accept_count += 1;
                    // If Accept is pending, deliver now
                    if sockets[li].accept_pending {
                        tcp_deliver_accept(
                            &mut sockets[li], tcp_conns, pending_accept, 0,
                            shm_base, raw_handle, our_mac, arp_table, pending, now,
                            tx,
                        );
                        // Process pending accept assignment
                        if let Some(info) = pending_accept.take() {
                            assign_accepted_socket(sockets, tcp_conns, info.handle, info.conn_idx);
                        }
                    }
                }
            }
        }
        TcpState::Established => {
            tcp_input_established(ci, tcp, data, sockets, tcp_conns, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
        }
        TcpState::FinWait1 => {
            let conn = &mut tcp_conns[ci];
            // We sent FIN, waiting for ACK
            if tcp.flags & TCP_ACK != 0 && tcp.ack == conn.snd_nxt {
                conn.snd_una = tcp.ack;
                conn.retx_deadline = 0;
                if tcp.flags & TCP_FIN != 0 {
                    // Simultaneous close: FIN+ACK
                    conn.rcv_nxt = tcp.seq.wrapping_add(1);
                    conn.state = TcpState::TimeWait;
                    conn.time_wait_deadline = now + 2 * TICK_HZ;
                    tcp_send_segment(
                        conn.local_port, &conn.remote_addr, conn.remote_port,
                        conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
                        shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                        tx,
                    );
                } else {
                    conn.state = TcpState::FinWait2;
                }
            } else if tcp.flags & TCP_FIN != 0 {
                // Simultaneous close without ACK
                conn.rcv_nxt = tcp.seq.wrapping_add(1);
                conn.state = TcpState::Closing;
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
        }
        TcpState::FinWait2 => {
            let conn = &mut tcp_conns[ci];
            // Waiting for remote FIN
            if tcp.flags & TCP_FIN != 0 {
                conn.rcv_nxt = tcp.seq.wrapping_add(1);
                conn.state = TcpState::TimeWait;
                conn.time_wait_deadline = now + 2 * TICK_HZ;
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
        }
        TcpState::Closing => {
            let conn = &mut tcp_conns[ci];
            if tcp.flags & TCP_ACK != 0 && tcp.ack == conn.snd_nxt {
                conn.state = TcpState::TimeWait;
                conn.time_wait_deadline = now + 2 * TICK_HZ;
            }
        }
        TcpState::LastAck => {
            let conn = &mut tcp_conns[ci];
            if tcp.flags & TCP_ACK != 0 && tcp.ack == conn.snd_nxt {
                let si = conn.socket_idx;
                conn.reset();
                if si != usize::MAX && si < MAX_SOCKETS {
                    // Don't deactivate — let client close the channel
                }
            }
        }
        TcpState::CloseWait => {
            // Process ACKs for sent data
            if tcp.flags & TCP_ACK != 0 {
                tcp_process_ack(ci, tcp_conns, tcp.ack);
            }
        }
        TcpState::TimeWait => {
            let conn = &mut tcp_conns[ci];
            // Re-ACK any FIN retransmissions
            if tcp.flags & TCP_FIN != 0 {
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
        }
        _ => {}
    }
}

/// Process TCP data in Established state.
#[allow(clippy::too_many_arguments)]
fn tcp_input_established(
    ci: usize,
    tcp: &TcpHdr, data: &[u8],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    tx: &mut TxScratch,
) {
    // Process ACK
    if tcp.flags & TCP_ACK != 0 {
        tcp_process_ack(ci, tcp_conns, tcp.ack);
    }
    let conn = &mut tcp_conns[ci];
    conn.snd_wnd = tcp.window;

    // Accept in-order data only
    if !data.is_empty() && tcp.seq == conn.rcv_nxt {
        let space = conn.recv_buf.len() - conn.recv_len;
        let copy_len = data.len().min(space);
        if copy_len > 0 {
            conn.recv_buf[conn.recv_len..conn.recv_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            conn.recv_len += copy_len;
            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(copy_len as u32);
        }
        // Send ACK
        tcp_send_segment(
            conn.local_port, &conn.remote_addr, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
            shm_base, raw_handle, our_mac, config, arp_table, pending, now,
            tx,
        );
        // Try to deliver data to waiting client
        let si = conn.socket_idx;
        if si != usize::MAX && si < MAX_SOCKETS {
            tcp_try_deliver_recv(&mut sockets[si], tcp_conns, &mut tx.msg);
        }
    } else if !data.is_empty() {
        // Out-of-order: send duplicate ACK (will cause retransmit on sender side)
        tcp_send_segment(
            conn.local_port, &conn.remote_addr, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
            shm_base, raw_handle, our_mac, config, arp_table, pending, now,
            tx,
        );
    }

    // Handle FIN
    let conn = &mut tcp_conns[ci];
    if tcp.flags & TCP_FIN != 0 && tcp.seq == conn.rcv_nxt {
        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
        conn.state = TcpState::CloseWait;
        // ACK the FIN
        tcp_send_segment(
            conn.local_port, &conn.remote_addr, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
            shm_base, raw_handle, our_mac, config, arp_table, pending, now,
            tx,
        );
        // If client is waiting on Recv, deliver EOF
        let si = conn.socket_idx;
        if si != usize::MAX && si < MAX_SOCKETS {
            tcp_try_deliver_recv(&mut sockets[si], tcp_conns, &mut tx.msg);
        }
    }

    // Try to send more data if window opened up
    if tcp_conns[ci].send_len > 0 {
        tcp_try_send_data(ci, tcp_conns, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
    }
}

/// Process an ACK: advance snd_una, remove acked data from send buffer.
fn tcp_process_ack(ci: usize, tcp_conns: &mut TcpConns, ack_num: u32) {
    let conn = &mut tcp_conns[ci];
    let acked = ack_num.wrapping_sub(conn.snd_una);
    if acked == 0 || acked > (conn.send_len as u32) {
        return;
    }
    let acked = acked as usize;
    // Remove acked data from send_buf
    if acked < conn.send_len {
        conn.send_buf.copy_within(acked..conn.send_len, 0);
    }
    conn.send_len -= acked;
    conn.snd_una = ack_num;
    // If all data is acked, clear retransmit timer
    if conn.snd_una == conn.snd_nxt {
        conn.retx_deadline = 0;
        conn.retx_count = 0;
    } else {
        // Reset retransmit timer for remaining data
        conn.rto_ticks = TCP_INITIAL_RTO;
        conn.retx_count = 0;
        conn.retx_deadline = now_ticks() + conn.rto_ticks;
    }
}

/// Deliver a connection from the accept queue to a waiting Accept call.
#[allow(clippy::too_many_arguments)]
fn tcp_deliver_accept(
    sock: &mut Socket,
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    _sockets_base: usize,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], _now: u64,
    tx: &mut TxScratch,
) {
    if !sock.accept_pending || sock.accept_count == 0 {
        return;
    }
    // Pop the first connection from the accept queue
    let ci = sock.accept_queue[0];
    for j in 1..sock.accept_count {
        sock.accept_queue[j - 1] = sock.accept_queue[j];
    }
    sock.accept_count -= 1;
    sock.accept_queue[sock.accept_count] = usize::MAX;

    let conn = &mut tcp_conns[ci];
    let peer_addr = SocketAddr::Inet4 {
        a: conn.remote_addr[0], b: conn.remote_addr[1],
        c: conn.remote_addr[2], d: conn.remote_addr[3],
        port: conn.remote_port,
    };

    // Create a new channel pair for the accepted socket
    let (sock_a, sock_b) = raw::sys_chan_create();

    // Send Accepted response with the new channel cap
    tx.msg = Message::new();
    let (len, cap_count) = rvos_wire::to_bytes_with_caps(
        &SocketResponse::Accepted {
            peer_addr,
            socket: rvos_wire::RawChannelCap::new(sock_b),
        },
        &mut tx.msg.data,
        &mut tx.msg.caps,
    ).unwrap_or((0, 0));
    tx.msg.len = len;
    tx.msg.cap_count = cap_count;
    let ret = raw::sys_chan_send(sock.handle, &tx.msg);
    raw::sys_chan_close(sock_b);
    sock.accept_pending = false;

    if ret == raw::CHAN_CLOSED {
        // Listener client gone
        raw::sys_chan_close(sock_a);
        conn.reset();
        return;
    }

    // We can't assign the socket here because sock is already a mutable
    // reference to one element of the sockets array. Store the info for
    // the caller to assign after this function returns.
    let _ = (shm_base, raw_handle, our_mac, arp_table, pending, tx);
    conn.socket_idx = sock_a; // abuse: store handle temporarily
    *pending_accept = Some(PendingAcceptInfo {
        handle: sock_a,
        conn_idx: ci,
    });
}

struct PendingAcceptInfo {
    handle: usize,
    conn_idx: usize,
}

/// Check retransmit timers for all active TCP connections.
#[allow(clippy::too_many_arguments)]
fn tcp_check_retransmits(
    tcp_conns: &mut TcpConns,
    shm_base: usize, raw_handle: usize,
    our_mac: &[u8; 6], config: &NetConfig, arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING], now: u64,
    sockets: &mut [Socket; MAX_SOCKETS],
    tx: &mut TxScratch,
) {
    for conn in tcp_conns.iter_mut() {
        if !conn.active || conn.retx_deadline == 0 || now < conn.retx_deadline {
            continue;
        }
        conn.retx_count += 1;
        if conn.retx_count > TCP_MAX_RETX {
            // Too many retransmits — abort connection
            let si = conn.socket_idx;
            conn.reset();
            if si != usize::MAX && si < MAX_SOCKETS && sockets[si].active {
                tx.msg = Message::new();
                tx.msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Error { code: SocketError::TimedOut {} },
                    &mut tx.msg.data,
                ).expect("serialize");
                if raw::sys_chan_send(sockets[si].handle, &tx.msg) == raw::CHAN_CLOSED {
                    // Can't call deactivate() here (tcp_conns borrowed by iter).
                    // Close handle; main loop will clean up the socket on next poll.
                    raw::sys_chan_close(sockets[si].handle);
                    sockets[si].active = false;
                }
            }
            continue;
        }
        // Exponential backoff
        conn.rto_ticks = conn.rto_ticks.saturating_mul(2).min(60 * TICK_HZ);
        conn.retx_deadline = now + conn.rto_ticks;

        match conn.state {
            TcpState::SynSent => {
                // Retransmit SYN
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_una, 0, TCP_SYN, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
            TcpState::SynReceived => {
                // Retransmit SYN-ACK
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_una, conn.rcv_nxt, TCP_SYN | TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
            TcpState::Established | TcpState::CloseWait => {
                // Retransmit unacked data
                let unacked_len = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
                if unacked_len > 0 && unacked_len <= conn.send_len {
                    let send_len = unacked_len.min(TCP_MSS as usize);
                    tcp_send_segment(
                        conn.local_port, &conn.remote_addr, conn.remote_port,
                        conn.snd_una, conn.rcv_nxt, TCP_ACK, TCP_WINDOW,
                        &conn.send_buf[..send_len],
                        shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                        tx,
                    );
                }
            }
            TcpState::FinWait1 | TcpState::LastAck => {
                // Retransmit FIN
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_nxt.wrapping_sub(1), conn.rcv_nxt,
                    TCP_FIN | TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
            }
            _ => {
                conn.retx_deadline = 0;
            }
        }
    }
}

/// Clean up TimeWait connections that have expired.
fn tcp_check_timewait(tcp_conns: &mut TcpConns, now: u64) {
    for conn in tcp_conns.iter_mut() {
        if conn.active && conn.state == TcpState::TimeWait
            && conn.time_wait_deadline != 0 && now >= conn.time_wait_deadline
        {
            conn.reset();
        }
    }
}

// ---------------------------------------------------------------------------
// Handle client requests
// ---------------------------------------------------------------------------

/// Send a SocketResponse::Ok on a handle. Returns false if channel closed.
fn send_sock_ok(handle: usize, msg: &mut Message) -> bool {
    *msg = Message::new();
    msg.len = rvos_wire::to_bytes(&SocketResponse::Ok {}, &mut msg.data).expect("serialize");
    raw::sys_chan_send(handle, msg) != raw::CHAN_CLOSED
}

/// Send a SocketResponse::Error on a handle. Returns false if channel closed.
fn send_sock_error(handle: usize, code: SocketError, msg: &mut Message) -> bool {
    *msg = Message::new();
    msg.len = rvos_wire::to_bytes(&SocketResponse::Error { code }, &mut msg.data).expect("serialize");
    raw::sys_chan_send(handle, msg) != raw::CHAN_CLOSED
}

/// Allocate an ephemeral port (49152..65535) that isn't in use.
fn alloc_ephemeral_port(sockets: &[Socket; MAX_SOCKETS]) -> u16 {
    static mut NEXT_EPHEMERAL: u16 = 49152;
    for _ in 0..1000 {
        let port = unsafe {
            let p = NEXT_EPHEMERAL;
            NEXT_EPHEMERAL = if p >= 65534 { 49152 } else { p + 1 };
            p
        };
        if !sockets.iter().any(|s| s.active && s.port == port) {
            return port;
        }
    }
    0 // shouldn't happen with 16K range and 16 sockets
}

/// Assign a newly accepted socket to a free slot.
fn assign_accepted_socket(sockets: &mut [Socket; MAX_SOCKETS], tcp_conns: &mut TcpConns, handle: usize, conn_idx: usize) {
    let free = sockets.iter().position(|s| !s.active);
    let Some(idx) = free else {
        raw::sys_chan_close(handle);
        tcp_conns[conn_idx].reset();
        return;
    };
    sockets[idx].active = true;
    sockets[idx].handle = handle;
    sockets[idx].is_stream = true;
    sockets[idx].tcp_conn_idx = conn_idx;
    tcp_conns[conn_idx].socket_idx = idx;
    sockets[idx].port = tcp_conns[conn_idx].local_port;
}

/// Allocate an ephemeral port (49152–65535) not currently in use.
fn allocate_ephemeral_port(sockets: &[Socket; MAX_SOCKETS]) -> Option<u16> {
    (49152u16..=65535).find(|&port| !sockets.iter().any(|s| s.active && s.port == port))
}

#[allow(clippy::too_many_arguments)] // inherent complexity of passing service state
fn handle_client_message(
    sock_idx: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    msg: &Message,
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    config: &NetConfig,
    arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING],
    now: u64,
    tx: &mut TxScratch,
) {
    let req = match rvos_wire::from_bytes::<SocketRequest<'_>>(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => return,
    };

    let handle = sockets[sock_idx].handle;

    match req {
        SocketRequest::Bind { addr } => {
            let SocketAddr::Inet4 { port, .. } = addr;
            // Assign ephemeral port if requested port is 0
            let port = if port == 0 {
                allocate_ephemeral_port(sockets)
            } else {
                Some(port)
            };
            tx.msg = Message::new();
            match port {
                Some(p) => {
                    let already_bound = sockets.iter().enumerate()
                        .any(|(i, s)| i != sock_idx && s.active && s.port == p);
                    if already_bound {
                        tx.msg.len = rvos_wire::to_bytes(
                            &SocketResponse::Error { code: SocketError::AddrInUse {} },
                            &mut tx.msg.data,
                        ).expect("serialize");
                    } else {
                        sockets[sock_idx].port = p;
                        tx.msg.len = rvos_wire::to_bytes(
                            &SocketResponse::Ok {},
                            &mut tx.msg.data,
                        ).expect("serialize");
                    }
                }
                None => {
                    tx.msg.len = rvos_wire::to_bytes(
                        &SocketResponse::Error { code: SocketError::NoResources {} },
                        &mut tx.msg.data,
                    ).expect("serialize");
                }
            }
            if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                sockets[sock_idx].deactivate(tcp_conns);
            }
        }
        SocketRequest::SendTo { addr, data } => {
            let SocketAddr::Inet4 { a, b, c, d, port: dst_port } = addr;
            let dst_ip = [a, b, c, d];
            // Auto-bind to ephemeral port if not yet bound
            if sockets[sock_idx].port == 0 {
                if let Some(p) = allocate_ephemeral_port(sockets) {
                    sockets[sock_idx].port = p;
                }
            }
            let src_port = sockets[sock_idx].port;

            // Build UDP payload
            let mut udp_buf = [0u8; 1480];
            let udp_len = build_udp(&config.our_ip, &dst_ip, src_port, dst_port, data, &mut udp_buf);
            if udp_len == 0 {
                tx.msg = Message::new();
                tx.msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Error { code: SocketError::InvalidArg {} },
                    &mut tx.msg.data,
                ).expect("serialize");
                if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                    sockets[sock_idx].deactivate(tcp_conns);
                }
                return;
            }

            // Build IPv4 packet
            let ip_len = build_ipv4(&config.our_ip, &dst_ip, PROTO_UDP, &udp_buf[..udp_len], &mut tx.ip_buf);
            if ip_len == 0 {
                tx.msg = Message::new();
                tx.msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Error { code: SocketError::NoResources {} },
                    &mut tx.msg.data,
                ).expect("serialize");
                if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                    sockets[sock_idx].deactivate(tcp_conns);
                }
                return;
            }

            send_ip_packet(
                shm_base, raw_handle, our_mac, config, arp_table, pending,
                &tx.ip_buf[..ip_len], &dst_ip, now,
                &mut tx.frame_buf, &mut tx.msg,
            );

            tx.msg = Message::new();
            tx.msg.len = rvos_wire::to_bytes(
                &SocketResponse::Sent { bytes: data.len() as u32 },
                &mut tx.msg.data,
            ).expect("serialize");
            if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                sockets[sock_idx].deactivate(tcp_conns);
            }
        }
        SocketRequest::RecvFrom {} => {
            sockets[sock_idx].recv_pending = true;
        }
        SocketRequest::GetSockName {} => {
            let port = sockets[sock_idx].port;
            tx.msg = Message::new();
            tx.msg.len = rvos_wire::to_bytes(
                &SocketResponse::Addr {
                    addr: SocketAddr::Inet4 {
                        a: config.our_ip[0], b: config.our_ip[1],
                        c: config.our_ip[2], d: config.our_ip[3],
                        port,
                    },
                },
                &mut tx.msg.data,
            ).expect("serialize");
            if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                sockets[sock_idx].deactivate(tcp_conns);
            }
        }
        SocketRequest::Listen { backlog: _ } => {
            if !sockets[sock_idx].is_stream {
                send_sock_error(handle, SocketError::NotSupported {}, &mut tx.msg);
                return;
            }
            if sockets[sock_idx].port == 0 {
                send_sock_error(handle, SocketError::InvalidArg {}, &mut tx.msg);
                return;
            }
            sockets[sock_idx].tcp_listening = true;
            send_sock_ok(handle, &mut tx.msg);
        }
        SocketRequest::Accept {} => {
            if !sockets[sock_idx].tcp_listening {
                send_sock_error(handle, SocketError::InvalidArg {}, &mut tx.msg);
                return;
            }
            if sockets[sock_idx].accept_count > 0 {
                // Connection already waiting — deliver immediately
                tcp_deliver_accept(
                    &mut sockets[sock_idx], tcp_conns, pending_accept, 0,
                    shm_base, raw_handle, our_mac, arp_table, pending, now,
                    tx,
                );
                // Process pending accept assignment
                if let Some(info) = pending_accept.take() {
                    assign_accepted_socket(sockets, tcp_conns, info.handle, info.conn_idx);
                }
            } else {
                // No connections waiting — mark as pending
                sockets[sock_idx].accept_pending = true;
            }
        }
        SocketRequest::Connect { addr } => {
            if !sockets[sock_idx].is_stream {
                send_sock_error(handle, SocketError::NotSupported {}, &mut tx.msg);
                return;
            }
            let SocketAddr::Inet4 { a, b, c, d, port } = addr;
            let dst_ip = [a, b, c, d];
            let src_port = sockets[sock_idx].port;
            // Auto-assign ephemeral port if not bound
            let src_port = if src_port == 0 {
                let p = alloc_ephemeral_port(sockets);
                sockets[sock_idx].port = p;
                p
            } else {
                src_port
            };
            // Allocate a TCP connection
            let Some(ci) = tcp_alloc_conn(tcp_conns) else {
                send_sock_error(handle, SocketError::NoResources {}, &mut tx.msg);
                return;
            };
            let conn = &mut tcp_conns[ci];
            conn.active = true;
            conn.local_port = src_port;
            conn.remote_addr = dst_ip;
            conn.remote_port = port;
            conn.state = TcpState::SynSent;
            conn.snd_una = tcp_initial_seq();
            conn.snd_nxt = conn.snd_una.wrapping_add(1);
            conn.snd_wnd = TCP_WINDOW;
            conn.socket_idx = sock_idx;
            conn.rto_ticks = TCP_INITIAL_RTO;
            conn.retx_count = 0;
            conn.retx_deadline = now + conn.rto_ticks;
            sockets[sock_idx].tcp_conn_idx = ci;
            // Send SYN
            tcp_send_segment(
                src_port, &dst_ip, port,
                conn.snd_una, 0, TCP_SYN, TCP_WINDOW, &[],
                shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                tx,
            );
            // Response is deferred until SYN-ACK arrives
        }
        SocketRequest::Send { data } => {
            let ci = sockets[sock_idx].tcp_conn_idx;
            if ci == usize::MAX {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            }
            let conn = &mut tcp_conns[ci];
            if conn.state != TcpState::Established && conn.state != TcpState::CloseWait {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            }
            let space = conn.send_buf.len() - conn.send_len;
            let copy_len = data.len().min(space);
            if copy_len == 0 {
                send_sock_error(handle, SocketError::NoResources {}, &mut tx.msg);
                return;
            }
            conn.send_buf[conn.send_len..conn.send_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            conn.send_len += copy_len;
            // Try to send immediately
            tcp_try_send_data(ci, tcp_conns, shm_base, raw_handle, our_mac, config, arp_table, pending, now, tx);
            // Respond with bytes accepted
            tx.msg = Message::new();
            tx.msg.len = rvos_wire::to_bytes(
                &SocketResponse::Sent { bytes: copy_len as u32 },
                &mut tx.msg.data,
            ).expect("serialize");
            if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                sockets[sock_idx].deactivate(tcp_conns);
            }
        }
        SocketRequest::Recv { max_len } => {
            let ci = sockets[sock_idx].tcp_conn_idx;
            if ci == usize::MAX {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            }
            sockets[sock_idx].recv_max_len = max_len;
            sockets[sock_idx].recv_pending = true;
            // Try to deliver immediately if data is available
            tcp_try_deliver_recv(&mut sockets[sock_idx], tcp_conns, &mut tx.msg);
        }
        SocketRequest::Shutdown { how } => {
            let ci = sockets[sock_idx].tcp_conn_idx;
            if ci == usize::MAX {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            }
            let conn = &mut tcp_conns[ci];
            let send_fin = matches!(how, ShutdownHow::Write {} | ShutdownHow::Both {});
            if send_fin && (conn.state == TcpState::Established || conn.state == TcpState::CloseWait) {
                // Send FIN
                let new_state = if conn.state == TcpState::Established {
                    TcpState::FinWait1
                } else {
                    TcpState::LastAck
                };
                conn.state = new_state;
                tcp_send_segment(
                    conn.local_port, &conn.remote_addr, conn.remote_port,
                    conn.snd_nxt, conn.rcv_nxt, TCP_FIN | TCP_ACK, TCP_WINDOW, &[],
                    shm_base, raw_handle, our_mac, config, arp_table, pending, now,
                    tx,
                );
                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                conn.retx_deadline = now + conn.rto_ticks;
            }
            send_sock_ok(handle, &mut tx.msg);
        }
        SocketRequest::GetPeerName {} => {
            let ci = sockets[sock_idx].tcp_conn_idx;
            if ci == usize::MAX {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            }
            let conn = &tcp_conns[ci];
            tx.msg = Message::new();
            tx.msg.len = rvos_wire::to_bytes(
                &SocketResponse::Addr {
                    addr: SocketAddr::Inet4 {
                        a: conn.remote_addr[0], b: conn.remote_addr[1],
                        c: conn.remote_addr[2], d: conn.remote_addr[3],
                        port: conn.remote_port,
                    },
                },
                &mut tx.msg.data,
            ).expect("serialize");
            if raw::sys_chan_send(handle, &tx.msg) == raw::CHAN_CLOSED {
                sockets[sock_idx].deactivate(tcp_conns);
            }
        }
    }
}

/// Handle a SocketsRequest from a pending client: create per-socket channel,
/// send back Created response with the cap, or return config info.
fn handle_socket_request(
    client_handle: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    msg: &Message,
    config: &NetConfig,
    tx: &mut TxScratch,
) {
    let req = match rvos_wire::from_bytes::<SocketsRequest>(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => {
            raw::sys_chan_close(client_handle);
            return;
        }
    };

    // Handle GetConfig — reply with current network configuration and close
    if matches!(req, SocketsRequest::GetConfig {}) {
        tx.msg = Message::new();
        let (len, cap_count) = rvos_wire::to_bytes_with_caps(
            &SocketsResponse::Config {
                ip_a: config.our_ip[0], ip_b: config.our_ip[1],
                ip_c: config.our_ip[2], ip_d: config.our_ip[3],
                gw_a: config.gateway[0], gw_b: config.gateway[1],
                gw_c: config.gateway[2], gw_d: config.gateway[3],
                mask_a: config.subnet_mask[0], mask_b: config.subnet_mask[1],
                mask_c: config.subnet_mask[2], mask_d: config.subnet_mask[3],
                dns_a: config.dns_server[0], dns_b: config.dns_server[1],
                dns_c: config.dns_server[2], dns_d: config.dns_server[3],
            },
            &mut tx.msg.data,
            &mut tx.msg.caps,
        ).unwrap_or((0, 0));
        tx.msg.len = len;
        tx.msg.cap_count = cap_count;
        let _ = raw::sys_chan_send(client_handle, &tx.msg);
        raw::sys_chan_close(client_handle);
        return;
    }

    let SocketsRequest::Socket { sock_type } = req else {
        raw::sys_chan_close(client_handle);
        return;
    };
    let is_stream = matches!(sock_type, SocketType::Stream {});

    // Find a free socket slot
    let free_idx = sockets.iter().position(|s| !s.active);
    let Some(idx) = free_idx else {
        // No free slots — send error
        tx.msg = Message::new();
        let (len, cap_count) = rvos_wire::to_bytes_with_caps(
            &SocketsResponse::Error { code: SocketError::NoResources {} },
            &mut tx.msg.data,
            &mut tx.msg.caps,
        ).unwrap_or((0, 0));
        tx.msg.len = len;
        tx.msg.cap_count = cap_count;
        let _ = raw::sys_chan_send(client_handle, &tx.msg);
        raw::sys_chan_close(client_handle);
        return;
    };

    // Create per-socket channel pair
    let (sock_a, sock_b) = raw::sys_chan_create();

    // Send Created response with sock_b as the client's end
    tx.msg = Message::new();
    let (len, cap_count) = rvos_wire::to_bytes_with_caps(
        &SocketsResponse::Created { socket: rvos_wire::RawChannelCap::new(sock_b) },
        &mut tx.msg.data,
        &mut tx.msg.caps,
    ).unwrap_or((0, 0));
    tx.msg.len = len;
    tx.msg.cap_count = cap_count;
    let ret = raw::sys_chan_send(client_handle, &tx.msg);

    // Close our reference to sock_b (the send transferred a ref to the client)
    raw::sys_chan_close(sock_b);
    // Close the control channel — client will drop their end too
    raw::sys_chan_close(client_handle);

    if ret == raw::CHAN_CLOSED {
        // Client already gone — clean up sock_a
        raw::sys_chan_close(sock_a);
        return;
    }

    // Register the per-socket channel in the socket table
    sockets[idx].active = true;
    sockets[idx].handle = sock_a;
    sockets[idx].port = 0;
    sockets[idx].recv_pending = false;
    sockets[idx].is_stream = is_stream;
}

// ---------------------------------------------------------------------------
// DHCP Client
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

/// Parsed DHCP response.
struct DhcpOffer {
    your_ip: [u8; 4],
    server_ip: [u8; 4],
    subnet_mask: [u8; 4],
    gateway: [u8; 4],
    dns_server: [u8; 4],
    msg_type: u8,
}

/// Build a DHCP message (DISCOVER or REQUEST) as a raw Ethernet frame.
/// Returns the frame length written to `frame_buf`.
fn build_dhcp_frame(
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
fn parse_dhcp_response(frame: &[u8], our_mac: &[u8; 6], xid: u32) -> Option<DhcpOffer> {
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

/// Run the DHCP client: DISCOVER → OFFER → REQUEST → ACK.
/// Returns true if an address was acquired, false if we should use fallback.
fn dhcp_acquire(
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

    // --- Phase 1: DISCOVER → OFFER ---
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

    // --- Phase 2: REQUEST → ACK ---
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
                // No packets — yield and retry
                std::thread::yield_now();
                continue;
            }

            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let slot_idx = (rx_tail % RX_SLOTS as u32) as usize;
            let slot_offset = RX_RING_OFFSET + slot_idx * RX_SLOT_SIZE;
            let frame_len = shm_read_u16(shm_base, slot_offset) as usize;
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
            rx.doorbell = Message::new();
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
            // Not a DHCP response — discard and keep polling
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("[net-stack] starting...");

    // 1. Connect to "net-raw" service via boot channel
    let raw_ch = match rvos::service::connect_to_service("net-raw") {
        Ok(ch) => ch,
        Err(e) => {
            println!("[net-stack] failed to connect to net-raw: {:?}", e);
            return;
        }
    };
    let raw_handle = raw_ch.into_raw_handle();

    // Allocate scratch buffers on the heap early so we can reuse tx.msg for init
    let mut tx: Box<TxScratch> = {
        let layout = alloc::alloc::Layout::new::<TxScratch>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut TxScratch };
        assert!(!ptr.is_null(), "failed to allocate TxScratch");
        unsafe { Box::from_raw(ptr) }
    };
    let mut rx: Box<RxScratch> = {
        let layout = alloc::alloc::Layout::new::<RxScratch>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut RxScratch };
        assert!(!ptr.is_null(), "failed to allocate RxScratch");
        unsafe { Box::from_raw(ptr) }
    };

    // 2. Send GetDeviceInfo request
    tx.msg = Message::new();
    tx.msg.len = rvos_wire::to_bytes(&NetRawRequest::GetDeviceInfo {}, &mut tx.msg.data).expect("serialize");
    if raw::sys_chan_send_blocking(raw_handle, &tx.msg) != 0 {
        println!("[net-stack] failed to send GetDeviceInfo");
        return;
    }

    // 3. Receive DeviceInfo response (with SHM cap)
    rx.client_msg = Message::new();
    if raw::sys_chan_recv_blocking(raw_handle, &mut rx.client_msg) != 0 {
        println!("[net-stack] failed to recv DeviceInfo");
        return;
    }

    let our_mac;
    match rvos_wire::from_bytes::<NetRawResponse>(&rx.client_msg.data[..rx.client_msg.len]) {
        Ok(NetRawResponse::DeviceInfo { mac0, mac1, mac2, mac3, mac4, mac5, mtu: _ }) => {
            our_mac = [mac0, mac1, mac2, mac3, mac4, mac5];
            println!(
                "[net-stack] MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac0, mac1, mac2, mac3, mac4, mac5
            );
        }
        _ => {
            println!("[net-stack] unexpected response from net-raw");
            return;
        }
    }

    // 4. Map SHM from cap
    let shm_cap = if rx.client_msg.cap_count > 0 { rx.client_msg.caps[0] } else { NO_CAP };
    if shm_cap == NO_CAP {
        println!("[net-stack] no SHM cap received from net-raw");
        return;
    }
    let shm_base = raw::sys_mmap(shm_cap, SHM_PAGE_COUNT * 4096);
    if shm_base == usize::MAX {
        println!("[net-stack] mmap failed for SHM");
        return;
    }
    println!("[net-stack] SHM mapped at {:#x}", shm_base);

    // 5. Initialize state
    let mut arp_table = ArpTable::new();
    let mut sockets = [const { Socket::new() }; MAX_SOCKETS];
    let mut tcp_conns: Box<TcpConns> = {
        let layout = alloc::alloc::Layout::new::<TcpConns>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut TcpConns };
        assert!(!ptr.is_null(), "failed to allocate TcpConns");
        let mut b = unsafe { Box::from_raw(ptr) };
        // Fix up non-zero default fields
        for conn in b.iter_mut() {
            conn.socket_idx = usize::MAX;
            conn.listener_sock_idx = usize::MAX;
        }
        b
    };
    let mut pending_accept: Option<PendingAcceptInfo> = None;
    let mut pending = core::array::from_fn(|_| PendingPacket::new());
    let mut pending_clients = [const { PendingClient::new() }; MAX_PENDING_CLIENTS];

    // Run DHCP to acquire network configuration; fall back to static IPs
    let mut config = NetConfig::new_unconfigured();
    if !dhcp_acquire(shm_base, raw_handle, &our_mac, &mut config, &mut tx, &mut rx) {
        config.apply_fallback();
    }

    // Pre-populate ARP entry for gateway (QEMU user-net responds to ARP)
    // We'll learn it dynamically from the first ARP reply, but send a
    // gratuitous ARP request to speed things up.
    {
        let mut arp_buf = [0u8; 64];
        let arp_len = send_arp_request(&our_mac, &config.our_ip, &config.gateway, &mut arp_buf);
        if arp_len > 0 {
            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len], &mut tx.msg);
        }
    }

    println!("[net-stack] entering main loop");

    // 6. Main event loop
    loop {
        let mut handled = false;
        let now = now_ticks();

        // Expire stale ARP entries
        arp_table.expire(now);

        // a. Drain SHM RX ring
        loop {
            let rx_head = shm_read_u32(shm_base, CTRL_RX_HEAD);
            let rx_tail = shm_read_u32(shm_base, CTRL_RX_TAIL);
            if rx_head == rx_tail {
                break;
            }
            handled = true;
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let slot_idx = (rx_tail % RX_SLOTS as u32) as usize;
            let slot_offset = RX_RING_OFFSET + slot_idx * RX_SLOT_SIZE;
            let frame_len = shm_read_u16(shm_base, slot_offset) as usize;

            let copy_len = frame_len.min(1534);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (shm_base + slot_offset + 2) as *const u8,
                    rx.rx_buf.as_mut_ptr(),
                    copy_len,
                );
            }
            shm_write_u32(shm_base, CTRL_RX_TAIL, rx_tail.wrapping_add(1));

            process_frame(
                &rx.rx_buf[..copy_len],
                shm_base,
                raw_handle,
                &our_mac,
                &config,
                &mut arp_table,
                &mut sockets,
                &mut tcp_conns,
                &mut pending_accept,
                &mut pending,
                now,
                &mut tx,
            );
        }

        // b. Poll raw channel for RxReady/TxConsumed doorbells
        loop {
            rx.doorbell = Message::new();
            let ret = raw::sys_chan_recv(raw_handle, &mut rx.doorbell);
            if ret != 0 {
                break;
            }
            handled = true;
            // We don't need to inspect the doorbell type -- any message from
            // net-raw means we should re-drain the SHM rings, which happens
            // at the top of the next iteration.
        }

        // c. Poll control channel (handle 1) for new client connections
        loop {
            rx.ctrl_msg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut rx.ctrl_msg);
            if ret != 0 {
                break;
            }
            handled = true;

            let cap = if rx.ctrl_msg.cap_count > 0 { rx.ctrl_msg.caps[0] } else { NO_CAP };
            if cap == NO_CAP {
                continue;
            }

            // Store as pending client — will handle SocketsRequest on next poll
            let mut assigned = false;
            for pc in pending_clients.iter_mut() {
                if !pc.active {
                    pc.active = true;
                    pc.handle = cap;
                    assigned = true;
                    break;
                }
            }
            if !assigned {
                println!("[net-stack] no free pending client slots, closing");
                raw::sys_chan_close(cap);
            }
        }

        // c2. Poll pending clients for SocketsRequest::Socket messages
        for pc in pending_clients.iter_mut() {
            if !pc.active {
                continue;
            }
            rx.client_msg = Message::new();
            let ret = raw::sys_chan_recv(pc.handle, &mut rx.client_msg);
            if ret == raw::CHAN_CLOSED {
                // Client closed control channel before sending request
                handled = true;
                raw::sys_chan_close(pc.handle);
                pc.active = false;
                continue;
            }
            if ret != 0 {
                continue; // No message yet
            }
            handled = true;
            let h = pc.handle;
            pc.active = false;
            handle_socket_request(h, &mut sockets, &rx.client_msg, &config, &mut tx);
        }

        // d. Poll all active socket channels for SocketRequest messages
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_SOCKETS {
            if !sockets[i].active {
                continue;
            }
            loop {
                rx.client_msg = Message::new();
                let ret = raw::sys_chan_recv(sockets[i].handle, &mut rx.client_msg);
                if ret == raw::CHAN_CLOSED {
                    // Channel closed by client — clean up socket
                    handled = true;
                    sockets[i].deactivate(&mut tcp_conns);
                    break;
                }
                if ret != 0 {
                    break;
                }
                handled = true;
                handle_client_message(
                    i,
                    &mut sockets,
                    &mut tcp_conns,
                    &mut pending_accept,
                    &rx.client_msg,
                    shm_base,
                    raw_handle,
                    &our_mac,
                    &config,
                    &arp_table,
                    &mut pending,
                    now,
                    &mut tx,
                );
            }
        }

        // e. Check pending ARP queue (retry with backoff, expire timed-out entries)
        for p in pending.iter_mut() {
            if p.active {
                handled = true; // Keep looping while we have pending work
                let next_hop = config.resolve_next_hop(&p.dst_ip);
                if arp_table.lookup(&next_hop, now).is_none()
                    && now.wrapping_sub(p.last_arp) >= ARP_RETRY_INTERVAL
                {
                    p.last_arp = now;
                    let mut arp_buf = [0u8; 64];
                    let arp_len = send_arp_request(&our_mac, &config.our_ip, &next_hop, &mut arp_buf);
                    if arp_len > 0 {
                        tx_frame(shm_base, raw_handle, &arp_buf[..arp_len], &mut tx.msg);
                    }
                }
            }
        }
        // Try to drain any newly resolved entries (also expires timed-out packets)
        drain_pending(shm_base, raw_handle, &our_mac, &config, &arp_table, &mut pending, now, &mut tx.frame_buf, &mut tx.msg);

        // f. Process pending accept assignments
        if let Some(info) = pending_accept.take() {
            assign_accepted_socket(&mut sockets, &mut tcp_conns, info.handle, info.conn_idx);
            handled = true;
        }

        // g. TCP retransmit timers
        tcp_check_retransmits(&mut tcp_conns, shm_base, raw_handle, &our_mac, &config, &arp_table, &mut pending, now, &mut sockets, &mut tx);

        // h. TCP TimeWait cleanup
        tcp_check_timewait(&mut tcp_conns, now);

        // i. Check if any TCP connections have pending retransmits (keep polling)
        for conn in tcp_conns.iter() {
            if conn.active && conn.retx_deadline != 0 {
                handled = true;
                break;
            }
        }

        if !handled {
            // Register all channels for poll-based wakeup
            raw::sys_chan_poll_add(raw_handle);
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            for pc in pending_clients.iter() {
                if pc.active {
                    raw::sys_chan_poll_add(pc.handle);
                }
            }
            for sock in sockets.iter() {
                if sock.active {
                    raw::sys_chan_poll_add(sock.handle);
                }
            }
            raw::sys_block();
        }
    }
}
