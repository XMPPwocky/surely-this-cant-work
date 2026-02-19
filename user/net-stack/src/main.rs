// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;

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

const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
const BROADCAST_MAC: [u8; 6] = [0xff; 6];

const ETH_HDR_SIZE: usize = 14;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;

const ARP_HLEN: usize = 28;

const IPV4_HDR_SIZE: usize = 20;
const PROTO_UDP: u8 = 17;

const UDP_HDR_SIZE: usize = 8;

const MAX_SOCKETS: usize = 16;
const MAX_PENDING: usize = 4;
const MAX_PENDING_CLIENTS: usize = 4;

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
// Routing
// ---------------------------------------------------------------------------

fn resolve_next_hop(dst_ip: &[u8; 4]) -> [u8; 4] {
    for i in 0..4 {
        if (dst_ip[i] & SUBNET_MASK[i]) != (OUR_IP[i] & SUBNET_MASK[i]) {
            return GATEWAY_IP;
        }
    }
    *dst_ip
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
}

impl Socket {
    const fn new() -> Self {
        Socket {
            port: 0,
            handle: 0,
            recv_pending: false,
            active: false,
            is_stream: false,
        }
    }

    /// Clean up a socket whose client channel is dead.
    fn deactivate(&mut self) {
        if self.active {
            raw::sys_chan_close(self.handle);
            self.active = false;
            self.handle = 0;
            self.port = 0;
            self.recv_pending = false;
            self.is_stream = false;
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
    data: [u8; 1500],
    len: usize,
    active: bool,
    timestamp: u64,
    last_arp: u64,
}

impl PendingPacket {
    const fn new() -> Self {
        PendingPacket {
            dst_ip: [0; 4],
            data: [0; 1500],
            len: 0,
            active: false,
            timestamp: 0,
            last_arp: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// TX via SHM ring buffer
// ---------------------------------------------------------------------------

fn tx_frame(shm_base: usize, raw_handle: usize, frame: &[u8]) {
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
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&NetRawRequest::TxReady {}, &mut msg.data).unwrap_or(0);
    let _ = raw::sys_chan_send(raw_handle, &msg); // fire-and-forget doorbell
}

// ---------------------------------------------------------------------------
// Send a fully built IP packet: resolve MAC, wrap in Ethernet, TX
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn send_ip_packet(
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING],
    ip_packet: &[u8],
    dst_ip: &[u8; 4],
    now: u64,
) {
    let next_hop = resolve_next_hop(dst_ip);

    if let Some(dst_mac) = arp_table.lookup(&next_hop, now) {
        // Have MAC -- send immediately
        let mut frame_buf = [0u8; 1534];
        let frame_len = build_eth(&dst_mac, our_mac, ETHERTYPE_IPV4, ip_packet, &mut frame_buf);
        if frame_len > 0 {
            tx_frame(shm_base, raw_handle, &frame_buf[..frame_len]);
        }
    } else {
        // Queue packet and send ARP request
        let mut queued = false;
        for p in pending.iter_mut() {
            if !p.active {
                let copy_len = ip_packet.len().min(p.data.len());
                p.data[..copy_len].copy_from_slice(&ip_packet[..copy_len]);
                p.len = copy_len;
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
        let arp_len = send_arp_request(our_mac, &OUR_IP, &next_hop, &mut arp_buf);
        if arp_len > 0 {
            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len]);
        }
    }
}

// ---------------------------------------------------------------------------
// Drain pending ARP queue: try to send queued packets whose MAC is now known
// ---------------------------------------------------------------------------

fn drain_pending(
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING],
    now: u64,
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
        let next_hop = resolve_next_hop(&p.dst_ip);
        if let Some(dst_mac) = arp_table.lookup(&next_hop, now) {
            let mut frame_buf = [0u8; 1534];
            let data_len = p.len;
            let frame_len = build_eth(&dst_mac, our_mac, ETHERTYPE_IPV4, &p.data[..data_len], &mut frame_buf);
            if frame_len > 0 {
                tx_frame(shm_base, raw_handle, &frame_buf[..frame_len]);
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
    arp_table: &mut ArpTable,
    sockets: &mut [Socket; MAX_SOCKETS],
    pending: &mut [PendingPacket; MAX_PENDING],
    now: u64,
) {
    let (eth, payload) = match parse_eth(frame) {
        Some(e) => e,
        None => return,
    };

    match eth.ethertype {
        ETHERTYPE_ARP => {
            let mut reply_buf = [0u8; 64];
            if let Some(reply_len) = handle_arp(arp_table, our_mac, &OUR_IP, payload, &mut reply_buf, now) {
                tx_frame(shm_base, raw_handle, &reply_buf[..reply_len]);
            }
            // After learning new MACs, try to drain pending queue
            drain_pending(shm_base, raw_handle, our_mac, arp_table, pending, now);
        }
        ETHERTYPE_IPV4 => {
            let (ip, ip_payload) = match parse_ipv4(payload) {
                Some(i) => i,
                None => return,
            };
            // Only accept packets addressed to us
            if ip.dst != OUR_IP {
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
                            let mut msg = Message::new();
                            let truncated_len = udp_data.len().min(900);
                            let addr = SocketAddr::Inet4 {
                                a: ip.src[0], b: ip.src[1],
                                c: ip.src[2], d: ip.src[3],
                                port: udp.src_port,
                            };
                            msg.len = rvos_wire::to_bytes(
                                &SocketData::Datagram {
                                    addr,
                                    data: &udp_data[..truncated_len],
                                },
                                &mut msg.data,
                            ).unwrap_or(0);
                            let ret = raw::sys_chan_send(sock.handle, &msg);
                            sock.recv_pending = false;
                            if ret == 2 {
                                // Client channel closed — clean up socket
                                sock.deactivate();
                            }
                        }
                        // Only deliver to the first matching socket
                        break;
                    }
                }
            }
        }
        _ => {} // Ignore other ethertypes
    }
}

// ---------------------------------------------------------------------------
// Handle client requests
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // inherent complexity of passing service state
fn handle_client_message(
    sock_idx: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    msg: &Message,
    shm_base: usize,
    raw_handle: usize,
    our_mac: &[u8; 6],
    arp_table: &ArpTable,
    pending: &mut [PendingPacket; MAX_PENDING],
    now: u64,
) {
    let req = match rvos_wire::from_bytes::<SocketRequest<'_>>(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => return,
    };

    let handle = sockets[sock_idx].handle;

    match req {
        SocketRequest::Bind { addr } => {
            let SocketAddr::Inet4 { port, .. } = addr;
            // Check if port is already bound
            let already_bound = sockets.iter().any(|s| s.active && s.port == port);
            let mut resp_msg = Message::new();
            if already_bound {
                resp_msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Error { code: SocketError::AddrInUse {} },
                    &mut resp_msg.data,
                ).unwrap_or(0);
            } else {
                sockets[sock_idx].port = port;
                resp_msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Ok {},
                    &mut resp_msg.data,
                ).unwrap_or(0);
            }
            if raw::sys_chan_send(handle, &resp_msg) == 2 {
                sockets[sock_idx].deactivate();
            }
        }
        SocketRequest::SendTo { addr, data } => {
            let SocketAddr::Inet4 { a, b, c, d, port: dst_port } = addr;
            let dst_ip = [a, b, c, d];
            let src_port = sockets[sock_idx].port;

            // Build UDP payload
            let mut udp_buf = [0u8; 1480];
            let udp_len = build_udp(&OUR_IP, &dst_ip, src_port, dst_port, data, &mut udp_buf);
            if udp_len == 0 {
                let mut resp_msg = Message::new();
                resp_msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Error { code: SocketError::InvalidArg {} },
                    &mut resp_msg.data,
                ).unwrap_or(0);
                if raw::sys_chan_send(handle, &resp_msg) == 2 {
                    sockets[sock_idx].deactivate();
                }
                return;
            }

            // Build IPv4 packet
            let mut ip_buf = [0u8; 1500];
            let ip_len = build_ipv4(&OUR_IP, &dst_ip, PROTO_UDP, &udp_buf[..udp_len], &mut ip_buf);
            if ip_len == 0 {
                let mut resp_msg = Message::new();
                resp_msg.len = rvos_wire::to_bytes(
                    &SocketResponse::Error { code: SocketError::NoResources {} },
                    &mut resp_msg.data,
                ).unwrap_or(0);
                if raw::sys_chan_send(handle, &resp_msg) == 2 {
                    sockets[sock_idx].deactivate();
                }
                return;
            }

            send_ip_packet(
                shm_base, raw_handle, our_mac, arp_table, pending,
                &ip_buf[..ip_len], &dst_ip, now,
            );

            let mut resp_msg = Message::new();
            resp_msg.len = rvos_wire::to_bytes(
                &SocketResponse::Sent { bytes: data.len() as u32 },
                &mut resp_msg.data,
            ).unwrap_or(0);
            if raw::sys_chan_send(handle, &resp_msg) == 2 {
                sockets[sock_idx].deactivate();
            }
        }
        SocketRequest::RecvFrom {} => {
            sockets[sock_idx].recv_pending = true;
        }
        SocketRequest::GetSockName {} => {
            let port = sockets[sock_idx].port;
            let mut resp_msg = Message::new();
            resp_msg.len = rvos_wire::to_bytes(
                &SocketResponse::Addr {
                    addr: SocketAddr::Inet4 {
                        a: OUR_IP[0], b: OUR_IP[1],
                        c: OUR_IP[2], d: OUR_IP[3],
                        port,
                    },
                },
                &mut resp_msg.data,
            ).unwrap_or(0);
            if raw::sys_chan_send(handle, &resp_msg) == 2 {
                sockets[sock_idx].deactivate();
            }
        }
        // TCP operations — not yet implemented
        SocketRequest::Listen { .. }
        | SocketRequest::Accept {}
        | SocketRequest::Connect { .. }
        | SocketRequest::Send { .. }
        | SocketRequest::Recv { .. }
        | SocketRequest::Shutdown { .. }
        | SocketRequest::GetPeerName {} => {
            let mut resp_msg = Message::new();
            resp_msg.len = rvos_wire::to_bytes(
                &SocketResponse::Error { code: SocketError::NotSupported {} },
                &mut resp_msg.data,
            ).unwrap_or(0);
            if raw::sys_chan_send(handle, &resp_msg) == 2 {
                sockets[sock_idx].deactivate();
            }
        }
    }
}

/// Handle a SocketsRequest from a pending client: create per-socket channel,
/// send back Created response with the cap.
fn handle_socket_request(
    client_handle: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    msg: &Message,
) {
    let req = match rvos_wire::from_bytes::<SocketsRequest>(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => {
            raw::sys_chan_close(client_handle);
            return;
        }
    };

    let SocketsRequest::Socket { sock_type } = req;
    let is_stream = matches!(sock_type, SocketType::Stream {});

    // Find a free socket slot
    let free_idx = sockets.iter().position(|s| !s.active);
    let Some(idx) = free_idx else {
        // No free slots — send error
        let mut resp = Message::new();
        let (len, cap_count) = rvos_wire::to_bytes_with_caps(
            &SocketsResponse::Error { code: SocketError::NoResources {} },
            &mut resp.data,
            &mut resp.caps,
        ).unwrap_or((0, 0));
        resp.len = len;
        resp.cap_count = cap_count;
        let _ = raw::sys_chan_send(client_handle, &resp);
        raw::sys_chan_close(client_handle);
        return;
    };

    // Create per-socket channel pair
    let (sock_a, sock_b) = raw::sys_chan_create();

    // Send Created response with sock_b as the client's end
    let mut resp = Message::new();
    let (len, cap_count) = rvos_wire::to_bytes_with_caps(
        &SocketsResponse::Created { socket: rvos_wire::RawChannelCap::new(sock_b) },
        &mut resp.data,
        &mut resp.caps,
    ).unwrap_or((0, 0));
    resp.len = len;
    resp.cap_count = cap_count;
    let ret = raw::sys_chan_send(client_handle, &resp);

    // Close our reference to sock_b (the send transferred a ref to the client)
    raw::sys_chan_close(sock_b);
    // Close the control channel — client will drop their end too
    raw::sys_chan_close(client_handle);

    if ret == 2 {
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

    // 2. Send GetDeviceInfo request
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&NetRawRequest::GetDeviceInfo {}, &mut msg.data).unwrap_or(0);
    if raw::sys_chan_send_blocking(raw_handle, &msg) != 0 {
        println!("[net-stack] failed to send GetDeviceInfo");
        return;
    }

    // 3. Receive DeviceInfo response (with SHM cap)
    let mut resp = Message::new();
    if raw::sys_chan_recv_blocking(raw_handle, &mut resp) != 0 {
        println!("[net-stack] failed to recv DeviceInfo");
        return;
    }

    let our_mac;
    match rvos_wire::from_bytes::<NetRawResponse>(&resp.data[..resp.len]) {
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
    let shm_cap = if resp.cap_count > 0 { resp.caps[0] } else { NO_CAP };
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
    let mut pending = [const { PendingPacket::new() }; MAX_PENDING];
    let mut pending_clients = [const { PendingClient::new() }; MAX_PENDING_CLIENTS];

    // Pre-populate ARP entry for gateway (QEMU user-net responds to ARP)
    // We'll learn it dynamically from the first ARP reply, but send a
    // gratuitous ARP request to speed things up.
    {
        let mut arp_buf = [0u8; 64];
        let arp_len = send_arp_request(&our_mac, &OUR_IP, &GATEWAY_IP, &mut arp_buf);
        if arp_len > 0 {
            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len]);
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

            let mut frame_buf = [0u8; 1534];
            let copy_len = frame_len.min(1534);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (shm_base + slot_offset + 2) as *const u8,
                    frame_buf.as_mut_ptr(),
                    copy_len,
                );
            }
            shm_write_u32(shm_base, CTRL_RX_TAIL, rx_tail.wrapping_add(1));

            process_frame(
                &frame_buf[..copy_len],
                shm_base,
                raw_handle,
                &our_mac,
                &mut arp_table,
                &mut sockets,
                &mut pending,
                now,
            );
        }

        // b. Poll raw channel for RxReady/TxConsumed doorbells
        loop {
            let mut doorbell = Message::new();
            let ret = raw::sys_chan_recv(raw_handle, &mut doorbell);
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
            let mut ctrl_msg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut ctrl_msg);
            if ret != 0 {
                break;
            }
            handled = true;

            let cap = if ctrl_msg.cap_count > 0 { ctrl_msg.caps[0] } else { NO_CAP };
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
            let mut client_msg = Message::new();
            let ret = raw::sys_chan_recv(pc.handle, &mut client_msg);
            if ret == 2 {
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
            handle_socket_request(h, &mut sockets, &client_msg);
        }

        // d. Poll all active socket channels for SocketRequest messages
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_SOCKETS {
            if !sockets[i].active {
                continue;
            }
            loop {
                let mut client_msg = Message::new();
                let ret = raw::sys_chan_recv(sockets[i].handle, &mut client_msg);
                if ret == 2 {
                    // Channel closed by client — clean up socket
                    handled = true;
                    sockets[i].deactivate();
                    break;
                }
                if ret != 0 {
                    break;
                }
                handled = true;
                handle_client_message(
                    i,
                    &mut sockets,
                    &client_msg,
                    shm_base,
                    raw_handle,
                    &our_mac,
                    &arp_table,
                    &mut pending,
                    now,
                );
            }
        }

        // e. Check pending ARP queue (retry with backoff, expire timed-out entries)
        for p in pending.iter_mut() {
            if p.active {
                handled = true; // Keep looping while we have pending work
                let next_hop = resolve_next_hop(&p.dst_ip);
                if arp_table.lookup(&next_hop, now).is_none()
                    && now.wrapping_sub(p.last_arp) >= ARP_RETRY_INTERVAL
                {
                    p.last_arp = now;
                    let mut arp_buf = [0u8; 64];
                    let arp_len = send_arp_request(&our_mac, &OUR_IP, &next_hop, &mut arp_buf);
                    if arp_len > 0 {
                        tx_frame(shm_base, raw_handle, &arp_buf[..arp_len]);
                    }
                }
            }
        }
        // Try to drain any newly resolved entries (also expires timed-out packets)
        drain_pending(shm_base, raw_handle, &our_mac, &arp_table, &mut pending, now);

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
