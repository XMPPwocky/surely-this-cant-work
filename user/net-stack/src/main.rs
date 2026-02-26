// Pull in the rvos-rt crate so _start gets linked
extern crate rvos_rt;
extern crate alloc;

mod eth;
mod arp;
mod ipv4;
mod udp;
mod tcp;
mod dhcp;

use alloc::boxed::Box;
use alloc::vec::Vec;
use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::net::{NetRawRequest, NetRawResponse};
use rvos_proto::socket::*;

use eth::*;
use arp::*;
use ipv4::*;
use udp::*;
use tcp::*;
use dhcp::dhcp_acquire;

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

pub(crate) const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub(crate) const BROADCAST_IP: [u8; 4] = [255, 255, 255, 255];
pub(crate) const ZERO_IP: [u8; 4] = [0, 0, 0, 0];

/// Fallback static configuration (used when DHCP times out).
const FALLBACK_IP: [u8; 4] = [10, 0, 2, 15];
const FALLBACK_GATEWAY: [u8; 4] = [10, 0, 2, 2];
const FALLBACK_MASK: [u8; 4] = [255, 255, 255, 0];

pub(crate) const TICK_HZ: u64 = 10_000_000; // QEMU virt aclint-mtimer @ 10MHz
pub(crate) const ARP_ENTRY_TTL: u64 = 60 * TICK_HZ; // 60 seconds
pub(crate) const PENDING_TIMEOUT: u64 = 3 * TICK_HZ; // 3 seconds
pub(crate) const ARP_RETRY_INTERVAL: u64 = TICK_HZ; // 1 second between retries
pub(crate) const ARP_HLEN: usize = 28;

pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_TCP: u8 = 6;

pub(crate) const EPHEMERAL_PORT_MIN: u16 = 49152;
pub(crate) const EPHEMERAL_PORT_MAX: u16 = 65535;

const MAX_PENDING: usize = 4;

pub(crate) const MAX_INTERFACES: usize = 4;
pub(crate) const IFACE_LOOPBACK: usize = 0;
pub(crate) const IFACE_ETH0: usize = 1;

/// Runtime network configuration, populated by DHCP or fallback.
pub(crate) struct NetConfig {
    pub(crate) our_ip: [u8; 4],
    pub(crate) gateway: [u8; 4],
    pub(crate) subnet_mask: [u8; 4],
    pub(crate) dns_server: [u8; 4],
}

impl NetConfig {
    pub(crate) fn new_unconfigured() -> Self {
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
    pub(crate) fn resolve_next_hop(&self, dst_ip: &[u8; 4]) -> [u8; 4] {
        if *dst_ip == BROADCAST_IP {
            return BROADCAST_IP;
        }
        // Subnet-directed broadcast (e.g. 10.0.2.255 for /24)
        let is_subnet_bcast = dst_ip.iter().zip(&self.subnet_mask).all(|(&d, &m)| d & !m == !m);
        if is_subnet_bcast {
            return *dst_ip;
        }
        // Off-subnet -> gateway
        let off_subnet = dst_ip.iter().zip(&self.our_ip).zip(&self.subnet_mask)
            .any(|((&d, &o), &m)| (d & m) != (o & m));
        if off_subnet {
            return self.gateway;
        }
        *dst_ip
    }

    /// Check if an IP is a broadcast address.
    pub(crate) fn is_broadcast(&self, ip: &[u8; 4]) -> bool {
        if *ip == BROADCAST_IP {
            return true;
        }
        // Subnet-directed broadcast
        ip.iter().zip(&self.subnet_mask).all(|(&b, &m)| b & !m == !m)
    }
}

/// Heap-allocated scratch buffers for packet TX, avoiding large stack frames.
pub(crate) struct TxScratch {
    pub(crate) frame_buf: [u8; 1534],
    pub(crate) ip_buf: [u8; 1534],
    pub(crate) tcp_buf: [u8; 1500],
    /// Reusable Message buffer for building responses (avoids 1080-byte stack allocs).
    pub(crate) msg: Message,
}

/// Heap-allocated buffers for receiving in the main event loop.
pub(crate) struct RxScratch {
    pub(crate) rx_buf: [u8; 1534],
    pub(crate) doorbell: Message,
    pub(crate) ctrl_msg: Message,
    pub(crate) client_msg: Message,
}

// ---------------------------------------------------------------------------
// Volatile SHM access
// ---------------------------------------------------------------------------

pub(crate) fn shm_read_u32(base: usize, offset: usize) -> u32 {
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

pub(crate) fn shm_write_u32(base: usize, offset: usize, val: u32) {
    unsafe { ((base + offset) as *mut u32).write_volatile(val) }
}

pub(crate) fn shm_read_u16(base: usize, offset: usize) -> u16 {
    unsafe { ((base + offset) as *const u16).read_volatile() }
}

fn shm_write_u16(base: usize, offset: usize, val: u16) {
    unsafe { ((base + offset) as *mut u16).write_volatile(val) }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

pub(crate) fn now_ticks() -> u64 {
    raw::sys_clock().0
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
// Multi-interface support
// ---------------------------------------------------------------------------

pub(crate) struct Interface {
    pub(crate) active: bool,
    pub(crate) name: &'static str,
    pub(crate) mac: [u8; 6],
    pub(crate) config: NetConfig,
    pub(crate) arp_table: ArpTable,
    pub(crate) shm_base: Option<usize>,
    pub(crate) raw_handle: Option<usize>,
    pub(crate) loopback_rx: Vec<Vec<u8>>,
    pending: [PendingPacket; MAX_PENDING],
}

/// Select the outgoing interface for a destination IP.
pub(crate) fn route(interfaces: &[Interface; MAX_INTERFACES], dst_ip: &[u8; 4]) -> usize {
    // 1. Loopback: 127.x.x.x
    if dst_ip[0] == 127 {
        return IFACE_LOOPBACK;
    }
    // 2. Own-IP destinations route through the owning interface (not loopback).
    // send_ip_packet detects self-delivery and pushes to the interface's loopback_rx.
    // This preserves the correct source IP on the packet.

    // 3. Default: first active non-loopback interface
    for (i, iface) in interfaces.iter().enumerate() {
        if iface.active && i != IFACE_LOOPBACK {
            return i;
        }
    }
    IFACE_LOOPBACK // fallback
}

// ---------------------------------------------------------------------------
// TX via SHM ring buffer
// ---------------------------------------------------------------------------

pub(crate) fn tx_frame(shm_base: usize, raw_handle: usize, frame: &[u8], msg: &mut Message) {
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
pub(crate) fn send_ip_packet(
    iface: &mut Interface,
    ip_packet: &[u8],
    dst_ip: &[u8; 4],
    now: u64,
    frame_buf: &mut [u8; 1534],
    msg: &mut Message,
) {
    // Loopback or self-delivery: push raw IP packet directly to loopback RX queue.
    // This handles both the virtual loopback interface (127.x) and own-IP delivery
    // (e.g., connecting to 10.0.2.30 on a host with IP 10.0.2.30).
    if iface.shm_base.is_none() || *dst_ip == iface.config.our_ip {
        iface.loopback_rx.push(ip_packet.to_vec());
        return;
    }
    let shm_base = iface.shm_base.unwrap();
    let raw_handle = iface.raw_handle.unwrap();

    let next_hop = iface.config.resolve_next_hop(dst_ip);

    // Broadcast destinations use broadcast MAC directly (no ARP)
    if iface.config.is_broadcast(&next_hop) {
        let frame_len = build_eth(&BROADCAST_MAC, &iface.mac, ETHERTYPE_IPV4, ip_packet, frame_buf);
        if frame_len > 0 {
            tx_frame(shm_base, raw_handle, &frame_buf[..frame_len], msg);
        }
        return;
    }

    if let Some(dst_mac) = iface.arp_table.lookup(&next_hop, now) {
        // Have MAC -- send immediately
        let frame_len = build_eth(&dst_mac, &iface.mac, ETHERTYPE_IPV4, ip_packet, frame_buf);
        if frame_len > 0 {
            tx_frame(shm_base, raw_handle, &frame_buf[..frame_len], msg);
        }
    } else {
        // Queue packet and send ARP request
        let mut queued = false;
        for p in iface.pending.iter_mut() {
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
        let arp_len = send_arp_request(&iface.mac, &iface.config.our_ip, &next_hop, &mut arp_buf);
        if arp_len > 0 {
            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len], msg);
        }
    }
}

// ---------------------------------------------------------------------------
// Drain pending ARP queue: try to send queued packets whose MAC is now known
// ---------------------------------------------------------------------------

fn drain_pending(
    iface: &mut Interface,
    now: u64,
    frame_buf: &mut [u8; 1534],
    msg: &mut Message,
) {
    // Only hardware interfaces have pending ARP
    let (shm_base, raw_handle) = match (iface.shm_base, iface.raw_handle) {
        (Some(s), Some(r)) => (s, r),
        _ => return,
    };
    for p in iface.pending.iter_mut() {
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
        let next_hop = iface.config.resolve_next_hop(&p.dst_ip);
        if let Some(dst_mac) = iface.arp_table.lookup(&next_hop, now) {
            let frame_len = build_eth(&dst_mac, &iface.mac, ETHERTYPE_IPV4, &p.data, frame_buf);
            if frame_len > 0 {
                tx_frame(shm_base, raw_handle, &frame_buf[..frame_len], msg);
            }
            p.active = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Process a received Ethernet frame (hardware NIC path)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn process_frame(
    frame: &[u8],
    interfaces: &mut [Interface; MAX_INTERFACES],
    rx_iface_idx: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    now: u64,
    tx: &mut TxScratch,
) {
    let (eth, payload) = match parse_eth(frame) {
        Some(e) => e,
        None => return,
    };

    match eth.ethertype {
        ETHERTYPE_ARP => {
            let iface = &mut interfaces[rx_iface_idx];
            let mut reply_buf = [0u8; 64];
            if let Some(reply_len) = handle_arp(&mut iface.arp_table, &iface.mac, &iface.config.our_ip, payload, &mut reply_buf, now) {
                if let (Some(sb), Some(rh)) = (iface.shm_base, iface.raw_handle) {
                    tx_frame(sb, rh, &reply_buf[..reply_len], &mut tx.msg);
                }
            }
            // After learning new MACs, try to drain pending queue
            drain_pending(iface, now, &mut tx.frame_buf, &mut tx.msg);
        }
        ETHERTYPE_IPV4 => {
            let (ip, ip_payload) = match parse_ipv4(payload) {
                Some(i) => i,
                None => return,
            };
            // Learn sender MAC on receiving interface
            interfaces[rx_iface_idx].arp_table.insert(ip.src, eth.src, now);
            process_ip_packet(&ip, ip_payload, interfaces, sockets, tcp_conns, pending_accept, rx_iface_idx, now, tx);
        }
        _ => {} // Ignore other ethertypes
    }
}

// ---------------------------------------------------------------------------
// Process an IP packet (shared by hardware NIC and loopback paths)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn process_ip_packet(
    ip: &IpHdr, ip_payload: &[u8],
    interfaces: &mut [Interface; MAX_INTERFACES],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    rx_iface_idx: usize,
    now: u64,
    tx: &mut TxScratch,
) {
    // Accept packets addressed to any of our interfaces, or broadcast
    let accepted = interfaces.iter().any(|iface| {
        iface.active && (ip.dst == iface.config.our_ip || iface.config.is_broadcast(&ip.dst))
    }) || ip.dst == ZERO_IP;
    if !accepted { return; }

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
                        sock.deactivate(tcp_conns);
                    }
                }
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
            interfaces, rx_iface_idx, now,
            tx,
        );
    }
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
    let mut sockets = [const { Socket::new() }; MAX_SOCKETS];
    let mut next_ephemeral: u16 = EPHEMERAL_PORT_MIN;
    let mut tcp_conns: Box<TcpConns> = {
        let layout = alloc::alloc::Layout::new::<TcpConns>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut TcpConns };
        assert!(!ptr.is_null(), "failed to allocate TcpConns");
        let mut b = unsafe { Box::from_raw(ptr) };
        // alloc_zeroed gives us zero bytes; reinit with proper defaults
        for conn in b.iter_mut() {
            *conn = TcpConn::new();
        }
        b
    };
    let mut pending_accept: Option<PendingAcceptInfo> = None;
    let mut pending_clients = [const { PendingClient::new() }; MAX_PENDING_CLIENTS];

    // Run DHCP to acquire network configuration; fall back to static IPs
    let mut config = NetConfig::new_unconfigured();
    if !dhcp_acquire(shm_base, raw_handle, &our_mac, &mut config, &mut tx, &mut rx) {
        config.apply_fallback();
    }

    // Initialize interfaces array
    let mut interfaces: [Interface; MAX_INTERFACES] = core::array::from_fn(|_| Interface {
        active: false,
        name: "",
        mac: [0; 6],
        config: NetConfig::new_unconfigured(),
        arp_table: ArpTable::new(),
        shm_base: None,
        raw_handle: None,
        loopback_rx: Vec::new(),
        pending: core::array::from_fn(|_| PendingPacket::new()),
    });

    // Interface 0: loopback (127.0.0.1/8)
    interfaces[IFACE_LOOPBACK].active = true;
    interfaces[IFACE_LOOPBACK].name = "lo";
    interfaces[IFACE_LOOPBACK].config.our_ip = [127, 0, 0, 1];
    interfaces[IFACE_LOOPBACK].config.subnet_mask = [255, 0, 0, 0];

    // Interface 1: eth0 (hardware NIC from DHCP)
    interfaces[IFACE_ETH0].active = true;
    interfaces[IFACE_ETH0].name = "eth0";
    interfaces[IFACE_ETH0].mac = our_mac;
    interfaces[IFACE_ETH0].config = config;
    interfaces[IFACE_ETH0].shm_base = Some(shm_base);
    interfaces[IFACE_ETH0].raw_handle = Some(raw_handle);

    // Pre-populate ARP entry for gateway (QEMU user-net responds to ARP)
    // We'll learn it dynamically from the first ARP reply, but send a
    // gratuitous ARP request to speed things up.
    {
        let eth0 = &interfaces[IFACE_ETH0];
        let mut arp_buf = [0u8; 64];
        let arp_len = send_arp_request(&eth0.mac, &eth0.config.our_ip, &eth0.config.gateway, &mut arp_buf);
        if arp_len > 0 {
            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len], &mut tx.msg);
        }
    }

    println!("[net-stack] entering main loop");

    // 6. Main event loop
    loop {
        let mut handled = false;
        let now = now_ticks();

        // Expire stale ARP entries on all interfaces
        for iface in interfaces.iter_mut() {
            if iface.active {
                iface.arp_table.expire(now);
            }
        }

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
            if frame_len > RX_SLOT_SIZE - 2 {
                // Bogus length from device -- skip frame
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
            shm_write_u32(shm_base, CTRL_RX_TAIL, rx_tail.wrapping_add(1));

            process_frame(
                &rx.rx_buf[..copy_len],
                &mut interfaces,
                IFACE_ETH0,
                &mut sockets,
                &mut tcp_conns,
                &mut pending_accept,
                now,
                &mut tx,
            );
        }

        // a2. Drain loopback RX queues on all interfaces.
        // Both the loopback interface (127.x) and hardware interfaces (own-IP
        // self-delivery) can have queued packets.
        for drain_iface in 0..MAX_INTERFACES {
            loop {
                let queue = core::mem::take(&mut interfaces[drain_iface].loopback_rx);
                if queue.is_empty() {
                    break;
                }
                handled = true;
                for pkt in &queue {
                    let (ip, ip_payload) = match parse_ipv4(pkt) {
                        Some(parsed) => parsed,
                        None => continue,
                    };
                    process_ip_packet(
                        &ip, ip_payload,
                        &mut interfaces,
                        &mut sockets,
                        &mut tcp_conns,
                        &mut pending_accept,
                        drain_iface,
                        now,
                        &mut tx,
                    );
                }
            }
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

            // Store as pending client -- will handle SocketsRequest on next poll
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
            handle_socket_request(h, &mut sockets, &rx.client_msg, &interfaces, &mut tx);
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
                    // Channel closed by client -- clean up socket
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
                    &mut interfaces,
                    now,
                    &mut tx,
                    &mut next_ephemeral,
                );
            }
        }

        // e. Check pending ARP queue on eth0 (retry with backoff, expire timed-out entries)
        {
            let eth0 = &mut interfaces[IFACE_ETH0];
            for p in eth0.pending.iter_mut() {
                if p.active {
                    handled = true; // Keep looping while we have pending work
                    let next_hop = eth0.config.resolve_next_hop(&p.dst_ip);
                    if eth0.arp_table.lookup(&next_hop, now).is_none()
                        && now.wrapping_sub(p.last_arp) >= ARP_RETRY_INTERVAL
                    {
                        p.last_arp = now;
                        let mut arp_buf = [0u8; 64];
                        let arp_len = send_arp_request(&eth0.mac, &eth0.config.our_ip, &next_hop, &mut arp_buf);
                        if arp_len > 0 {
                            tx_frame(shm_base, raw_handle, &arp_buf[..arp_len], &mut tx.msg);
                        }
                    }
                }
            }
        }
        // Try to drain any newly resolved entries (also expires timed-out packets)
        drain_pending(&mut interfaces[IFACE_ETH0], now, &mut tx.frame_buf, &mut tx.msg);

        // f. Process pending accept assignments
        if let Some(info) = pending_accept.take() {
            assign_accepted_socket(&mut sockets, &mut tcp_conns, info.handle, info.conn_idx);
            handled = true;
        }

        // g. TCP retransmit timers
        tcp_check_retransmits(&mut tcp_conns, &mut interfaces, now, &mut sockets, &mut tx);

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
