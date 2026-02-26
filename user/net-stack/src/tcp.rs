// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

use rvos::raw;
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::socket::*;

use crate::ipv4::build_ipv4;
use crate::udp::build_udp;
use crate::{
    now_ticks, send_ip_packet, route,
    Interface, TxScratch,
    PROTO_TCP, PROTO_UDP, TICK_HZ,
    MAX_INTERFACES, IFACE_ETH0,
    EPHEMERAL_PORT_MIN, EPHEMERAL_PORT_MAX,
};

// ---------------------------------------------------------------------------
// TCP constants
// ---------------------------------------------------------------------------

pub const TCP_HDR_SIZE: usize = 20;
pub const TCP_MSS: u16 = 1460;
pub const TCP_WINDOW: u16 = 4096;
pub const MAX_TCP_CONNS: usize = 16;
pub const TCP_INITIAL_RTO: u64 = TICK_HZ; // 1 second
pub const TCP_MAX_RETX: u8 = 8;
pub const TCP_ACCEPT_BACKLOG: usize = 4;

// TCP flags
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

pub const MAX_SOCKETS: usize = 16;
pub const MAX_PENDING_CLIENTS: usize = 4;

// ---------------------------------------------------------------------------
// TCP header
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)] // all states are part of the TCP FSM even if not all are constructed yet
pub enum TcpState {
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

pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

pub fn parse_tcp(packet: &[u8]) -> Option<(TcpHdr, &[u8])> {
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
pub fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
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
pub fn tcp_checksum_ok(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> bool {
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
pub fn build_tcp(
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

// ---------------------------------------------------------------------------
// TCP connection
// ---------------------------------------------------------------------------

pub struct TcpConn {
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub state: TcpState,
    // Send state
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u16,
    // Receive state
    pub rcv_nxt: u32,
    // Buffers
    pub recv_buf: [u8; 4096],
    pub recv_len: usize,
    pub send_buf: [u8; 4096],
    pub send_len: usize,
    // Retransmission
    pub rto_ticks: u64,
    pub retx_count: u8,
    pub retx_deadline: u64, // 0 = no pending retransmit
    // Owning socket index (None = not yet associated with a socket)
    pub socket_idx: Option<usize>,
    // For listening: index of the listener socket that spawned this conn
    pub listener_sock_idx: Option<usize>,
    pub active: bool,
    // TimeWait deadline
    pub time_wait_deadline: u64,
    // Interface index for routing
    pub iface_idx: usize,
}

impl TcpConn {
    pub const fn new() -> Self {
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
            socket_idx: None,
            listener_sock_idx: None,
            active: false,
            time_wait_deadline: 0,
            iface_idx: 0,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Initial sequence number from clock.
pub fn tcp_initial_seq() -> u32 {
    (now_ticks() & 0xFFFF_FFFF) as u32
}

pub type TcpConns = [TcpConn; MAX_TCP_CONNS];

/// Find a TCP connection matching a 4-tuple.
pub fn tcp_find_conn(conns: &TcpConns, local_port: u16, remote_addr: &[u8; 4], remote_port: u16) -> Option<usize> {
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
pub fn tcp_alloc_conn(conns: &TcpConns) -> Option<usize> {
    conns.iter().position(|c| !c.active)
}

// ---------------------------------------------------------------------------
// Socket table
// ---------------------------------------------------------------------------

pub struct Socket {
    pub port: u16,
    pub handle: usize,
    pub recv_pending: bool,
    pub active: bool,
    pub is_stream: bool,
    // TCP-specific
    pub tcp_conn_idx: Option<usize>,
    pub tcp_listening: bool,
    pub accept_queue: [Option<usize>; TCP_ACCEPT_BACKLOG], // conn indices waiting to be accepted
    pub accept_count: usize,
    pub accept_pending: bool,       // client has called Accept, waiting for connection
    pub recv_max_len: u32,          // for TCP Recv: max bytes to return
}

impl Socket {
    pub const fn new() -> Self {
        Socket {
            port: 0,
            handle: 0,
            recv_pending: false,
            active: false,
            is_stream: false,
            tcp_conn_idx: None,
            tcp_listening: false,
            accept_queue: [None; TCP_ACCEPT_BACKLOG],
            accept_count: 0,
            accept_pending: false,
            recv_max_len: 0,
        }
    }

    /// Clean up a socket whose client channel is dead.
    pub fn deactivate(&mut self, tcp_conns: &mut TcpConns) {
        if self.active {
            raw::sys_chan_close(self.handle);
            // Clean up associated TCP connection
            if let Some(ci) = self.tcp_conn_idx {
                tcp_conns[ci].reset();
            }
            // Clean up accept queue connections
            for i in 0..self.accept_count {
                if let Some(ci) = self.accept_queue[i] {
                    tcp_conns[ci].reset();
                }
            }
            *self = Self::new();
        }
    }
}

/// A pending client that has connected to the sockets control channel
/// but hasn't yet sent a SocketsRequest::Socket message.
pub struct PendingClient {
    pub handle: usize,
    pub active: bool,
}

impl PendingClient {
    pub const fn new() -> Self {
        PendingClient { handle: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// TCP segment sending helpers
// ---------------------------------------------------------------------------

/// Send a TCP segment (helper wrapping build_tcp + build_ipv4 + send_ip_packet).
#[allow(clippy::too_many_arguments)]
pub fn tcp_send_segment(
    src_port: u16, dst_addr: &[u8; 4], dst_port: u16,
    seq: u32, ack: u32, flags: u8, window: u16,
    payload: &[u8],
    iface: &mut Interface, now: u64,
    tx: &mut TxScratch,
) {
    let tcp_len = build_tcp(
        &iface.config.our_ip, dst_addr, src_port, dst_port,
        seq, ack, flags, window, payload, &mut tx.tcp_buf,
    );
    if tcp_len == 0 { return; }
    let ip_len = build_ipv4(&iface.config.our_ip, dst_addr, PROTO_TCP, &tx.tcp_buf[..tcp_len], &mut tx.ip_buf);
    if ip_len == 0 { return; }
    send_ip_packet(iface, &tx.ip_buf[..ip_len], dst_addr, now, &mut tx.frame_buf, &mut tx.msg);
}

/// Send a RST in response to an unexpected segment.
pub fn tcp_send_rst(
    src_ip: &[u8; 4], tcp: &TcpHdr,
    iface: &mut Interface, now: u64,
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
        iface, now,
        tx,
    );
}

/// Deliver buffered data to a client waiting on Recv.
pub fn tcp_try_deliver_recv(sock: &mut Socket, tcp_conns: &mut TcpConns, msg: &mut Message) {
    let Some(ci) = sock.tcp_conn_idx else { return };
    if !sock.recv_pending {
        return;
    }
    let conn = &mut tcp_conns[ci];
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
pub fn tcp_try_send_data(
    conn_idx: usize,
    tcp_conns: &mut TcpConns,
    iface: &mut Interface, now: u64,
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
        iface, now,
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

// ---------------------------------------------------------------------------
// TCP input processing
// ---------------------------------------------------------------------------

/// Process an incoming TCP segment.
#[allow(clippy::too_many_arguments)]
pub fn tcp_input(
    src_ip: &[u8; 4], _dst_ip: &[u8; 4],
    tcp: &TcpHdr, data: &[u8],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    interfaces: &mut [Interface; MAX_INTERFACES],
    rx_iface_idx: usize, now: u64,
    tx: &mut TxScratch,
) {
    // 1. Try to find an existing connection
    if let Some(ci) = tcp_find_conn(tcp_conns, tcp.dst_port, src_ip, tcp.src_port) {
        let iface_idx = tcp_conns[ci].iface_idx;
        tcp_input_conn(
            ci, src_ip, tcp, data,
            sockets, tcp_conns, pending_accept,
            &mut interfaces[iface_idx], now,
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
            tcp_send_rst(src_ip, tcp, &mut interfaces[rx_iface_idx], now, tx);
            return;
        }
        // Check accept backlog
        if sockets[li].accept_count >= TCP_ACCEPT_BACKLOG {
            tcp_send_rst(src_ip, tcp, &mut interfaces[rx_iface_idx], now, tx);
            return;
        }
        // Allocate a connection
        let Some(ci) = tcp_alloc_conn(tcp_conns) else {
            tcp_send_rst(src_ip, tcp, &mut interfaces[rx_iface_idx], now, tx);
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
        conn.socket_idx = None; // not yet associated with a socket
        conn.listener_sock_idx = Some(li);
        conn.iface_idx = rx_iface_idx;
        conn.rto_ticks = TCP_INITIAL_RTO;
        conn.retx_count = 0;
        conn.retx_deadline = now + conn.rto_ticks;
        // Send SYN-ACK
        tcp_send_segment(
            conn.local_port, &conn.remote_addr, conn.remote_port,
            conn.snd_una, conn.rcv_nxt, TCP_SYN | TCP_ACK, TCP_WINDOW, &[],
            &mut interfaces[rx_iface_idx], now,
            tx,
        );
        return;
    }

    // 3. No match -- send RST
    if tcp.flags & TCP_RST == 0 {
        tcp_send_rst(src_ip, tcp, &mut interfaces[rx_iface_idx], now, tx);
    }
}

/// Process TCP input for an existing connection.
#[allow(clippy::too_many_arguments)]
pub fn tcp_input_conn(
    ci: usize,
    src_ip: &[u8; 4],
    tcp: &TcpHdr, data: &[u8],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    iface: &mut Interface, now: u64,
    tx: &mut TxScratch,
) {
    // Handle RST
    if tcp.flags & TCP_RST != 0 {
        let conn = &mut tcp_conns[ci];
        let si = conn.socket_idx;
        conn.reset();
        if let Some(si) = si {
            if sockets[si].active {
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
                    tcp_send_rst(src_ip, tcp, iface, now, tx);
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
                    iface, now,
                    tx,
                );
                // Notify waiting Connect call
                if let Some(si) = conn.socket_idx {
                    let sock = &mut sockets[si];
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
                // RFC 793: the handshake ACK may carry data -- buffer it
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
                        iface, now,
                        tx,
                    );
                }
                // Add to listener's accept queue
                if let Some(li) = conn.listener_sock_idx {
                    if sockets[li].active && sockets[li].accept_count < TCP_ACCEPT_BACKLOG {
                        let cnt = sockets[li].accept_count;
                        sockets[li].accept_queue[cnt] = Some(ci);
                        sockets[li].accept_count += 1;
                        // If Accept is pending, deliver now
                        if sockets[li].accept_pending {
                            tcp_deliver_accept(
                                &mut sockets[li], tcp_conns, pending_accept,
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
        }
        TcpState::Established => {
            tcp_input_established(ci, tcp, data, sockets, tcp_conns, iface, now, tx);
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
                        iface, now,
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
                    iface, now,
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
                    iface, now,
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
                conn.reset();
                // Don't deactivate socket -- let client close the channel
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
                    iface, now,
                    tx,
                );
            }
        }
        _ => {}
    }
}

/// Process TCP data in Established state.
#[allow(clippy::too_many_arguments)]
pub fn tcp_input_established(
    ci: usize,
    tcp: &TcpHdr, data: &[u8],
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    iface: &mut Interface, now: u64,
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
            iface, now,
            tx,
        );
        // Try to deliver data to waiting client
        if let Some(si) = conn.socket_idx {
            tcp_try_deliver_recv(&mut sockets[si], tcp_conns, &mut tx.msg);
        }
    } else if !data.is_empty() {
        // Out-of-order: send duplicate ACK (will cause retransmit on sender side)
        tcp_send_segment(
            conn.local_port, &conn.remote_addr, conn.remote_port,
            conn.snd_nxt, conn.rcv_nxt, TCP_ACK, TCP_WINDOW, &[],
            iface, now,
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
            iface, now,
            tx,
        );
        // If client is waiting on Recv, deliver EOF
        if let Some(si) = conn.socket_idx {
            tcp_try_deliver_recv(&mut sockets[si], tcp_conns, &mut tx.msg);
        }
    }

    // Try to send more data if window opened up
    if tcp_conns[ci].send_len > 0 {
        tcp_try_send_data(ci, tcp_conns, iface, now, tx);
    }
}

/// Process an ACK: advance snd_una, remove acked data from send buffer.
pub fn tcp_process_ack(ci: usize, tcp_conns: &mut TcpConns, ack_num: u32) {
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
pub fn tcp_deliver_accept(
    sock: &mut Socket,
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    tx: &mut TxScratch,
) {
    if !sock.accept_pending || sock.accept_count == 0 {
        return;
    }
    // Pop the first connection from the accept queue
    let ci = sock.accept_queue[0].expect("accept_queue entry should be Some");
    for j in 1..sock.accept_count {
        sock.accept_queue[j - 1] = sock.accept_queue[j];
    }
    sock.accept_count -= 1;
    sock.accept_queue[sock.accept_count] = None;

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
    // socket_idx will be set by assign_accepted_socket after this returns
    *pending_accept = Some(PendingAcceptInfo {
        handle: sock_a,
        conn_idx: ci,
    });
}

pub struct PendingAcceptInfo {
    pub handle: usize,
    pub conn_idx: usize,
}

/// Check retransmit timers for all active TCP connections.
#[allow(clippy::too_many_arguments)]
pub fn tcp_check_retransmits(
    tcp_conns: &mut TcpConns,
    interfaces: &mut [Interface; MAX_INTERFACES], now: u64,
    sockets: &mut [Socket; MAX_SOCKETS],
    tx: &mut TxScratch,
) {
    for conn in tcp_conns.iter_mut() {
        if !conn.active || conn.retx_deadline == 0 || now < conn.retx_deadline {
            continue;
        }
        conn.retx_count += 1;
        if conn.retx_count > TCP_MAX_RETX {
            // Too many retransmits -- abort connection
            let si = conn.socket_idx;
            conn.reset();
            if let Some(si) = si {
                if sockets[si].active {
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
            }
            continue;
        }
        // Exponential backoff
        conn.rto_ticks = conn.rto_ticks.saturating_mul(2).min(60 * TICK_HZ);
        conn.retx_deadline = now + conn.rto_ticks;

        // Copy fields needed for tcp_send_segment (avoid borrow conflict)
        let local_port = conn.local_port;
        let remote_addr = conn.remote_addr;
        let remote_port = conn.remote_port;
        let snd_una = conn.snd_una;
        let snd_nxt = conn.snd_nxt;
        let rcv_nxt = conn.rcv_nxt;
        let iface_idx = conn.iface_idx;

        match conn.state {
            TcpState::SynSent => {
                // Retransmit SYN
                tcp_send_segment(
                    local_port, &remote_addr, remote_port,
                    snd_una, 0, TCP_SYN, TCP_WINDOW, &[],
                    &mut interfaces[iface_idx], now, tx,
                );
            }
            TcpState::SynReceived => {
                // Retransmit SYN-ACK
                tcp_send_segment(
                    local_port, &remote_addr, remote_port,
                    snd_una, rcv_nxt, TCP_SYN | TCP_ACK, TCP_WINDOW, &[],
                    &mut interfaces[iface_idx], now, tx,
                );
            }
            TcpState::Established | TcpState::CloseWait => {
                // Retransmit unacked data
                let unacked_len = snd_nxt.wrapping_sub(snd_una) as usize;
                if unacked_len > 0 && unacked_len <= conn.send_len {
                    let send_len = unacked_len.min(TCP_MSS as usize);
                    tcp_send_segment(
                        local_port, &remote_addr, remote_port,
                        snd_una, rcv_nxt, TCP_ACK, TCP_WINDOW,
                        &conn.send_buf[..send_len],
                        &mut interfaces[iface_idx], now, tx,
                    );
                }
            }
            TcpState::FinWait1 | TcpState::LastAck => {
                // Retransmit FIN
                tcp_send_segment(
                    local_port, &remote_addr, remote_port,
                    snd_nxt.wrapping_sub(1), rcv_nxt,
                    TCP_FIN | TCP_ACK, TCP_WINDOW, &[],
                    &mut interfaces[iface_idx], now, tx,
                );
            }
            _ => {
                conn.retx_deadline = 0;
            }
        }
    }
}

/// Clean up TimeWait connections that have expired.
pub fn tcp_check_timewait(tcp_conns: &mut TcpConns, now: u64) {
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
pub fn send_sock_ok(handle: usize, msg: &mut Message) -> bool {
    *msg = Message::new();
    msg.len = rvos_wire::to_bytes(&SocketResponse::Ok {}, &mut msg.data).expect("serialize");
    raw::sys_chan_send(handle, msg) != raw::CHAN_CLOSED
}

/// Send a SocketResponse::Error on a handle. Returns false if channel closed.
pub fn send_sock_error(handle: usize, code: SocketError, msg: &mut Message) -> bool {
    *msg = Message::new();
    msg.len = rvos_wire::to_bytes(&SocketResponse::Error { code }, &mut msg.data).expect("serialize");
    raw::sys_chan_send(handle, msg) != raw::CHAN_CLOSED
}

/// Allocate an ephemeral port (EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX) that isn't in use.
pub fn alloc_ephemeral_port(sockets: &[Socket; MAX_SOCKETS], next_ephemeral: &mut u16) -> u16 {
    for _ in 0..1000 {
        let p = *next_ephemeral;
        *next_ephemeral = if p >= EPHEMERAL_PORT_MAX - 1 { EPHEMERAL_PORT_MIN } else { p + 1 };
        if !sockets.iter().any(|s| s.active && s.port == p) {
            return p;
        }
    }
    0 // shouldn't happen with 16K range and 16 sockets
}

/// Assign a newly accepted socket to a free slot.
pub fn assign_accepted_socket(sockets: &mut [Socket; MAX_SOCKETS], tcp_conns: &mut TcpConns, handle: usize, conn_idx: usize) {
    let free = sockets.iter().position(|s| !s.active);
    let Some(idx) = free else {
        raw::sys_chan_close(handle);
        tcp_conns[conn_idx].reset();
        return;
    };
    sockets[idx].active = true;
    sockets[idx].handle = handle;
    sockets[idx].is_stream = true;
    sockets[idx].tcp_conn_idx = Some(conn_idx);
    tcp_conns[conn_idx].socket_idx = Some(idx);
    sockets[idx].port = tcp_conns[conn_idx].local_port;
}

/// Allocate an ephemeral port (EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX) not currently in use.
pub fn allocate_ephemeral_port(sockets: &[Socket; MAX_SOCKETS]) -> Option<u16> {
    (EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX).find(|&port| !sockets.iter().any(|s| s.active && s.port == port))
}

#[allow(clippy::too_many_arguments)] // inherent complexity of passing service state
pub fn handle_client_message(
    sock_idx: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    tcp_conns: &mut TcpConns,
    pending_accept: &mut Option<PendingAcceptInfo>,
    msg: &Message,
    interfaces: &mut [Interface; MAX_INTERFACES],
    now: u64,
    tx: &mut TxScratch,
    next_ephemeral: &mut u16,
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

            // Route the packet to the correct interface
            let iface_idx = route(interfaces, &dst_ip);
            let src_ip = interfaces[iface_idx].config.our_ip;

            // Build UDP payload
            let mut udp_buf = [0u8; 1480];
            let udp_len = build_udp(&src_ip, &dst_ip, src_port, dst_port, data, &mut udp_buf);
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
            let ip_len = build_ipv4(&src_ip, &dst_ip, PROTO_UDP, &udp_buf[..udp_len], &mut tx.ip_buf);
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
                &mut interfaces[iface_idx],
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
            let our_ip = interfaces[IFACE_ETH0].config.our_ip;
            tx.msg = Message::new();
            tx.msg.len = rvos_wire::to_bytes(
                &SocketResponse::Addr {
                    addr: SocketAddr::Inet4 {
                        a: our_ip[0], b: our_ip[1],
                        c: our_ip[2], d: our_ip[3],
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
                // Connection already waiting -- deliver immediately
                tcp_deliver_accept(
                    &mut sockets[sock_idx], tcp_conns, pending_accept, tx,
                );
                // Process pending accept assignment
                if let Some(info) = pending_accept.take() {
                    assign_accepted_socket(sockets, tcp_conns, info.handle, info.conn_idx);
                }
            } else {
                // No connections waiting -- mark as pending
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
                let p = alloc_ephemeral_port(sockets, next_ephemeral);
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
            conn.socket_idx = Some(sock_idx);
            conn.rto_ticks = TCP_INITIAL_RTO;
            conn.retx_count = 0;
            conn.retx_deadline = now + conn.rto_ticks;
            conn.iface_idx = route(interfaces, &dst_ip);
            sockets[sock_idx].tcp_conn_idx = Some(ci);
            // Send SYN
            let snd_una = conn.snd_una;
            let iface_idx = conn.iface_idx;
            tcp_send_segment(
                src_port, &dst_ip, port,
                snd_una, 0, TCP_SYN, TCP_WINDOW, &[],
                &mut interfaces[iface_idx], now, tx,
            );
            // Response is deferred until SYN-ACK arrives
        }
        SocketRequest::Send { data } => {
            let Some(ci) = sockets[sock_idx].tcp_conn_idx else {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            };
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
            let iface_idx = tcp_conns[ci].iface_idx;
            tcp_try_send_data(ci, tcp_conns, &mut interfaces[iface_idx], now, tx);
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
            let Some(_ci) = sockets[sock_idx].tcp_conn_idx else {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            };
            sockets[sock_idx].recv_max_len = max_len;
            sockets[sock_idx].recv_pending = true;
            // Try to deliver immediately if data is available
            tcp_try_deliver_recv(&mut sockets[sock_idx], tcp_conns, &mut tx.msg);
        }
        SocketRequest::Shutdown { how } => {
            let Some(ci) = sockets[sock_idx].tcp_conn_idx else {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            };
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
                let local_port = conn.local_port;
                let remote_addr = conn.remote_addr;
                let remote_port = conn.remote_port;
                let snd_nxt = conn.snd_nxt;
                let rcv_nxt = conn.rcv_nxt;
                let iface_idx = conn.iface_idx;
                tcp_send_segment(
                    local_port, &remote_addr, remote_port,
                    snd_nxt, rcv_nxt, TCP_FIN | TCP_ACK, TCP_WINDOW, &[],
                    &mut interfaces[iface_idx], now, tx,
                );
                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                conn.retx_deadline = now + conn.rto_ticks;
            }
            send_sock_ok(handle, &mut tx.msg);
        }
        SocketRequest::GetPeerName {} => {
            let Some(ci) = sockets[sock_idx].tcp_conn_idx else {
                send_sock_error(handle, SocketError::NotConnected {}, &mut tx.msg);
                return;
            };
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
pub fn handle_socket_request(
    client_handle: usize,
    sockets: &mut [Socket; MAX_SOCKETS],
    msg: &Message,
    interfaces: &[Interface; MAX_INTERFACES],
    tx: &mut TxScratch,
) {
    let req = match rvos_wire::from_bytes::<SocketsRequest>(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => {
            raw::sys_chan_close(client_handle);
            return;
        }
    };

    // Handle GetConfig -- reply with current network configuration and close
    if matches!(req, SocketsRequest::GetConfig {}) {
        let config = &interfaces[IFACE_ETH0].config;
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
        // No free slots -- send error
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
    // Close the control channel -- client will drop their end too
    raw::sys_chan_close(client_handle);

    if ret == raw::CHAN_CLOSED {
        // Client already gone -- clean up sock_a
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
