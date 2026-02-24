//! Socket client API — Result-based wrappers over the socket wire protocol.
//!
//! Provides `UdpSocket`, `TcpListener`, and `TcpStream` types that hide
//! the two-layer channel protocol behind a familiar Berkeley-style API.

use crate::channel::Channel;
use rvos_proto::socket::*;

/// Re-export socket types for convenience.
pub use rvos_proto::socket::{SocketAddr, SocketError, ShutdownHow};

/// Network configuration returned by `get_net_config()`.
pub struct NetConfigInfo {
    pub ip: [u8; 4],
    pub gateway: [u8; 4],
    pub mask: [u8; 4],
    pub dns: [u8; 4],
}

/// Query the net-stack for the current network configuration.
pub fn get_net_config() -> Result<NetConfigInfo, SocketError> {
    let svc = crate::service::connect_to_service("net")
        .map_err(|_| SocketError::NoResources {})?;
    let mut ch: Channel<SocketsRequest, SocketsResponse> =
        Channel::from_raw_handle(svc.into_raw_handle());

    ch.send(&SocketsRequest::GetConfig {})
        .map_err(|_| SocketError::NoResources {})?;
    let resp = ch.recv_blocking()
        .map_err(|_| SocketError::NoResources {})?;

    match resp {
        SocketsResponse::Config {
            ip_a, ip_b, ip_c, ip_d,
            gw_a, gw_b, gw_c, gw_d,
            mask_a, mask_b, mask_c, mask_d,
            dns_a, dns_b, dns_c, dns_d,
        } => Ok(NetConfigInfo {
            ip: [ip_a, ip_b, ip_c, ip_d],
            gateway: [gw_a, gw_b, gw_c, gw_d],
            mask: [mask_a, mask_b, mask_c, mask_d],
            dns: [dns_a, dns_b, dns_c, dns_d],
        }),
        _ => Err(SocketError::NoResources {}),
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Connect to the "net" service and request a socket of the given type.
/// Returns the per-socket raw channel handle.
fn create_socket(sock_type: SocketType) -> Result<usize, SocketError> {
    let svc = crate::service::connect_to_service("net")
        .map_err(|_| SocketError::NoResources {})?;
    let mut ch: Channel<SocketsRequest, SocketsResponse> =
        Channel::from_raw_handle(svc.into_raw_handle());

    ch.send(&SocketsRequest::Socket { sock_type })
        .map_err(|_| SocketError::NoResources {})?;
    let resp = ch.recv_blocking()
        .map_err(|_| SocketError::NoResources {})?;

    match resp {
        SocketsResponse::Created { socket } => Ok(socket.raw()),
        SocketsResponse::Error { code } => Err(code),
        _ => Err(SocketError::NoResources {}),
    }
    // ch drops here, closing the control channel
}

/// Helper: send a request, receive a SocketResponse.
fn sock_rpc(ch: &mut Channel<SocketRequestMsg, SocketResponse>, req: &SocketRequest<'_>) -> Result<SocketResponse, SocketError> {
    ch.send(req).map_err(|_| SocketError::NoResources {})?;
    ch.recv_blocking().map_err(|_| SocketError::NoResources {})
}

// ── UdpSocket ───────────────────────────────────────────────────

/// A UDP socket.
pub struct UdpSocket {
    ch: Channel<SocketRequestMsg, SocketResponse>,
    /// Raw handle for receiving SocketData messages via raw syscalls.
    /// Same handle as `ch` — not separately owned.
    data_handle: usize,
}

impl UdpSocket {
    /// Create an unbound UDP socket.
    pub fn new() -> Result<Self, SocketError> {
        let handle = create_socket(SocketType::Dgram {})?;
        let ch = Channel::from_raw_handle(handle);
        Ok(UdpSocket { ch, data_handle: handle })
    }

    /// Create a UDP socket and bind it to the given address.
    pub fn bind(addr: SocketAddr) -> Result<Self, SocketError> {
        let mut sock = Self::new()?;
        match sock_rpc(&mut sock.ch, &SocketRequest::Bind { addr })? {
            SocketResponse::Ok {} => Ok(sock),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Send a datagram to the specified address.
    pub fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> Result<usize, SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::SendTo { addr, data })? {
            SocketResponse::Sent { bytes } => Ok(bytes as usize),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Receive a datagram. Blocks until one arrives.
    /// Returns (bytes_read, sender_address).
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), SocketError> {
        // Send RecvFrom request
        self.ch.send(&SocketRequest::RecvFrom {})
            .map_err(|_| SocketError::NoResources {})?;
        // Response is a SocketData message (not SocketResponse)
        let mut msg = crate::Message::boxed();
        let ret = crate::raw::sys_chan_recv_blocking(self.data_handle, &mut msg);
        if ret != 0 {
            return Err(SocketError::NoResources {});
        }
        let data_resp = rvos_wire::from_bytes::<SocketData<'_>>(&msg.data[..msg.len])
            .map_err(|_| SocketError::InvalidArg {})?;
        match data_resp {
            SocketData::Datagram { addr, data } => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok((len, addr))
            }
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Get the local address this socket is bound to.
    pub fn local_addr(&mut self) -> Result<SocketAddr, SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::GetSockName {})? {
            SocketResponse::Addr { addr } => Ok(addr),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }
}

// ── TcpListener ─────────────────────────────────────────────────

/// A TCP listener socket.
pub struct TcpListener {
    ch: Channel<SocketRequestMsg, SocketResponse>,
}

impl TcpListener {
    /// Create a TCP listener bound to the given address and listening.
    pub fn bind(addr: SocketAddr) -> Result<Self, SocketError> {
        let handle = create_socket(SocketType::Stream {})?;
        let mut ch: Channel<SocketRequestMsg, SocketResponse> =
            Channel::from_raw_handle(handle);

        // Bind
        match sock_rpc(&mut ch, &SocketRequest::Bind { addr })? {
            SocketResponse::Ok {} => {}
            SocketResponse::Error { code } => return Err(code),
            _ => return Err(SocketError::InvalidArg {}),
        }

        // Listen
        match sock_rpc(&mut ch, &SocketRequest::Listen { backlog: 4 })? {
            SocketResponse::Ok {} => {}
            SocketResponse::Error { code } => return Err(code),
            _ => return Err(SocketError::InvalidArg {}),
        }

        Ok(TcpListener { ch })
    }

    /// Accept a connection. Blocks until one arrives.
    /// Returns (TcpStream, peer_address).
    pub fn accept(&mut self) -> Result<(TcpStream, SocketAddr), SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::Accept {})? {
            SocketResponse::Accepted { peer_addr, socket } => {
                let handle = socket.raw();
                let ch = Channel::from_raw_handle(handle);
                Ok((TcpStream { ch, data_handle: handle }, peer_addr))
            }
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&mut self) -> Result<SocketAddr, SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::GetSockName {})? {
            SocketResponse::Addr { addr } => Ok(addr),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }
}

// ── TcpStream ───────────────────────────────────────────────────

/// A TCP stream (connected socket).
pub struct TcpStream {
    ch: Channel<SocketRequestMsg, SocketResponse>,
    data_handle: usize,
}

impl TcpStream {
    /// Connect to a remote address.
    pub fn connect(addr: SocketAddr) -> Result<Self, SocketError> {
        let handle = create_socket(SocketType::Stream {})?;
        let mut ch: Channel<SocketRequestMsg, SocketResponse> =
            Channel::from_raw_handle(handle);

        match sock_rpc(&mut ch, &SocketRequest::Connect { addr })? {
            SocketResponse::Ok {} => Ok(TcpStream { ch, data_handle: handle }),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Send data. Returns the number of bytes sent.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::Send { data })? {
            SocketResponse::Sent { bytes } => Ok(bytes as usize),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Receive data. Blocks until data is available.
    /// Returns the number of bytes read.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, SocketError> {
        let max_len = buf.len().min(u32::MAX as usize) as u32;
        self.ch.send(&SocketRequest::Recv { max_len })
            .map_err(|_| SocketError::NoResources {})?;
        // Response is a SocketData::Data message
        let mut msg = crate::Message::boxed();
        let ret = crate::raw::sys_chan_recv_blocking(self.data_handle, &mut msg);
        if ret != 0 {
            return Err(SocketError::NoResources {});
        }
        let data_resp = rvos_wire::from_bytes::<SocketData<'_>>(&msg.data[..msg.len])
            .map_err(|_| SocketError::InvalidArg {})?;
        match data_resp {
            SocketData::Data { data } => {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            }
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Shutdown part of the connection.
    pub fn shutdown(&mut self, how: ShutdownHow) -> Result<(), SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::Shutdown { how })? {
            SocketResponse::Ok {} => Ok(()),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Get the remote address.
    pub fn peer_addr(&mut self) -> Result<SocketAddr, SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::GetPeerName {})? {
            SocketResponse::Addr { addr } => Ok(addr),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }

    /// Get the local address.
    pub fn local_addr(&mut self) -> Result<SocketAddr, SocketError> {
        match sock_rpc(&mut self.ch, &SocketRequest::GetSockName {})? {
            SocketResponse::Addr { addr } => Ok(addr),
            SocketResponse::Error { code } => Err(code),
            _ => Err(SocketError::InvalidArg {}),
        }
    }
}
