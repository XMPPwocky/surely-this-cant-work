//! Socket service protocols.
//!
//! Two protocol layers:
//! - **Sockets control protocol** (`SocketsRequest`/`SocketsResponse`): between
//!   user programs and the net-stack service. Creates per-socket channels.
//! - **Socket per-socket protocol** (`SocketRequest`/`SocketResponse`/`SocketData`):
//!   operations on individual sockets (bind, send, recv, connect, accept, etc.).
//!
//! The per-socket protocol uses two response types: `SocketResponse` (owned, may
//! carry caps) for control responses, and `SocketData` (borrowed, zero-copy) for
//! data delivery. The response type depends on the request:
//! - `RecvFrom` → `SocketData::Datagram`
//! - `Recv` → `SocketData::Data`
//! - `Accept` → `SocketResponse::Accepted`
//! - All others → `SocketResponse::Ok` or `SocketResponse::Error`
//!
//! Closing a per-socket channel implicitly closes the socket (RAII).

use rvos_wire::{define_message, define_protocol, RawChannelCap};

// ── Error codes ─────────────────────────────────────────────────

define_message! {
    /// Socket error codes.
    pub enum SocketError {
        AddrInUse(1) {},
        AddrNotAvail(2) {},
        ConnRefused(3) {},
        ConnReset(4) {},
        NotConnected(5) {},
        AlreadyConnected(6) {},
        InvalidArg(7) {},
        TimedOut(8) {},
        NoResources(9) {},
        NotSupported(10) {},
    }
}

// ── Shared types ────────────────────────────────────────────────

define_message! {
    /// Socket type selector.
    pub enum SocketType {
        Dgram(0) {},
        Stream(1) {},
    }
}

define_message! {
    /// Socket address.
    pub enum SocketAddr {
        Inet4(0) { a: u8, b: u8, c: u8, d: u8, port: u16 },
    }
}

define_message! {
    /// Shutdown direction.
    pub enum ShutdownHow {
        Read(0) {},
        Write(1) {},
        Both(2) {},
    }
}

// ── Sockets control protocol (service → per-socket channels) ────

define_message! {
    /// Requests on the sockets control channel.
    pub enum SocketsRequest {
        /// Create a new socket of the given type.
        Socket(0) { sock_type: SocketType },
        /// Get current network configuration (IP, gateway, mask, DNS).
        GetConfig(1) {},
    }
}

define_message! {
    /// Responses on the sockets control channel.
    pub owned enum SocketsResponse {
        /// Socket created — carries the per-socket channel capability.
        Created(0) { socket: RawChannelCap },
        /// Error creating socket.
        Error(1) { code: SocketError },
        /// Network configuration.
        Config(2) {
            ip_a: u8, ip_b: u8, ip_c: u8, ip_d: u8,
            gw_a: u8, gw_b: u8, gw_c: u8, gw_d: u8,
            mask_a: u8, mask_b: u8, mask_c: u8, mask_d: u8,
            dns_a: u8, dns_b: u8, dns_c: u8, dns_d: u8,
        },
    }
}

define_protocol! {
    /// Sockets control protocol (creates per-socket channels).
    pub protocol Sockets =>
        SocketsClient, SocketsHandler, sockets_dispatch, sockets_handle
    {
        type Request = SocketsRequest;
        type Response = SocketsResponse;

        /// Create a new socket.
        rpc socket as Socket(sock_type: SocketType) -> SocketsResponse;

        /// Get current network configuration.
        rpc get_config as GetConfig() -> SocketsResponse;
    }
}

// ── Socket per-socket protocol (operations on individual sockets) ──

define_message! {
    /// Requests on a per-socket channel.
    pub enum SocketRequest<'a> => SocketRequestMsg {
        /// Bind to a local address.
        Bind(0)         { addr: SocketAddr },
        /// Start listening for connections (stream sockets).
        Listen(1)       { backlog: u32 },
        /// Accept a connection (stream sockets, blocks until one arrives).
        Accept(2)       {},
        /// Connect to a remote address.
        Connect(3)      { addr: SocketAddr },
        /// Send data (connected stream sockets).
        Send(4)         { data: &'a [u8] },
        /// Receive data (connected stream sockets).
        Recv(5)         { max_len: u32 },
        /// Send data to a specific address (datagram sockets).
        SendTo(6)       { addr: SocketAddr, data: &'a [u8] },
        /// Receive data with sender address (datagram sockets).
        RecvFrom(7)     {},
        /// Shutdown part of the connection.
        Shutdown(8)     { how: ShutdownHow },
        /// Get local address.
        GetSockName(9)  {},
        /// Get remote address.
        GetPeerName(10) {},
    }
}

define_message! {
    /// Control responses on a per-socket channel (owned — may carry caps).
    pub owned enum SocketResponse {
        /// Generic success.
        Ok(0)       {},
        /// Error.
        Error(1)    { code: SocketError },
        /// Accepted connection (Accept response).
        Accepted(2) { peer_addr: SocketAddr, socket: RawChannelCap },
        /// Address result (GetSockName / GetPeerName).
        Addr(3)     { addr: SocketAddr },
        /// Send succeeded with byte count.
        Sent(4)     { bytes: u32 },
    }
}

define_message! {
    /// Data responses on a per-socket channel (borrowed — zero-copy).
    pub enum SocketData<'a> => SocketDataMsg {
        /// Received data (Recv on stream sockets).
        Data(0)     { data: &'a [u8] },
        /// Received datagram (RecvFrom on datagram sockets).
        Datagram(1) { addr: SocketAddr, data: &'a [u8] },
    }
}
