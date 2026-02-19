//! Socket service protocols.
//!
//! Two protocol layers:
//! - **Sockets control protocol** (`SocketsRequest`/`SocketsResponse`): between
//!   user programs and the net-stack service. Creates per-socket channels.
//! - **Socket per-socket protocol** (`SocketRequest`/`SocketResponse`): operations
//!   on individual sockets (bind, send, recv, connect, accept, etc.).

use rvos_wire::define_message;

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
