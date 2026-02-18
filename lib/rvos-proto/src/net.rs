//! Network service protocols.
//!
//! Two protocol layers:
//! - **Raw frame protocol** (`NetRawRequest`/`NetRawResponse`): between the
//!   kernel net-server and the userspace net-stack. Frames are exchanged via
//!   a SHM ring buffer; IPC messages serve as doorbells.
//! - **UDP socket protocol** (`NetRequest`/`NetResponse`): between the
//!   userspace net-stack and application programs (e.g., udp-echo).

use rvos_wire::define_message;

// ── Raw frame protocol (net-server ↔ net-stack) ─────────────────

define_message! {
    /// Requests from net-stack to net-server.
    pub enum NetRawRequest {
        /// Request device info (MAC, MTU) and the SHM ring buffer handle.
        GetDeviceInfo(0) {},
        /// Doorbell: net-stack has written new TX frames to the SHM ring.
        TxReady(1) {},
        /// Doorbell: net-stack has consumed RX frames from the SHM ring.
        RxConsumed(2) {},
    }
}

define_message! {
    /// Responses from net-server to net-stack.
    pub owned enum NetRawResponse {
        /// Device info. The SHM ring buffer handle is sent as a cap in the
        /// message sideband (cap index 0).
        DeviceInfo(0) {
            mac0: u8, mac1: u8, mac2: u8, mac3: u8, mac4: u8, mac5: u8,
            mtu: u16,
        },
        /// Doorbell: new RX frames are available in the SHM ring.
        RxReady(1) {},
        /// Doorbell: TX frames have been consumed from the SHM ring.
        TxConsumed(2) {},
    }
}

// ── UDP socket protocol (net-stack ↔ user programs) ─────────────

define_message! {
    /// Requests from user programs to net-stack.
    pub enum NetRequest<'a> => NetRequestMsg {
        /// Bind a UDP socket to a local port.
        Bind(0) { port: u16 },
        /// Send a UDP datagram.
        SendTo(1) {
            dst_ip0: u8, dst_ip1: u8, dst_ip2: u8, dst_ip3: u8,
            dst_port: u16,
            data: &'a [u8],
        },
        /// Receive a UDP datagram (blocks until one arrives).
        RecvFrom(2) {},
        /// Close the socket.
        Close(3) {},
    }
}

define_message! {
    /// Responses from net-stack to user programs.
    pub enum NetResponse<'a> => NetResponseMsg {
        /// Generic success.
        Ok(0) {},
        /// Error with a human-readable message.
        Error(1) { message: &'a str },
        /// A received UDP datagram.
        Datagram(2) {
            src_ip0: u8, src_ip1: u8, src_ip2: u8, src_ip3: u8,
            src_port: u16,
            data: &'a [u8],
        },
        /// Send completed successfully.
        SendOk(3) {},
    }
}
