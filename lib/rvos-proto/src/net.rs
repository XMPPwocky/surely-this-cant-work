//! Raw frame protocol between the kernel net-server and userspace net-stack.
//!
//! Frames are exchanged via a SHM ring buffer; IPC messages serve as doorbells.
//! The higher-level socket protocol is in `socket.rs`.

use rvos_wire::define_message;

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
