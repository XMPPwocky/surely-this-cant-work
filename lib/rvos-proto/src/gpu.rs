//! GPU server protocol.
//!
//! The GPU server is a kernel task wrapping VirtIO GPU. A single client
//! (the window server) connects via service discovery and uses this protocol
//! to query display info and flush framebuffer regions.
//!
//! See docs/protocols/gpu.md for the full spec.

use rvos_wire::define_message;

define_message! {
    /// GPU requests (client → server).
    pub enum GpuRequest {
        /// Query display dimensions, format, and get the framebuffer SHM handle.
        GetDisplayInfo(0) {},
        /// Flush a rectangular region of the framebuffer to the display.
        Flush(1) { x: u32, y: u32, w: u32, h: u32 },
    }
}

define_message! {
    /// GPU responses (server → client).
    pub enum GpuResponse {
        /// Display info: dimensions, stride, pixel format. Cap = SHM handle.
        DisplayInfo(0) { width: u32, height: u32, stride: u32, format: u8 },
        /// Flush acknowledgment.
        FlushOk(1) {},
    }
}
