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

rvos_wire::define_protocol! {
    /// GPU request/reply protocol.
    ///
    /// Clients use `GpuClient<T>` for type-safe RPC calls.
    ///
    /// **Note:** `GetDisplayInfo` returns a SHM capability in the message
    /// sideband that is not captured by the generated client. For the initial
    /// `GetDisplayInfo` call, use raw channel recv to extract the SHM cap.
    /// Subsequent `Flush` calls work through the typed client.
    pub protocol Gpu => GpuClient, GpuHandler, gpu_dispatch, gpu_handle {
        type Request = GpuRequest;
        type Response = GpuResponse;

        rpc get_display_info as GetDisplayInfo() -> GpuResponse;
        rpc flush as Flush(x: u32, y: u32, w: u32, h: u32) -> GpuResponse;
    }
}
