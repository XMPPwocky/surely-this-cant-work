//! Window manager protocol.
//!
//! The window server is a user-space compositor. Clients connect via the
//! "window" service and go through a two-phase handshake:
//!
//! 1. **Control channel** (from init routing): client sends CreateWindow,
//!    server replies with window info + a per-window channel capability.
//! 2. **Window channel**: client sends requests (GetInfo, GetFramebuffer,
//!    SwapBuffers, CloseWindow), server sends replies and push events (key
//!    events forwarded from the keyboard server).
//!
//! See docs/protocols/window.md for the full spec.

use rvos_wire::define_message;

// ── Control channel (one-shot handshake) ─────────────────────────

define_message! {
    /// CreateWindow request (client → server on control channel).
    pub struct CreateWindowRequest {
        width: u32,
        height: u32,
    }
}

define_message! {
    /// CreateWindow response (server → client on control channel).
    /// Cap = per-window channel endpoint.
    pub struct CreateWindowResponse {
        window_id: u32,
        width: u32,
        height: u32,
    }
}

// ── Window channel: client → server ──────────────────────────────

define_message! {
    /// Window requests (client → server on window channel).
    pub enum WindowRequest {
        /// Query window info (dimensions, format).
        GetInfo(0) { seq: u32 },
        /// Request framebuffer SHM handle.
        GetFramebuffer(1) { seq: u32 },
        /// Swap front/back buffers (present frame).
        SwapBuffers(2) { seq: u32 },
        /// Close the window.
        CloseWindow(3) {},
    }
}

// ── Window channel: server → client ──────────────────────────────
//
// Replies and events are combined into one enum because both arrive on
// the same channel. The client deserializes as WindowServerMsg and
// matches on the variant.

define_message! {
    /// All server-to-client messages on a window channel.
    pub enum WindowServerMsg {
        /// Reply to GetInfo.
        InfoReply(128) { seq: u32, window_id: u32, width: u32, height: u32, stride: u32, format: u8 },
        /// Reply to GetFramebuffer. Cap = SHM handle for the double-buffered framebuffer.
        FbReply(129) { seq: u32 },
        /// Reply to SwapBuffers.
        SwapReply(130) { seq: u32, ok: u8 },
        /// Keyboard event: key pressed (forwarded from kbd server).
        KeyDown(192) { code: u16 },
        /// Keyboard event: key released (forwarded from kbd server).
        KeyUp(193) { code: u16 },
    }
}
