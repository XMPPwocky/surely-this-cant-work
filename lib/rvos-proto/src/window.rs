//! Window manager protocol.
//!
//! The window server is a user-space compositor. Clients connect via the
//! "window" service and go through a two-phase handshake:
//!
//! 1. **Control channel** (from init routing): client sends CreateWindow,
//!    server replies with window info + two per-window channel capabilities.
//! 2. **Request channel** (caps[0]): client sends `WindowRequest`, server
//!    sends `WindowReply`. Use the generated `WindowClient` for type-safe RPC.
//! 3. **Event channel** (caps[1]): server pushes `WindowEvent` (keyboard,
//!    mouse, close notifications). A receive-only stream for clients.
//!
//! See docs/protocols/window.md for the full spec.

use rvos_wire::define_message;
use rvos_wire::RawChannelCap;
use rvos_wire::ShmHandle;

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
    /// Embeds the per-window request channel and event channel as typed caps.
    pub owned struct CreateWindowResponse {
        window_id: u32,
        width: u32,
        height: u32,
        req_channel: RawChannelCap,
        event_channel: RawChannelCap,
    }
}

// ── Request channel: client → server ─────────────────────────────

define_message! {
    /// Window requests (client → server on request channel).
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

// ── Request channel: server → client (replies) ──────────────────

define_message! {
    /// Replies from the window server on the request channel.
    pub owned enum WindowReply {
        /// Reply to GetInfo.
        InfoReply(128) { seq: u32, window_id: u32, width: u32, height: u32, stride: u32, format: u8 },
        /// Reply to GetFramebuffer. SHM handle embedded in the message.
        FbReply(129) { seq: u32, fb: ShmHandle },
        /// Reply to SwapBuffers.
        SwapReply(130) { seq: u32, ok: u8 },
        /// Reply to CloseWindow.
        CloseAck(131) {},
    }
}

// ── Event channel: server → client (push events) ────────────────

define_message! {
    /// Push events from the window server on the event channel.
    pub enum WindowEvent {
        /// Keyboard event: key pressed (forwarded from kbd server).
        KeyDown(192) { code: u16 },
        /// Keyboard event: key released (forwarded from kbd server).
        KeyUp(193) { code: u16 },
        /// Mouse moved (window-local coordinates).
        MouseMove(194) { x: u32, y: u32 },
        /// Mouse button pressed (window-local coordinates).
        MouseButtonDown(195) { x: u32, y: u32, button: u8 },
        /// Mouse button released (window-local coordinates).
        MouseButtonUp(196) { x: u32, y: u32, button: u8 },
        /// Close button was clicked by user; client should exit gracefully.
        CloseRequested(197) {},
    }
}

// ── Protocol definition (typed RPC for request channel) ──────────

rvos_wire::define_protocol! {
    /// Window request/reply protocol.
    ///
    /// Clients use `WindowClient<T>` for type-safe RPC calls.
    /// The server may use `WindowHandler` + `window_dispatch` or
    /// handle `WindowRequest`/`WindowReply` manually.
    pub protocol Window => WindowClient, WindowHandler, window_dispatch, window_handle {
        type Request = WindowRequest;
        type Response = WindowReply;

        rpc get_info as GetInfo(seq: u32) -> WindowReply;
        rpc get_framebuffer as GetFramebuffer(seq: u32) -> WindowReply;
        rpc swap_buffers as SwapBuffers(seq: u32) -> WindowReply;
        rpc close_window as CloseWindow() -> WindowReply;
    }
}
