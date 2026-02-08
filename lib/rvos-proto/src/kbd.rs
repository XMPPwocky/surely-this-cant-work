//! Keyboard server protocol.
//!
//! The keyboard server is a kernel task wrapping VirtIO keyboard input.
//! A single client (the window server) connects via service discovery and
//! receives push-style key events (no request-response).
//!
//! See docs/protocols/kbd.md for the full spec.

use rvos_wire::define_message;

define_message! {
    /// Keyboard events (server → client, push only).
    pub enum KbdEvent {
        /// A key was pressed. `code` is a Linux evdev keycode.
        KeyDown(0) { code: u16 },
        /// A key was released. `code` is a Linux evdev keycode.
        KeyUp(1) { code: u16 },
    }
}
