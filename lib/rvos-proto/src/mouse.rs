//! Mouse server protocol.
//!
//! The mouse server is a kernel task wrapping VirtIO tablet/mouse input.
//! A single client (the window server) connects via service discovery and
//! receives push-style mouse events (no request-response).

use rvos_wire::define_message;

define_message! {
    /// Mouse events (server → client, push only).
    pub enum MouseEvent {
        /// Absolute pointer move. Coordinates are in tablet space (0..32767).
        Move(0) { abs_x: u16, abs_y: u16 },
        /// A mouse button was pressed. button: 0=Left, 1=Right, 2=Middle.
        ButtonDown(1) { button: u8 },
        /// A mouse button was released. button: 0=Left, 1=Right, 2=Middle.
        ButtonUp(2) { button: u8 },
    }
}
