//! Service control channel protocol.
//!
//! When init routes a client to a service (via the service's control channel),
//! it sends a `NewConnection` message carrying the client endpoint as `msg.cap`
//! and metadata about the connecting process.

use rvos_wire::define_message;

/// Channel role: generic service connection.
pub const ROLE_GENERIC: u8 = 0;
/// Channel role: stdin (read side of stdio).
pub const ROLE_STDIN: u8 = 1;
/// Channel role: stdout (write side of stdio).
pub const ROLE_STDOUT: u8 = 2;

define_message! {
    /// Sent by init on a service's control channel when a new client connects.
    /// The message `cap` field carries the server-side endpoint for the new client.
    /// `channel_role`: 0 = generic, 1 = stdin, 2 = stdout.
    pub struct NewConnection {
        client_pid: u32,
        channel_role: u8,
    }
}
