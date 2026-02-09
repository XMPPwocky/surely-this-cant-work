//! Service control channel protocol.
//!
//! When init routes a client to a service (via the service's control channel),
//! it sends a `NewConnection` message carrying the client endpoint as `msg.cap`
//! and metadata about the connecting process.

use rvos_wire::define_message;

define_message! {
    /// Sent by init on a service's control channel when a new client connects.
    /// The message `cap` field carries the server-side endpoint for the new client.
    pub struct NewConnection {
        client_pid: u32,
    }
}
