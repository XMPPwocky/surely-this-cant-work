//! rvos: Minimal userland library for rvOS IPC
//!
//! Provides safe wrappers around raw syscalls, channel management,
//! message construction, and service discovery.

#![no_std]

pub mod raw;
pub mod error;
pub mod message;
pub mod channel;
// TODO: Port to ChannelCap-based protocols — currently uses deprecated raw cap sideband.
#[allow(deprecated)]
pub mod service;
pub mod transport;
pub mod tty;
// TODO: Port to ChannelCap-based protocols — currently uses deprecated raw cap sideband.
#[allow(deprecated)]
pub mod fs;

pub use error::{SysError, SysResult};
pub use message::Message;
pub use channel::{RawChannel, Channel, channel_pair};
pub use service::{connect_to_service, spawn_process, spawn_process_with_args, spawn_process_with_cap, spawn_process_with_overrides, NsOverride};
pub use raw::NO_CAP;
pub use transport::UserTransport;

pub use rvos_wire;
pub use rvos_proto;
