//! rvos: Minimal userland library for rvOS IPC
//!
//! Provides safe wrappers around raw syscalls, channel management,
//! message construction, and service discovery.

#![no_std]

extern crate alloc;

pub mod raw;
pub mod error;
pub mod message;
pub mod channel;
#[allow(deprecated)]
pub mod service;
pub mod reactor;
pub mod transport;
pub mod window;
pub mod tty;
pub mod fs;
pub mod socket;
pub mod dns;

pub use error::{RecvError, SysError, SysResult};
pub use message::Message;
pub use channel::{RawChannel, Channel, channel_pair};
pub use service::{connect_to_service, spawn_process, spawn_process_with_args, spawn_process_with_cap, spawn_process_with_overrides, spawn_process_suspended, NsOverride};
pub use raw::NO_CAP;
pub use reactor::Reactor;
pub use transport::UserTransport;
pub use window::Window;

pub use rvos_wire;
pub use rvos_proto;
