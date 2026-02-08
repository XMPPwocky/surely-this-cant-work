//! rvos: Minimal userland library for rvOS IPC
//!
//! Provides safe wrappers around raw syscalls, channel management,
//! message construction, and service discovery.

#![no_std]

pub mod raw;
pub mod error;
pub mod message;
pub mod channel;
pub mod service;

pub use error::{SysError, SysResult};
pub use message::Message;
pub use channel::Channel;
pub use service::{connect_to_service, spawn_process};
pub use raw::NO_CAP;

pub use rvos_wire;
