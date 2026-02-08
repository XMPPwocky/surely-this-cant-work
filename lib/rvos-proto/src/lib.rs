//! rvos-proto: Canonical protocol definitions for rvOS IPC services.
//!
//! Uses `define_message!` from `rvos-wire` to generate tagged enums/structs
//! with `Serialize` and `Deserialize` impls. Shared between kernel services
//! and user-space clients.

#![no_std]

pub mod math;
pub mod fs;
