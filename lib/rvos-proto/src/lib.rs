//! rvos-proto: Canonical protocol definitions for rvOS IPC services.
//!
//! Uses `define_message!` from `rvos-wire` to generate tagged enums/structs
//! with `Serialize` and `Deserialize` impls. Shared between kernel services
//! and user-space clients.

#![no_std]

pub mod math;
pub mod debug;
pub mod fs;
pub mod sysinfo;
pub mod boot;
pub mod process;
pub mod gpu;
pub mod kbd;
pub mod mouse;
pub mod net;
pub mod socket;
pub mod timer;
pub mod window;
pub mod service_control;
