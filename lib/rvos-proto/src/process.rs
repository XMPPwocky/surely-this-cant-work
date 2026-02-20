//! Process handle protocol.
//!
//! A process handle is a unidirectional notification channel returned by a
//! Spawn request on the boot channel. The holder blocks on it to wait for
//! the process to exit.
//!
//! See docs/protocols/process-handle.md for the full spec.

use rvos_wire::define_message;

define_message! {
    /// Sent on the process handle channel immediately after spawn.
    /// Tells the watcher the PID of the newly spawned process.
    pub struct ProcessStarted {
        pid: u32,
    }
}

define_message! {
    /// Exit notification sent from init to the process watcher.
    /// exit_code: 0 = success, nonzero = failure.
    pub struct ExitNotification {
        exit_code: i32,
    }
}
