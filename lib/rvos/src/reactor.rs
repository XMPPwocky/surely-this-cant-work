//! Event reactor for multiplexing multiple channel handles.
//!
//! Wraps the `sys_chan_poll_add` + `sys_block` pattern into a reusable struct.
//!
//! # Example
//! ```ignore
//! let mut reactor = Reactor::new();
//! reactor.add(stdin_handle);
//! reactor.add(event_handle);
//! loop {
//!     reactor.poll_and_block();
//!     // check channels non-blocking...
//! }
//! ```

use alloc::vec::Vec;
use crate::raw;

/// A simple event reactor that polls a set of channel handles.
pub struct Reactor {
    handles: Vec<usize>,
}

impl Reactor {
    /// Create an empty reactor.
    pub fn new() -> Self {
        Reactor { handles: Vec::new() }
    }

    /// Add a channel handle to the poll set.
    pub fn add(&mut self, handle: usize) {
        if !self.handles.contains(&handle) {
            self.handles.push(handle);
        }
    }

    /// Remove a channel handle from the poll set.
    pub fn remove(&mut self, handle: usize) {
        self.handles.retain(|&h| h != handle);
    }

    /// Register all handles for polling and block until any has data.
    pub fn poll_and_block(&self) {
        for &h in &self.handles {
            raw::sys_chan_poll_add(h);
        }
        raw::sys_block();
    }

    /// Register all handles for polling and block until any has data
    /// or the deadline (rdtime ticks) is reached.
    pub fn poll_and_block_deadline(&self, deadline: u64) {
        for &h in &self.handles {
            raw::sys_chan_poll_add(h);
        }
        raw::sys_block_deadline(deadline);
    }

    /// Return the number of handles in the poll set.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Return true if the poll set is empty.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}
