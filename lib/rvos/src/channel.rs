//! RAII channel handle.

use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;

/// An owned IPC channel handle. Closes the handle on drop.
pub struct Channel {
    handle: usize,
}

impl Channel {
    /// Create a new bidirectional channel pair.
    pub fn create_pair() -> SysResult<(Channel, Channel)> {
        let (a, b) = raw::syscall0(raw::SYS_CHAN_CREATE);
        if a == usize::MAX {
            return Err(SysError::NoResources);
        }
        Ok((Channel { handle: a }, Channel { handle: b }))
    }

    /// Wrap a raw handle into a Channel (takes ownership).
    pub fn from_raw_handle(handle: usize) -> Self {
        Channel { handle }
    }

    /// Get the raw handle value.
    pub fn raw_handle(&self) -> usize {
        self.handle
    }

    /// Consume the Channel without closing the handle.
    pub fn into_raw_handle(self) -> usize {
        let h = self.handle;
        core::mem::forget(self);
        h
    }

    /// Send a message on this channel.
    pub fn send(&self, msg: &Message) -> SysResult<()> {
        let ret = raw::syscall2(
            raw::SYS_CHAN_SEND,
            self.handle,
            msg as *const Message as usize,
        );
        SysError::from_code(ret)
    }

    /// Blocking receive on this channel.
    pub fn recv_blocking(&self, msg: &mut Message) -> SysResult<()> {
        let ret = raw::syscall2(
            raw::SYS_CHAN_RECV_BLOCKING,
            self.handle,
            msg as *mut Message as usize,
        );
        SysError::from_code(ret)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        raw::syscall1(raw::SYS_CHAN_CLOSE, self.handle);
    }
}
