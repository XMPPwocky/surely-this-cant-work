//! User-space Transport implementation for rvos-wire RPC.

use crate::raw;
use crate::message::Message;
use rvos_wire::{Transport, RpcError, MAX_CAPS};

/// User-space transport wrapping a channel handle.
///
/// Uses blocking send/recv syscalls.
pub struct UserTransport {
    handle: usize,
}

impl UserTransport {
    /// Create a new transport for the given channel handle.
    pub fn new(handle: usize) -> Self {
        Self { handle }
    }

    /// Get the underlying handle.
    pub fn handle(&self) -> usize {
        self.handle
    }
}

impl Transport for UserTransport {
    fn from_cap(&self, cap: usize) -> Self {
        Self::new(cap)
    }

    fn send(&mut self, data: &[u8], caps: &[usize]) -> Result<(), RpcError> {
        let mut msg = Message::boxed();
        let copy_len = data.len().min(msg.data.len());
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        msg.len = copy_len;
        msg.cap_count = caps.len().min(MAX_CAPS);
        for i in 0..msg.cap_count {
            msg.caps[i] = caps[i];
        }
        let ret = raw::sys_chan_send_blocking(self.handle, &msg);
        match ret {
            0 => Ok(()),
            2 => Err(RpcError::ChannelClosed),
            other => Err(RpcError::Transport(other)),
        }
    }

    fn recv(&mut self, buf: &mut [u8], caps: &mut [usize]) -> Result<(usize, usize), RpcError> {
        let mut msg = Message::boxed();
        let ret = raw::sys_chan_recv_blocking(self.handle, &mut msg);
        match ret {
            0 => {
                let copy_len = msg.len.min(buf.len());
                buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                let cap_count = msg.cap_count.min(caps.len());
                for i in 0..cap_count {
                    caps[i] = msg.caps[i];
                }
                Ok((copy_len, cap_count))
            }
            2 => Err(RpcError::ChannelClosed),
            other => Err(RpcError::Transport(other)),
        }
    }
}
