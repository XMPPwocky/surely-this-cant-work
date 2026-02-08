//! User-space Transport implementation for rvos-wire RPC.

use crate::raw;
use crate::message::Message;
use rvos_wire::{Transport, RpcError};

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

    fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError> {
        let mut msg = Message::new();
        let copy_len = data.len().min(msg.data.len());
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        msg.len = copy_len;
        msg.cap = cap;
        let ret = raw::sys_chan_send_blocking(self.handle, &msg);
        match ret {
            0 => Ok(()),
            2 => Err(RpcError::ChannelClosed),
            other => Err(RpcError::Transport(other)),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
        let mut msg = Message::new();
        let ret = raw::sys_chan_recv_blocking(self.handle, &mut msg);
        match ret {
            0 => {
                let copy_len = msg.len.min(buf.len());
                buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                Ok((copy_len, msg.cap))
            }
            2 => Err(RpcError::ChannelClosed),
            other => Err(RpcError::Transport(other)),
        }
    }
}
