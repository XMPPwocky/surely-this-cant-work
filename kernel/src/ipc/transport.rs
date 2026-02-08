//! Kernel-side Transport implementation for rvos-wire RPC.

use crate::ipc::{self, Message, NO_CAP};
use rvos_wire::{Transport, RpcError};

/// Kernel-side transport wrapping a channel endpoint.
///
/// Uses `channel_send_blocking` / `channel_recv_blocking` which block
/// the kernel task (not a user process).
pub struct KernelTransport {
    endpoint: usize,
    pid: usize,
}

impl KernelTransport {
    /// Create a new kernel transport for the given endpoint and PID.
    pub fn new(endpoint: usize, pid: usize) -> Self {
        Self { endpoint, pid }
    }

    /// Get the underlying endpoint.
    pub fn endpoint(&self) -> usize {
        self.endpoint
    }
}

impl Transport for KernelTransport {
    fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError> {
        let mut msg = Message::new();
        let copy_len = data.len().min(msg.data.len());
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        msg.len = copy_len;
        msg.sender_pid = self.pid;
        msg.cap = if cap == rvos_wire::NO_CAP { NO_CAP } else { ipc::encode_cap_channel(cap) };
        match ipc::channel_send_blocking(self.endpoint, &msg, self.pid) {
            Ok(()) => Ok(()),
            Err(ipc::SendError::ChannelClosed) => Err(RpcError::ChannelClosed),
            Err(ipc::SendError::QueueFull) => Err(RpcError::Transport(5)),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
        match ipc::channel_recv_blocking(self.endpoint, self.pid) {
            Some(msg) => {
                let copy_len = msg.len.min(buf.len());
                buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                let cap = if msg.cap == NO_CAP {
                    rvos_wire::NO_CAP
                } else {
                    match ipc::decode_cap(msg.cap) {
                        ipc::DecodedCap::Channel(ep) => ep,
                        _ => rvos_wire::NO_CAP,
                    }
                };
                Ok((copy_len, cap))
            }
            None => Err(RpcError::ChannelClosed),
        }
    }
}
