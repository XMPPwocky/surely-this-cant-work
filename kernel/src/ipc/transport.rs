//! Kernel-side Transport implementation for rvos-wire RPC.

use crate::ipc::{self, Cap, Message, OwnedEndpoint};
use rvos_wire::{Transport, RpcError, MAX_CAPS};

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

}

impl Transport for KernelTransport {
    fn from_cap(&self, cap: usize) -> Self {
        Self::new(cap, self.pid)
    }

    fn send(&mut self, data: &[u8], caps: &[usize]) -> Result<(), RpcError> {
        let mut msg = Message::new();
        let copy_len = data.len().min(msg.data.len());
        msg.data[..copy_len].copy_from_slice(&data[..copy_len]);
        msg.len = copy_len;
        msg.sender_pid = self.pid;
        msg.cap_count = caps.len().min(MAX_CAPS);
        for (i, &cap) in caps.iter().enumerate().take(msg.cap_count) {
            if cap != rvos_wire::NO_CAP {
                msg.caps[i] = Cap::Channel(OwnedEndpoint::clone_from_raw(cap));
            }
        }
        match ipc::channel_send_blocking(self.endpoint, msg, self.pid) {
            Ok(()) => Ok(()),
            Err(e) => {
                // On error, `msg` was consumed by channel_send_blocking
                // which drops it (auto-closing any caps). No manual rollback.
                match e {
                    ipc::SendError::ChannelClosed => Err(RpcError::ChannelClosed),
                    ipc::SendError::QueueFull => Err(RpcError::Transport(5)),
                }
            }
        }
    }

    fn recv(&mut self, buf: &mut [u8], caps: &mut [usize]) -> Result<(usize, usize), RpcError> {
        match ipc::channel_recv_blocking(self.endpoint, self.pid) {
            Some(mut msg) => {
                let copy_len = msg.len.min(buf.len());
                buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                let cap_count = msg.cap_count.min(caps.len());
                for (cap_out, msg_cap) in caps.iter_mut().zip(msg.caps.iter_mut()).take(cap_count) {
                    match msg_cap.take() {
                        Cap::Channel(ep) => {
                            *cap_out = ep.into_raw();
                        }
                        Cap::Shm { .. } => {
                            // Wire protocol doesn't carry SHM caps; drop it
                            *cap_out = rvos_wire::NO_CAP;
                        }
                        Cap::None => {
                            *cap_out = rvos_wire::NO_CAP;
                        }
                    }
                }
                Ok((copy_len, cap_count))
            }
            None => Err(RpcError::ChannelClosed),
        }
    }
}
