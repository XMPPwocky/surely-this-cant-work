//! IPC Message type matching the kernel's layout.

use crate::raw::NO_CAP;
use rvos_wire::{Reader, Writer};

const MAX_MSG_SIZE: usize = 1024;

/// Maximum number of capabilities per message.
pub const MAX_CAPS: usize = 4;

/// Fixed-size IPC message matching kernel's `ipc::Message` layout exactly.
#[repr(C)]
#[derive(Clone)]
pub struct Message {
    pub data: [u8; MAX_MSG_SIZE],
    pub len: usize,
    pub sender_pid: usize,
    /// Capability sideband — only accessed by `Transport::send/recv` and
    /// IPC infrastructure (`Channel`).  Application code should use typed
    /// protocol clients (`define_protocol!`) instead of touching this directly.
    pub caps: [usize; MAX_CAPS],
    pub cap_count: usize,
}

// Compile-time assertions: must match kernel's ipc::Message layout exactly.
const _: () = assert!(MAX_MSG_SIZE == 1024);
const _: () = assert!(core::mem::size_of::<Message>() == 1080);

impl Message {
    /// Create a new empty message.
    pub const fn new() -> Self {
        Message {
            data: [0u8; MAX_MSG_SIZE],
            len: 0,
            sender_pid: 0,
            caps: [NO_CAP; MAX_CAPS],
            cap_count: 0,
        }
    }

    /// Create a message from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut msg = Self::new();
        let copy_len = bytes.len().min(MAX_MSG_SIZE);
        msg.data[..copy_len].copy_from_slice(&bytes[..copy_len]);
        msg.len = copy_len;
        msg
    }

    /// Create a message from a string.
    pub fn from_str(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    /// Get the message payload as a byte slice.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get a mutable reference to the full data buffer.
    pub fn data_mut(&mut self) -> &mut [u8; MAX_MSG_SIZE] {
        &mut self.data
    }

    /// Get the data buffer.
    pub fn data(&self) -> &[u8; MAX_MSG_SIZE] {
        &self.data
    }

    /// Get the message length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Set the message length.
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(MAX_MSG_SIZE);
    }

    /// Get the sender PID.
    pub fn sender_pid(&self) -> usize {
        self.sender_pid
    }

    /// Create a Writer over the data buffer.
    pub fn writer(&mut self) -> Writer<'_> {
        Writer::new(&mut self.data)
    }

    /// Create a Reader over the payload.
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.data[..self.len])
    }
}
