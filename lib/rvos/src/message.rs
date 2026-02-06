//! IPC Message type matching the kernel's layout.

use crate::raw::NO_CAP;
use rvos_wire::{Reader, Writer};

const MAX_MSG_SIZE: usize = 1024;

/// Fixed-size IPC message matching kernel's `ipc::Message` layout exactly.
#[repr(C)]
#[derive(Clone)]
pub struct Message {
    pub data: [u8; MAX_MSG_SIZE],
    pub len: usize,
    pub sender_pid: usize,
    pub cap: usize,
}

impl Message {
    /// Create a new empty message.
    pub fn new() -> Self {
        Message {
            data: [0u8; MAX_MSG_SIZE],
            len: 0,
            sender_pid: 0,
            cap: NO_CAP,
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

    /// Get the capability handle.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Set the capability handle.
    pub fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
    }

    /// Create a Writer over the data buffer.
    pub fn writer(&mut self) -> Writer<'_> {
        Writer::new(&mut self.data)
    }

    /// Create a Reader over the payload.
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.data[..self.len])
    }

    /// Build a message: write into data using a closure, set len from writer position.
    pub fn build<F>(cap: usize, f: F) -> Self
    where
        F: FnOnce(&mut Writer<'_>),
    {
        let mut msg = Self::new();
        msg.cap = cap;
        let mut w = Writer::new(&mut msg.data);
        f(&mut w);
        msg.len = w.position();
        msg
    }
}
