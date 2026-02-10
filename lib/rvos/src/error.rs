//! Error types for rvOS syscalls.

/// System call error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    InvalidHandle,
    ChannelClosed,
    NoResources,
    BadAddress,
    QueueFull,
    Unknown(usize),
}

/// Result type for syscall operations.
pub type SysResult<T> = Result<T, SysError>;

/// Errors from channel receive operations.
///
/// Used as the error type in `Result<T, RecvError>` returned by
/// `Channel::try_recv`, `Channel::recv_blocking`, and
/// `RawChannel::try_recv_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// No message available (channel queue is empty).
    Empty,
    /// The peer closed the channel.
    Closed,
    /// A message was received but failed to decode.  The channel should be
    /// considered broken — callers should log the error and close it.
    Decode(rvos_wire::WireError),
}

impl SysError {
    /// Convert a raw syscall return code to a result.
    pub fn from_code(code: usize) -> SysResult<()> {
        match code {
            0 => Ok(()),
            1 => Err(SysError::InvalidHandle),
            2 => Err(SysError::ChannelClosed),
            3 => Err(SysError::NoResources),
            4 => Err(SysError::BadAddress),
            5 => Err(SysError::QueueFull),
            n => Err(SysError::Unknown(n)),
        }
    }
}
