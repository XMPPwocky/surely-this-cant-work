//! Error types for rvOS syscalls.

/// System call error codes.
///
/// Variants marked "(ABI)" can be returned by `from_code()`; other variants
/// are only used for locally-constructed errors on the user side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// The channel is closed / deactivated. (ABI code 2)
    ChannelClosed,
    /// Non-blocking send: queue is full. (ABI code 5)
    QueueFull,
    /// Resource exhaustion (handle table full, no free channels, OOM).
    NoResources,
    /// A user pointer or serialization buffer was invalid.
    BadAddress,
    /// An unrecognised or generic kernel error code. (ABI code usize::MAX)
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
    /// A syscall error other than Empty or Closed.
    Syscall(SysError),
}

impl SysError {
    /// Convert a raw syscall return code to a `SysResult`.
    ///
    /// The kernel ABI codes are: 0 = success, 2 = ChannelClosed,
    /// 5 = QueueFull, usize::MAX = generic error. All other values
    /// are mapped to `Unknown(code)`.
    pub fn from_code(code: usize) -> SysResult<()> {
        match code {
            0 => Ok(()),
            2 => Err(SysError::ChannelClosed),
            5 => Err(SysError::QueueFull),
            n => Err(SysError::Unknown(n)),
        }
    }
}
