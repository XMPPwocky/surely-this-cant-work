//! Error types for rvOS syscalls.

/// System call error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    InvalidHandle,
    ChannelClosed,
    NoResources,
    BadAddress,
    Unknown(usize),
}

/// Result type for syscall operations.
pub type SysResult<T> = Result<T, SysError>;

impl SysError {
    /// Convert a raw syscall return code to a result.
    pub fn from_code(code: usize) -> SysResult<()> {
        match code {
            0 => Ok(()),
            1 => Err(SysError::InvalidHandle),
            2 => Err(SysError::ChannelClosed),
            3 => Err(SysError::NoResources),
            4 => Err(SysError::BadAddress),
            n => Err(SysError::Unknown(n)),
        }
    }
}
