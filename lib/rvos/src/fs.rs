//! Filesystem helpers for raw handle-based file operations.

use crate::error::{SysError, SysResult};
use crate::transport::UserTransport;
use rvos_proto::fs::{FsRequest, FsResponse, OpenFlags};

/// Open a file via the fs service and return the raw file channel handle.
///
/// This is a low-level helper for cases where you need the raw handle
/// (e.g., to pass as a capability for stdio redirection) rather than
/// going through std::fs.
pub fn file_open_raw(path: &str, flags: OpenFlags) -> SysResult<usize> {
    // Connect to fs service
    let fs_chan = crate::service::connect_to_service("fs")?;
    let fs_handle = fs_chan.into_raw_handle();

    // Send Open, receive response with embedded file channel cap
    let mut transport = UserTransport::new(fs_handle);
    let mut buf = [0u8; rvos_wire::MAX_MSG_SIZE];
    let result = rvos_wire::rpc_call::<_, _, FsResponse>(
        &mut transport,
        &FsRequest::Open { flags, path },
        &mut buf,
    );

    // Done with fs control channel
    crate::raw::sys_chan_close(fs_handle);

    let resp = result.map_err(|_| SysError::NoResources)?;
    match resp {
        FsResponse::Opened { file, .. } => Ok(file.raw()),
        _ => Err(SysError::NoResources),
    }
}
