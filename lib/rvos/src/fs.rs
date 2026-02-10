//! Filesystem helpers for raw handle-based file operations.

use crate::error::{SysError, SysResult};
use crate::transport::UserTransport;
use rvos_proto::fs::{FsRequest, FsResponse, OpenFlags};
use rvos_wire::NO_CAP;

/// Open a file via the fs service and return the raw file channel handle.
///
/// This is a low-level helper for cases where you need the raw handle
/// (e.g., to pass as a capability for stdio redirection) rather than
/// going through std::fs.
pub fn file_open_raw(path: &str, flags: OpenFlags) -> SysResult<usize> {
    // Connect to fs service
    let fs_chan = crate::service::connect_to_service("fs")?;
    let fs_handle = fs_chan.into_raw_handle();

    // Send Open, receive response + file handle cap
    let mut transport = UserTransport::new(fs_handle);
    let mut buf = [0u8; rvos_wire::MAX_MSG_SIZE];
    let result = rvos_wire::rpc_call_with_cap(
        &mut transport,
        &FsRequest::Open { flags, path },
        NO_CAP,
        &mut buf,
    );

    // Done with fs control channel
    crate::raw::sys_chan_close(fs_handle);

    let (resp, cap) = result.map_err(|_| SysError::NoResources)?;
    match resp {
        FsResponse::Ok { .. } => {}
        _ => return Err(SysError::NoResources),
    }

    if cap == NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(cap)
}
