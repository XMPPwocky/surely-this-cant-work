//! Filesystem helpers for raw handle-based file operations.

use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;
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

    // Send Open request
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &FsRequest::Open { flags, path },
        &mut msg.data,
    ).map_err(|_| SysError::BadAddress)?;
    let ret = raw::sys_chan_send_blocking(fs_handle, &msg);
    if ret != 0 {
        raw::sys_chan_close(fs_handle);
        return Err(SysError::from_code(ret).unwrap_err());
    }

    // Recv response
    let mut reply = Message::new();
    let ret = raw::sys_chan_recv_blocking(fs_handle, &mut reply);
    if ret != 0 {
        raw::sys_chan_close(fs_handle);
        return Err(SysError::from_code(ret).unwrap_err());
    }

    // Done with fs control channel
    raw::sys_chan_close(fs_handle);

    // Parse response
    match rvos_wire::from_bytes::<FsResponse>(&reply.data[..reply.len]) {
        Ok(FsResponse::Ok { .. }) => {}
        _ => return Err(SysError::NoResources),
    }

    let file_handle = reply.cap();
    if file_handle == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(file_handle)
}
