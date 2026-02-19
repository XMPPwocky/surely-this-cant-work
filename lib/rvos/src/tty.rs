//! Terminal control helpers.

use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;
use rvos_proto::fs::{FileRequest, FileResponse};

/// Send a FileRequest::Ioctl on the given handle and wait for the response.
/// Returns the result field from IoctlOk.
pub fn ioctl(handle: usize, cmd: u32, arg: u32) -> SysResult<i32> {
    if handle == 0 {
        return Err(SysError::BadAddress);
    }
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &FileRequest::Ioctl { cmd, arg },
        &mut msg.data,
    ).map_err(|_| SysError::BadAddress)?;
    let send_ret = raw::sys_chan_send_blocking(handle, &msg);
    SysError::from_code(send_ret)?;

    // Receive response
    let mut resp = Message::new();
    let recv_ret = raw::sys_chan_recv_blocking(handle, &mut resp);
    SysError::from_code(recv_ret)?;

    match rvos_wire::from_bytes::<FileResponse>(&resp.data[..resp.len]) {
        Ok(FileResponse::IoctlOk { result }) => Ok(result as i32),
        _ => Err(SysError::Unknown(0)),
    }
}
