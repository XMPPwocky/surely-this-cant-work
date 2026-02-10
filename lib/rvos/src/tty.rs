//! Terminal control helpers.

use crate::message::Message;
use crate::raw;
use rvos_proto::fs::{FileRequest, FileResponse};

/// Send a FileRequest::Ioctl on the given handle and wait for the response.
/// Returns the result field from IoctlOk, or -1 on error.
pub fn ioctl(handle: usize, cmd: u32, arg: u32) -> i32 {
    if handle == 0 {
        return -1;
    }
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &FileRequest::Ioctl { cmd, arg },
        &mut msg.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);

    // Receive response
    let mut resp = Message::new();
    let ret = raw::sys_chan_recv_blocking(handle, &mut resp);
    if ret != 0 || resp.len < 1 {
        return -1;
    }

    match rvos_wire::from_bytes::<FileResponse>(&resp.data[..resp.len]) {
        Ok(FileResponse::IoctlOk { result }) => result as i32,
        _ => -1,
    }
}
