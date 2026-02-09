//! Terminal control helpers.

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::message::Message;
use crate::raw;

/// Global stdin handle, set by std's stdio::init().
pub static STDIN_HANDLE: AtomicUsize = AtomicUsize::new(0);
/// Global stdout handle, set by std's stdio::init().
pub static STDOUT_HANDLE: AtomicUsize = AtomicUsize::new(0);

/// Send a FileRequest::Ioctl on the given handle and wait for the response.
/// Returns the result field from IoctlOk, or -1 on error.
pub fn ioctl(handle: usize, cmd: u32, arg: u32) -> i32 {
    if handle == 0 {
        return -1;
    }
    // Build FileRequest::Ioctl: u8(2) + u32(cmd) + u32(arg)
    let msg = Message::build(raw::NO_CAP, |w| {
        let _ = w.write_u8(2); // tag: Ioctl
        let _ = w.write_u32(cmd);
        let _ = w.write_u32(arg);
    });
    raw::sys_chan_send_blocking(handle, &msg);

    // Receive response
    let mut resp = Message::new();
    let ret = raw::sys_chan_recv_blocking(handle, &mut resp);
    if ret != 0 || resp.len < 1 {
        return -1;
    }

    let mut r = rvos_wire::Reader::new(&resp.data[..resp.len]);
    let tag = r.read_u8().unwrap_or(0xFF);
    match tag {
        3 => {
            // IoctlOk: u32(result)
            r.read_u32().unwrap_or(0) as i32
        }
        _ => -1,
    }
}

/// Convenience: set terminal raw/cooked mode on the stdin handle.
pub fn set_raw_mode(enable: bool) {
    let h = STDIN_HANDLE.load(Ordering::Acquire);
    if h != 0 {
        let cmd = if enable {
            rvos_proto::fs::TCRAW
        } else {
            rvos_proto::fs::TCCOOKED
        };
        ioctl(h, cmd, 0);
    }
}
