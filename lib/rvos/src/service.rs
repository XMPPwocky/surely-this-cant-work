//! Service discovery via the boot channel.

use crate::channel::Channel;
use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;

/// Connect to a named service via the boot channel (handle 0).
///
/// Sends the service name on the boot channel and receives a capability
/// handle for the service's control channel.
pub fn connect_to_service(name: &str) -> SysResult<Channel> {
    connect_to_service_on(0, name)
}

/// Connect to a named service via a specific boot handle.
pub fn connect_to_service_on(boot_handle: usize, name: &str) -> SysResult<Channel> {
    let msg = Message::from_str(name);
    let ret = raw::syscall2(
        raw::SYS_CHAN_SEND,
        boot_handle,
        &msg as *const Message as usize,
    );
    if ret != 0 {
        return Err(SysError::from_code(ret).unwrap_err());
    }

    let mut reply = Message::new();
    let ret = raw::syscall2(
        raw::SYS_CHAN_RECV_BLOCKING,
        boot_handle,
        &mut reply as *mut Message as usize,
    );
    if ret != 0 {
        return Err(SysError::from_code(ret).unwrap_err());
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}
