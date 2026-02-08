//! Service discovery and process spawning via the boot channel.

use crate::channel::Channel;
use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;

// Boot channel request tags
const TAG_CONNECT_SERVICE: u8 = 0;
const TAG_SPAWN: u8 = 1;

// Boot channel response tags
const TAG_OK: u8 = 0;
const TAG_ERROR: u8 = 1;

/// Connect to a named service via the boot channel (handle 0).
///
/// Sends a ConnectService request on the boot channel and receives a capability
/// handle for the service's channel.
pub fn connect_to_service(name: &str) -> SysResult<Channel> {
    connect_to_service_on(0, name)
}

/// Connect to a named service via a specific boot handle.
pub fn connect_to_service_on(boot_handle: usize, name: &str) -> SysResult<Channel> {
    let msg = Message::build(raw::NO_CAP, |w| {
        let _ = w.write_u8(TAG_CONNECT_SERVICE);
        let _ = w.write_str(name);
    });
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

    // Parse response
    let mut r = reply.reader();
    let tag = r.read_u8().unwrap_or(TAG_ERROR);
    if tag != TAG_OK {
        return Err(SysError::NoResources);
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}

/// Spawn a process from a filesystem path via the boot channel (handle 0).
///
/// Returns a process handle channel that will receive an exit notification
/// (i32 exit code) when the spawned process exits.
pub fn spawn_process(path: &str) -> SysResult<Channel> {
    spawn_process_on(0, path)
}

/// Spawn a process via a specific boot handle.
pub fn spawn_process_on(boot_handle: usize, path: &str) -> SysResult<Channel> {
    let msg = Message::build(raw::NO_CAP, |w| {
        let _ = w.write_u8(TAG_SPAWN);
        let _ = w.write_str(path);
    });
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

    // Parse response
    let mut r = reply.reader();
    let tag = r.read_u8().unwrap_or(TAG_ERROR);
    if tag != TAG_OK {
        // Try to read error message for the caller
        return Err(SysError::NoResources);
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}

/// Spawn a process with an extra capability channel passed as handle 1.
///
/// Like `spawn_process`, but additionally sends `cap_handle` as a capability
/// with the Spawn request. The spawned process receives this as handle 1.
pub fn spawn_process_with_cap(path: &str, cap_handle: usize) -> SysResult<Channel> {
    spawn_process_with_cap_on(0, path, cap_handle)
}

/// Spawn a process with an extra capability via a specific boot handle.
pub fn spawn_process_with_cap_on(boot_handle: usize, path: &str, cap_handle: usize) -> SysResult<Channel> {
    let msg = Message::build(cap_handle, |w| {
        let _ = w.write_u8(TAG_SPAWN);
        let _ = w.write_str(path);
    });
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

    // Parse response
    let mut r = reply.reader();
    let tag = r.read_u8().unwrap_or(TAG_ERROR);
    if tag != TAG_OK {
        return Err(SysError::NoResources);
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}

/// Read the error message from a boot channel Error response.
/// Returns the error string from msg.data, or "unknown" if parsing fails.
pub fn read_error_response(msg: &Message) -> &str {
    let mut r = msg.reader();
    let tag = r.read_u8().unwrap_or(0);
    if tag == TAG_ERROR {
        r.read_str().unwrap_or("unknown")
    } else {
        "unknown"
    }
}
