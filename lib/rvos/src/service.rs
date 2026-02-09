//! Service discovery and process spawning via the boot channel.

use crate::channel::Channel;
use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;
use rvos_proto::boot::{BootRequest, BootResponse};

/// Connect to a named service via the boot channel (handle 0).
///
/// Sends a ConnectService request on the boot channel and receives a capability
/// handle for the service's channel.
pub fn connect_to_service(name: &str) -> SysResult<Channel> {
    connect_to_service_on(0, name)
}

/// Connect to a named service via a specific boot handle.
pub fn connect_to_service_on(boot_handle: usize, name: &str) -> SysResult<Channel> {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&BootRequest::ConnectService { name }, &mut msg.data)
        .map_err(|_| SysError::BadAddress)?;
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
    match rvos_wire::from_bytes::<BootResponse<'_>>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => {}
        _ => return Err(SysError::NoResources),
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
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &BootRequest::Spawn { path, args: &[], ns_overrides: &[] },
        &mut msg.data,
    ).map_err(|_| SysError::BadAddress)?;
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

    match rvos_wire::from_bytes::<BootResponse<'_>>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => {}
        _ => return Err(SysError::NoResources),
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
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &BootRequest::Spawn { path, args: &[], ns_overrides: &[] },
        &mut msg.data,
    ).map_err(|_| SysError::BadAddress)?;
    msg.set_cap(cap_handle);
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

    match rvos_wire::from_bytes::<BootResponse<'_>>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => {}
        _ => return Err(SysError::NoResources),
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}

/// Spawn a process with command-line arguments via the boot channel (handle 0).
///
/// `args` is a null-separated blob (e.g., b"arg1\0arg2"). The spawned process
/// retrieves these via `GetArgs` on its boot channel (used by `std::env::args()`).
pub fn spawn_process_with_args(path: &str, args: &[u8]) -> SysResult<Channel> {
    spawn_process_with_args_on(0, path, args)
}

/// Spawn a process with args via a specific boot handle.
pub fn spawn_process_with_args_on(boot_handle: usize, path: &str, args: &[u8]) -> SysResult<Channel> {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &BootRequest::Spawn { path, args, ns_overrides: &[] },
        &mut msg.data,
    ).map_err(|_| SysError::BadAddress)?;
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

    match rvos_wire::from_bytes::<BootResponse<'_>>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => {}
        _ => return Err(SysError::NoResources),
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}

/// Spawn a process with args and namespace overrides.
///
/// `ns_overrides` is a packed blob: `[count: u8] then count * [name_len: u8, name_bytes..., cap_index: u8]`
/// Each cap_index references `msg.caps[cap_index]`.
/// `caps` contains the handles to send as capabilities with the spawn message.
pub fn spawn_process_with_overrides(
    path: &str,
    args: &[u8],
    ns_overrides: &[u8],
    caps: &[usize],
) -> SysResult<Channel> {
    spawn_process_with_overrides_on(0, path, args, ns_overrides, caps)
}

/// Spawn with overrides via a specific boot handle.
pub fn spawn_process_with_overrides_on(
    boot_handle: usize,
    path: &str,
    args: &[u8],
    ns_overrides: &[u8],
    caps: &[usize],
) -> SysResult<Channel> {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &BootRequest::Spawn { path, args, ns_overrides },
        &mut msg.data,
    ).map_err(|_| SysError::BadAddress)?;
    let cap_count = caps.len().min(crate::message::MAX_CAPS);
    for i in 0..cap_count {
        msg.caps[i] = caps[i];
    }
    msg.cap_count = cap_count;
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

    match rvos_wire::from_bytes::<BootResponse<'_>>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => {}
        _ => return Err(SysError::NoResources),
    }

    if reply.cap() == raw::NO_CAP {
        return Err(SysError::NoResources);
    }

    Ok(Channel::from_raw_handle(reply.cap()))
}

/// Read the error message from a boot channel Error response.
/// Returns the error string from msg.data, or "unknown" if parsing fails.
pub fn read_error_response(msg: &Message) -> &str {
    match rvos_wire::from_bytes::<BootResponse<'_>>(&msg.data[..msg.len]) {
        Ok(BootResponse::Error { message }) => message,
        _ => "unknown",
    }
}
