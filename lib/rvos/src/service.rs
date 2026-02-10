//! Service discovery and process spawning via the boot channel.

use crate::channel::RawChannel;
use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;
use crate::transport::UserTransport;
use rvos_proto::boot::{BootRequest, BootResponse};
use rvos_wire::{Transport, NO_CAP, MAX_MSG_SIZE};

/// Extract a capability handle from a boot channel response, returning
/// an error if the response is not Ok or carries no capability.
fn boot_response_cap(resp: BootResponse<'_>, cap: usize) -> SysResult<RawChannel> {
    match resp {
        BootResponse::Ok {} => {}
        _ => return Err(SysError::NoResources),
    }
    if cap == NO_CAP {
        return Err(SysError::NoResources);
    }
    Ok(RawChannel::from_raw_handle(cap))
}

/// Connect to a named service via the boot channel (handle 0).
///
/// Sends a ConnectService request on the boot channel and receives a capability
/// handle for the service's channel.
pub fn connect_to_service(name: &str) -> SysResult<RawChannel> {
    connect_to_service_on(0, name)
}

/// Connect to a named service via a specific boot handle.
pub fn connect_to_service_on(boot_handle: usize, name: &str) -> SysResult<RawChannel> {
    let mut transport = UserTransport::new(boot_handle);
    let mut buf = [0u8; MAX_MSG_SIZE];
    let (resp, cap) = rvos_wire::rpc_call_with_cap(
        &mut transport,
        &BootRequest::ConnectService { name },
        NO_CAP,
        &mut buf,
    ).map_err(|_| SysError::NoResources)?;
    boot_response_cap(resp, cap)
}

/// Spawn a process from a filesystem path via the boot channel (handle 0).
///
/// Returns a process handle channel that will receive an exit notification
/// (i32 exit code) when the spawned process exits.
pub fn spawn_process(path: &str) -> SysResult<RawChannel> {
    spawn_process_on(0, path)
}

/// Spawn a process via a specific boot handle.
pub fn spawn_process_on(boot_handle: usize, path: &str) -> SysResult<RawChannel> {
    let mut transport = UserTransport::new(boot_handle);
    let mut buf = [0u8; MAX_MSG_SIZE];
    let (resp, cap) = rvos_wire::rpc_call_with_cap(
        &mut transport,
        &BootRequest::Spawn { path, args: &[], ns_overrides: &[] },
        NO_CAP,
        &mut buf,
    ).map_err(|_| SysError::NoResources)?;
    boot_response_cap(resp, cap)
}

/// Spawn a process with an extra capability channel passed as handle 1.
///
/// Like `spawn_process`, but additionally sends `cap_handle` as a capability
/// with the Spawn request. The spawned process receives this as handle 1.
pub fn spawn_process_with_cap(path: &str, cap_handle: usize) -> SysResult<RawChannel> {
    spawn_process_with_cap_on(0, path, cap_handle)
}

/// Spawn a process with an extra capability via a specific boot handle.
pub fn spawn_process_with_cap_on(boot_handle: usize, path: &str, cap_handle: usize) -> SysResult<RawChannel> {
    let mut transport = UserTransport::new(boot_handle);
    let mut buf = [0u8; MAX_MSG_SIZE];
    let (resp, cap) = rvos_wire::rpc_call_with_cap(
        &mut transport,
        &BootRequest::Spawn { path, args: &[], ns_overrides: &[] },
        cap_handle,
        &mut buf,
    ).map_err(|_| SysError::NoResources)?;
    boot_response_cap(resp, cap)
}

/// Spawn a process with command-line arguments via the boot channel (handle 0).
///
/// `args` is a null-separated blob (e.g., b"arg1\0arg2"). The spawned process
/// retrieves these via `GetArgs` on its boot channel (used by `std::env::args()`).
pub fn spawn_process_with_args(path: &str, args: &[u8]) -> SysResult<RawChannel> {
    spawn_process_with_args_on(0, path, args)
}

/// Spawn a process with args via a specific boot handle.
pub fn spawn_process_with_args_on(boot_handle: usize, path: &str, args: &[u8]) -> SysResult<RawChannel> {
    let mut transport = UserTransport::new(boot_handle);
    let mut buf = [0u8; MAX_MSG_SIZE];
    let (resp, cap) = rvos_wire::rpc_call_with_cap(
        &mut transport,
        &BootRequest::Spawn { path, args, ns_overrides: &[] },
        NO_CAP,
        &mut buf,
    ).map_err(|_| SysError::NoResources)?;
    boot_response_cap(resp, cap)
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
) -> SysResult<RawChannel> {
    spawn_process_with_overrides_on(0, path, args, ns_overrides, caps)
}

/// Spawn with overrides via a specific boot handle.
pub fn spawn_process_with_overrides_on(
    boot_handle: usize,
    path: &str,
    args: &[u8],
    ns_overrides: &[u8],
    caps: &[usize],
) -> SysResult<RawChannel> {
    // Multi-cap send — use Transport directly since rpc_call_with_cap
    // only supports a single capability.
    let mut transport = UserTransport::new(boot_handle);
    let mut send_buf = [0u8; MAX_MSG_SIZE];
    let n = rvos_wire::to_bytes(
        &BootRequest::Spawn { path, args, ns_overrides },
        &mut send_buf,
    ).map_err(|_| SysError::BadAddress)?;
    transport.send(&send_buf[..n], caps)
        .map_err(|_| SysError::NoResources)?;

    let mut recv_buf = [0u8; MAX_MSG_SIZE];
    let mut recv_caps = [0usize; rvos_wire::MAX_CAPS];
    let (len, cap_count) = transport.recv(&mut recv_buf, &mut recv_caps)
        .map_err(|_| SysError::NoResources)?;

    let resp = rvos_wire::from_bytes::<BootResponse<'_>>(&recv_buf[..len])
        .map_err(|_| SysError::BadAddress)?;
    let cap = if cap_count > 0 { recv_caps[0] } else { NO_CAP };
    boot_response_cap(resp, cap)
}

/// Read the error message from a boot channel Error response.
/// Returns the error string from msg.data, or "unknown" if parsing fails.
pub fn read_error_response(msg: &Message) -> &str {
    match rvos_wire::from_bytes::<BootResponse<'_>>(&msg.data[..msg.len]) {
        Ok(BootResponse::Error { message }) => message,
        _ => "unknown",
    }
}
