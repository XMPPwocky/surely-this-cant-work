//! Channel IPC syscalls: create, send, recv, close, poll.

use crate::task::{HandleObject, HandleInfo};
use super::{validate_user_buffer, UserMessage, SyscallError, SyscallResult};

/// SYS_CHAN_CREATE: create a bidirectional channel pair.
/// Returns (handle_a, handle_b) on success.
pub fn sys_chan_create() -> Result<(usize, usize), SyscallError> {
    // Per-process channel limit: creating a pair adds 2 handles
    if crate::task::current_process_channel_count() + 2 > crate::task::process::MAX_CHANNELS_PER_PROCESS as u16 {
        return Err(SyscallError::Error);
    }
    let (ep_a, ep_b) = crate::ipc::channel_create_pair()
        .ok_or(SyscallError::Error)?;
    // alloc_handle takes ownership. On failure, ep drops → auto-close.
    let handle_a = match crate::task::current_process_alloc_handle(HandleObject::Channel(ep_a)) {
        Some(h) => h,
        None => {
            // ep_a was moved into alloc_handle → dropped on None return (auto-close).
            // ep_b still owned here → drops when we return (auto-close).
            drop(ep_b);
            return Err(SyscallError::Error);
        }
    };
    let handle_b = match crate::task::current_process_alloc_handle(HandleObject::Channel(ep_b)) {
        Some(h) => h,
        None => {
            // ep_b was moved into alloc_handle → dropped on None return (auto-close).
            // handle_a is in the handle table → take it back so it drops.
            drop(crate::task::current_process_take_handle(handle_a));
            return Err(SyscallError::Error);
        }
    };
    Ok((handle_a, handle_b))
}

/// Build a kernel Message with RAII caps from a user-space ABI message.
/// On success returns the kernel Message ready to send.
/// On failure (bad handle) returns None — the partially-built message drops,
/// auto-closing any previously translated caps.
fn build_kernel_message(user_msg: &UserMessage) -> Result<crate::ipc::Message, SyscallError> {
    let mut msg = crate::ipc::Message::new();
    let copy_len = user_msg.len.min(crate::ipc::MAX_MSG_SIZE);
    msg.data[..copy_len].copy_from_slice(&user_msg.data[..copy_len]);
    msg.len = copy_len;
    msg.sender_pid = crate::task::current_pid();
    msg.cap_count = user_msg.cap_count.min(crate::ipc::MAX_CAPS);

    for i in 0..msg.cap_count {
        let local_handle = user_msg.caps[i];
        if local_handle == crate::ipc::NO_CAP {
            continue; // Cap::None is already the default
        }
        match crate::task::current_process_handle(local_handle) {
            Some(HandleInfo::Channel(global_ep)) => {
                msg.caps[i] = crate::ipc::Cap::Channel(
                    crate::ipc::OwnedEndpoint::clone_from_raw(global_ep),
                );
            }
            Some(HandleInfo::Shm { id, rw }) => {
                msg.caps[i] = crate::ipc::Cap::Shm {
                    owned: crate::ipc::OwnedShm::clone_from_raw(id),
                    rw,
                };
            }
            None => {
                // Invalid handle — drop msg (auto-closes all previously translated caps)
                return Err(SyscallError::Error);
            }
        }
    }
    Ok(msg)
}

/// Write a received kernel Message into user space, installing caps into the
/// handle table. Consumes the kernel Message.
fn write_recv_message(msg: &mut crate::ipc::Message, msg_pa: usize) {
    let mut user_msg = UserMessage {
        data: [0u8; crate::ipc::MAX_MSG_SIZE],
        len: msg.len,
        sender_pid: msg.sender_pid,
        caps: [crate::ipc::NO_CAP; crate::ipc::MAX_CAPS],
        cap_count: msg.cap_count,
    };
    user_msg.data[..msg.len].copy_from_slice(&msg.data[..msg.len]);

    // Install received caps into handle table
    for i in 0..msg.cap_count {
        match msg.caps[i].take() {
            crate::ipc::Cap::Channel(ep) => {
                // alloc_handle takes ownership. On None, ep drops → auto-close.
                if let Some(h) = crate::task::current_process_alloc_handle(
                    HandleObject::Channel(ep),
                ) {
                    user_msg.caps[i] = h;
                }
            }
            crate::ipc::Cap::Shm { owned, rw } => {
                if let Some(h) = crate::task::current_process_alloc_handle(
                    HandleObject::Shm { owned, rw },
                ) {
                    user_msg.caps[i] = h;
                }
            }
            crate::ipc::Cap::None => {}
        }
    }

    unsafe { core::ptr::write(msg_pa as *mut UserMessage, user_msg); }
}

/// SYS_CHAN_SEND: translate handle -> endpoint, copy message from user, send.
pub fn sys_chan_send(handle: usize, msg_ptr: usize) -> SyscallResult {
    let msg_pa = validate_user_buffer(msg_ptr, core::mem::size_of::<UserMessage>())?;

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleInfo::Channel(ep)) => ep,
        _ => return Err(SyscallError::Error),
    };

    let user_msg = unsafe { core::ptr::read(msg_pa as *const UserMessage) };
    let msg = build_kernel_message(&user_msg)?;

    match crate::ipc::channel_send(endpoint, msg) {
        Ok(wake) => {
            if wake != 0 { crate::task::wake_process(wake); }
            Ok(0)
        }
        Err((crate::ipc::SendError::QueueFull, _dropped)) => Err(SyscallError::QueueFull),
        Err((_, _dropped)) => Err(SyscallError::Error),
    }
}

/// SYS_CHAN_RECV (non-blocking): translate handle, try recv, install caps.
pub fn sys_chan_recv(handle: usize, msg_buf_ptr: usize) -> SyscallResult {
    let msg_pa = validate_user_buffer(msg_buf_ptr, core::mem::size_of::<UserMessage>())?;

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleInfo::Channel(ep)) => ep,
        _ => return Err(SyscallError::Error),
    };

    let (msg, send_wake) = crate::ipc::channel_recv(endpoint);
    if send_wake != 0 {
        crate::task::wake_process(send_wake);
    }
    match msg {
        Some(mut msg) => {
            write_recv_message(&mut msg, msg_pa);
            Ok(0)
        }
        None => {
            if !crate::ipc::channel_is_active(endpoint) {
                Err(SyscallError::ChannelClosed)
            } else {
                Err(SyscallError::Empty)
            }
        }
    }
}

/// SYS_CHAN_RECV_BLOCKING: like recv but blocks if empty.
pub fn sys_chan_recv_blocking(handle: usize, msg_buf_ptr: usize) -> SyscallResult {
    let msg_pa = validate_user_buffer(msg_buf_ptr, core::mem::size_of::<UserMessage>())?;

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleInfo::Channel(ep)) => ep,
        _ => return Err(SyscallError::Error),
    };

    let cur_pid = crate::task::current_pid();
    loop {
        let (msg, send_wake) = crate::ipc::channel_recv(endpoint);
        if send_wake != 0 {
            crate::task::wake_process(send_wake);
        }
        match msg {
            Some(mut msg) => {
                write_recv_message(&mut msg, msg_pa);
                return Ok(0);
            }
            None => {
                if !crate::ipc::channel_is_active(endpoint) {
                    return Err(SyscallError::ChannelClosed);
                }
                crate::ipc::channel_set_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
            }
        }
    }
}

/// SYS_CHAN_SEND_BLOCKING: like send but blocks if queue full.
/// Uses return-on-failure pattern: channel_send returns the message on QueueFull
/// so we can retry without re-translating caps.
pub fn sys_chan_send_blocking(handle: usize, msg_ptr: usize) -> SyscallResult {
    let msg_pa = validate_user_buffer(msg_ptr, core::mem::size_of::<UserMessage>())?;

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleInfo::Channel(ep)) => ep,
        _ => return Err(SyscallError::Error),
    };

    let user_msg = unsafe { core::ptr::read(msg_pa as *const UserMessage) };
    let mut msg = build_kernel_message(&user_msg)?;

    let cur_pid = crate::task::current_pid();
    loop {
        match crate::ipc::channel_send(endpoint, msg) {
            Ok(wake) => {
                if wake != 0 {
                    crate::task::wake_process(wake);
                }
                return Ok(0);
            }
            Err((crate::ipc::SendError::QueueFull, returned)) => {
                msg = returned; // got message back, retry after blocking
                if !crate::ipc::channel_is_active(endpoint) {
                    // msg drops → caps auto-close
                    return Err(SyscallError::Error);
                }
                crate::ipc::channel_set_send_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
            }
            Err((_, _dropped)) => {
                // msg dropped → caps auto-close
                return Err(SyscallError::Error);
            }
        }
    }
}

/// SYS_CHAN_POLL_ADD: register the calling process as blocked-waiting on a
/// channel handle so that any future send to that endpoint will wake us.
pub fn sys_chan_poll_add(handle: usize) -> SyscallResult {
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleInfo::Channel(ep)) => ep,
        _ => return Err(SyscallError::Error),
    };
    let pid = crate::task::current_pid();
    crate::ipc::channel_set_blocked(endpoint, pid);
    Ok(0)
}

/// SYS_CHAN_CLOSE: close a handle (channel or SHM).
/// Takes the handle from the table; the returned RAII object drops automatically.
pub fn sys_chan_close(handle: usize) -> SyscallResult {
    match crate::task::current_process_take_handle(handle) {
        Some(_obj) => Ok(0), // _obj drops → auto-close channel or dec_ref SHM
        None => Err(SyscallError::Error),
    }
}
