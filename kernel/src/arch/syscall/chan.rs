//! Channel IPC syscalls: create, send, recv, close, poll.

use crate::arch::trap::TrapFrame;
use crate::task::HandleObject;
use super::{validate_user_buffer, translate_cap_for_send, rollback_encoded_cap, install_received_caps};

/// SYS_CHAN_CREATE: create a bidirectional channel pair.
/// Returns handle_a in a0, handle_b in a1.
pub fn sys_chan_create(tf: &mut TrapFrame) {
    let (ep_a, ep_b) = match crate::ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };
    let handle_a = match crate::task::current_process_alloc_handle(HandleObject::Channel(ep_a)) {
        Some(h) => h,
        None => {
            crate::ipc::channel_close(ep_a);
            crate::ipc::channel_close(ep_b);
            tf.regs[10] = usize::MAX;
            return;
        }
    };
    let handle_b = match crate::task::current_process_alloc_handle(HandleObject::Channel(ep_b)) {
        Some(h) => h,
        None => {
            crate::task::current_process_free_handle(handle_a);
            crate::ipc::channel_close(ep_a);
            crate::ipc::channel_close(ep_b);
            tf.regs[10] = usize::MAX;
            return;
        }
    };
    tf.regs[10] = handle_a;
    tf.regs[11] = handle_b;
}

/// SYS_CHAN_SEND: translate handle -> endpoint, copy message from user, send.
pub fn sys_chan_send(handle: usize, msg_ptr: usize) -> usize {
    let msg_pa = match validate_user_buffer(msg_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => return usize::MAX,
    };

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => return usize::MAX,
    };

    let mut msg = unsafe { core::ptr::read(msg_pa as *const crate::ipc::Message) };

    msg.len = msg.len.min(crate::ipc::MAX_MSG_SIZE);
    msg.cap_count = msg.cap_count.min(crate::ipc::MAX_CAPS);
    msg.sender_pid = crate::task::current_pid();

    // Translate all caps: local handle -> encoded capability
    let mut translated = 0usize;
    for i in 0..msg.cap_count {
        match translate_cap_for_send(msg.caps[i]) {
            Some(encoded) => {
                msg.caps[i] = encoded;
                translated += 1;
            }
            None => {
                for j in 0..translated {
                    rollback_encoded_cap(msg.caps[j]);
                }
                return usize::MAX;
            }
        }
    }

    let wake_pid = match crate::ipc::channel_send_ref(endpoint, &msg) {
        Ok(w) => w,
        Err(crate::ipc::SendError::QueueFull) => return 5,
        Err(_) => return usize::MAX,
    };
    if wake_pid != 0 {
        crate::task::wake_process(wake_pid);
    }
    0
}

/// SYS_CHAN_RECV (non-blocking): translate handle, try recv, translate caps.
pub fn sys_chan_recv(handle: usize, msg_buf_ptr: usize) -> usize {
    let msg_pa = match validate_user_buffer(msg_buf_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => return usize::MAX,
    };

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => return usize::MAX,
    };

    let (msg, send_wake) = crate::ipc::channel_recv(endpoint);
    if send_wake != 0 {
        crate::task::wake_process(send_wake);
    }
    match msg {
        Some(mut msg) => {
            install_received_caps(&mut msg);
            unsafe {
                core::ptr::write(msg_pa as *mut crate::ipc::Message, msg);
            }
            0
        }
        None => {
            if !crate::ipc::channel_is_active(endpoint) {
                2 // ChannelClosed
            } else {
                1 // Nothing available
            }
        }
    }
}

/// SYS_CHAN_RECV_BLOCKING: like recv but blocks if empty.
pub fn sys_chan_recv_blocking(tf: &mut TrapFrame) {
    let handle = tf.regs[10];
    let msg_buf_ptr = tf.regs[11];
    let msg_pa = match validate_user_buffer(msg_buf_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    let cur_pid = crate::task::current_pid();
    loop {
        let (msg, send_wake) = crate::ipc::channel_recv(endpoint);
        if send_wake != 0 {
            crate::task::wake_process(send_wake);
        }
        match msg {
            Some(mut msg) => {
                install_received_caps(&mut msg);
                unsafe {
                    core::ptr::write(msg_pa as *mut crate::ipc::Message, msg);
                }
                tf.regs[10] = 0;
                return;
            }
            None => {
                if !crate::ipc::channel_is_active(endpoint) {
                    tf.regs[10] = 2; // ChannelClosed
                    return;
                }
                crate::ipc::channel_set_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
            }
        }
    }
}

/// SYS_CHAN_SEND_BLOCKING: like send but blocks if queue full.
pub fn sys_chan_send_blocking(tf: &mut TrapFrame) {
    let handle = tf.regs[10];
    let msg_ptr = tf.regs[11];
    let msg_pa = match validate_user_buffer(msg_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    let mut msg = unsafe { core::ptr::read(msg_pa as *const crate::ipc::Message) };
    msg.len = msg.len.min(crate::ipc::MAX_MSG_SIZE);
    msg.cap_count = msg.cap_count.min(crate::ipc::MAX_CAPS);
    msg.sender_pid = crate::task::current_pid();

    let mut translated = 0usize;
    for i in 0..msg.cap_count {
        match translate_cap_for_send(msg.caps[i]) {
            Some(encoded) => {
                msg.caps[i] = encoded;
                translated += 1;
            }
            None => {
                for j in 0..translated {
                    rollback_encoded_cap(msg.caps[j]);
                }
                tf.regs[10] = usize::MAX;
                return;
            }
        }
    }

    let cur_pid = crate::task::current_pid();
    loop {
        match crate::ipc::channel_send_ref(endpoint, &msg) {
            Ok(wake) => {
                if wake != 0 {
                    crate::task::wake_process(wake);
                }
                tf.regs[10] = 0;
                return;
            }
            Err(crate::ipc::SendError::QueueFull) => {
                if !crate::ipc::channel_is_active(endpoint) {
                    tf.regs[10] = usize::MAX;
                    return;
                }
                crate::ipc::channel_set_send_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
            }
            Err(_) => {
                tf.regs[10] = usize::MAX;
                return;
            }
        }
    }
}

/// SYS_CHAN_POLL_ADD: register the calling process as blocked-waiting on a
/// channel handle so that any future send to that endpoint will wake us.
pub fn sys_chan_poll_add(handle: usize) -> usize {
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => return usize::MAX,
    };
    let pid = crate::task::current_pid();
    crate::ipc::channel_set_blocked(endpoint, pid);
    0
}

/// SYS_CHAN_CLOSE: close a handle (channel or SHM).
pub fn sys_chan_close(handle: usize) -> usize {
    match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => {
            crate::task::current_process_free_handle(handle);
            crate::ipc::channel_close(ep);
            0
        }
        Some(HandleObject::Shm { id, .. }) => {
            crate::task::current_process_free_handle(handle);
            crate::ipc::shm_dec_ref(id);
            0
        }
        None => usize::MAX,
    }
}
