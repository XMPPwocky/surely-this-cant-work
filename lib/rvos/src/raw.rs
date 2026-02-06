//! Raw syscall wrappers and constants.

pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;
pub const SYS_CHAN_RECV_BLOCKING: usize = 204;
pub const SYS_HANDLE_RELEASE: usize = 207;

/// No capability sentinel value.
pub const NO_CAP: usize = usize::MAX;

#[inline(always)]
pub fn syscall0(num: usize) -> (usize, usize) {
    let ret0: usize;
    let ret1: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") 0usize => ret0,
            lateout("a1") ret1,
            in("a7") num,
            options(nostack),
        );
    }
    (ret0, ret1)
}

#[inline(always)]
pub fn syscall1(num: usize, a0: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") a0 => ret,
            in("a7") num,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub fn syscall2(num: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") a0 => ret,
            in("a1") a1,
            in("a7") num,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
pub fn syscall2_ret2(num: usize, a0: usize, a1: usize) -> (usize, usize) {
    let ret0: usize;
    let ret1: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") a0 => ret0,
            inlateout("a1") a1 => ret1,
            in("a7") num,
            options(nostack),
        );
    }
    (ret0, ret1)
}

// --- Convenience wrappers matching common userland syscall modules ---

use crate::message::Message;

/// Create a bidirectional channel pair. Returns (handle_a, handle_b).
pub fn sys_chan_create() -> (usize, usize) {
    syscall0(SYS_CHAN_CREATE)
}

/// Send a message on a channel handle.
pub fn sys_chan_send(handle: usize, msg: &Message) -> usize {
    syscall2(SYS_CHAN_SEND, handle, msg as *const Message as usize)
}

/// Blocking receive on a channel handle.
pub fn sys_chan_recv_blocking(handle: usize, msg: &mut Message) -> usize {
    syscall2(SYS_CHAN_RECV_BLOCKING, handle, msg as *mut Message as usize)
}

/// Close a channel handle.
pub fn sys_chan_close(handle: usize) {
    syscall1(SYS_CHAN_CLOSE, handle);
}

/// Release a local handle slot without closing the underlying channel.
/// Used after sending a capability to free the sender's copy.
pub fn sys_handle_release(handle: usize) {
    syscall1(SYS_HANDLE_RELEASE, handle);
}
