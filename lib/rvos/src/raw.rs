//! Raw syscall wrappers and constants.

pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;
pub const SYS_CHAN_RECV_BLOCKING: usize = 204;

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
