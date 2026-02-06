/// No capability sentinel
pub const NO_CAP: usize = usize::MAX;

/// Fixed-size message matching kernel's ipc::Message layout exactly.
#[repr(C)]
pub struct Message {
    pub data: [u8; 64],
    pub len: usize,
    pub sender_pid: usize,
    pub cap: usize,
}

impl Message {
    pub fn new() -> Self {
        Message {
            data: [0u8; 64],
            len: 0,
            sender_pid: 0,
            cap: NO_CAP,
        }
    }
}

#[inline(always)]
fn syscall0(num: usize) -> usize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") 0usize => ret,
            in("a7") num,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn syscall1(num: usize, a0: usize) -> usize {
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
fn syscall2(num: usize, a0: usize, a1: usize) -> (usize, usize) {
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

pub fn sys_exit(code: usize) -> ! {
    syscall1(93, code);
    loop {}
}

pub fn sys_yield() {
    syscall0(124);
}

pub fn sys_getpid() -> usize {
    syscall0(172)
}

/// Create a bidirectional channel pair. Returns (handle_a, handle_b).
pub fn sys_chan_create() -> (usize, usize) {
    syscall2(200, 0, 0)
}

pub fn sys_chan_send(handle: usize, msg: &Message) -> usize {
    let (ret, _) = syscall2(201, handle, msg as *const Message as usize);
    ret
}

pub fn sys_chan_recv(handle: usize, msg: &mut Message) -> usize {
    let (ret, _) = syscall2(202, handle, msg as *mut Message as usize);
    ret
}

pub fn sys_chan_close(handle: usize) {
    syscall1(203, handle);
}

/// Blocking receive: blocks until a message is available.
pub fn sys_chan_recv_blocking(handle: usize, msg: &mut Message) -> usize {
    let (ret, _) = syscall2(204, handle, msg as *mut Message as usize);
    ret
}
