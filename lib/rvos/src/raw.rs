//! Raw syscall wrappers and constants.

pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;
pub const SYS_CHAN_RECV_BLOCKING: usize = 204;
pub const SYS_SHM_CREATE: usize = 205;
pub const SYS_SHM_DUP_RO: usize = 206;
pub const SYS_CHAN_SEND_BLOCKING: usize = 207;
pub const SYS_CHAN_POLL_ADD: usize = 208;
pub const SYS_BLOCK: usize = 209;
pub const SYS_BLOCK_DEADLINE: usize = 210;
pub const SYS_MUNMAP: usize = 215;
pub const SYS_MMAP: usize = 222;
pub const SYS_TRACE: usize = 230;
pub const SYS_SHUTDOWN: usize = 231;
pub const SYS_CLOCK: usize = 232;
pub const SYS_MEMINFO: usize = 233;
pub const SYS_KILL: usize = 234;
pub const SYS_HEARTBEAT: usize = 235;

/// No capability sentinel value.
pub const NO_CAP: usize = usize::MAX;

/// Syscall return codes (matches kernel SyscallError ABI).
pub const CHAN_CLOSED: usize = 2;

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

/// Yield the current time slice.
pub fn sys_yield() {
    syscall0(SYS_YIELD);
}

/// Record a timestamped trace event in the kernel ring buffer.
pub fn sys_trace(label: &[u8]) -> usize {
    syscall2(SYS_TRACE, label.as_ptr() as usize, label.len())
}

/// Blocking send on a channel handle. Blocks if queue is full.
pub fn sys_chan_send_blocking(handle: usize, msg: &Message) -> usize {
    syscall2(SYS_CHAN_SEND_BLOCKING, handle, msg as *const Message as usize)
}

/// Send a message, blocking if queue is full.
pub fn sys_chan_send_retry(handle: usize, msg: &Message) -> usize {
    sys_chan_send_blocking(handle, msg)
}

/// Shut down the system. Does not return.
pub fn sys_shutdown() -> ! {
    syscall0(SYS_SHUTDOWN);
    unreachable!()
}

/// Read wall-clock and global CPU ticks. Returns (wall_ticks, global_cpu_ticks).
pub fn sys_clock() -> (u64, u64) {
    let (a0, a1) = syscall0(SYS_CLOCK);
    (a0 as u64, a1 as u64)
}

/// Non-blocking receive on a channel handle.
/// Returns 0 on success (message filled in), 1 if no message available.
pub fn sys_chan_recv(handle: usize, msg: &mut Message) -> usize {
    syscall2(SYS_CHAN_RECV, handle, msg as *mut Message as usize)
}

/// Create a shared memory region. Returns the SHM handle.
pub fn sys_shm_create(size: usize) -> usize {
    syscall1(SYS_SHM_CREATE, size)
}

/// Duplicate a SHM handle as read-only. Returns a new handle.
pub fn sys_shm_dup_ro(handle: usize) -> usize {
    syscall1(SYS_SHM_DUP_RO, handle)
}

/// Map an SHM handle (or anonymous pages if handle=0) into process address space.
/// Returns the mapped virtual address, or usize::MAX on error.
pub fn sys_mmap(shm_handle: usize, length: usize) -> usize {
    syscall2(SYS_MMAP, shm_handle, length)
}

/// Map memory into process address space with error handling.
/// `shm_handle`: SHM handle to map, or 0 for anonymous pages.
/// Returns a pointer to the mapped region on success.
pub fn mmap(shm_handle: usize, length: usize) -> Result<*mut u8, crate::SysError> {
    let addr = syscall2(SYS_MMAP, shm_handle, length);
    if addr == usize::MAX {
        Err(crate::SysError::NoResources)
    } else {
        Ok(addr as *mut u8)
    }
}

/// Unmap pages from process address space.
pub fn sys_munmap(addr: usize, length: usize) -> usize {
    syscall2(SYS_MUNMAP, addr, length)
}

/// Register interest in a channel handle for poll-style multiplexing.
/// After calling this for each handle of interest, call `sys_block()` to sleep.
/// The process will be woken when any registered channel receives a message.
pub fn sys_chan_poll_add(handle: usize) -> usize {
    syscall1(SYS_CHAN_POLL_ADD, handle)
}

/// Block the calling process until woken by a channel event.
/// Typically used after one or more `sys_chan_poll_add()` calls.
pub fn sys_block() {
    syscall0(SYS_BLOCK);
}

/// Block the calling process until woken by a channel event or the given
/// deadline (in rdtime ticks) is reached — whichever comes first.
/// Typically used after one or more `sys_chan_poll_add()` calls.
pub fn sys_block_deadline(deadline: u64) {
    syscall1(SYS_BLOCK_DEADLINE, deadline as usize);
}

/// Kernel memory statistics returned by `sys_meminfo()`.
#[repr(C)]
pub struct MemInfo {
    pub heap_used: usize,
    pub heap_total: usize,
    pub frames_used: usize,
    pub frames_total: usize,
    pub proc_mem_pages: usize,
}

/// Query kernel memory statistics.
/// Returns 0 on success, usize::MAX on error.
pub fn sys_meminfo(info: &mut MemInfo) -> usize {
    syscall1(SYS_MEMINFO, info as *mut MemInfo as usize)
}

/// Kill a process by PID. Returns 0 on success, usize::MAX on error.
pub fn sys_kill(pid: usize, exit_code: i32) -> usize {
    syscall2(SYS_KILL, pid, exit_code as usize)
}

/// Pet the system watchdog. Updates the calling process's heartbeat timestamp.
/// Critical processes should call this in their main loop.
/// Returns the recommended maximum blocking duration in rdtime ticks (half the
/// watchdog timeout). Returns 0 if the watchdog is disabled — callers should
/// interpret 0 as "block forever."
pub fn sys_heartbeat() -> u64 {
    syscall0(SYS_HEARTBEAT).0 as u64
}

