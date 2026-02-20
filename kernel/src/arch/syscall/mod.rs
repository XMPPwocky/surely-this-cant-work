//! Syscall dispatch and shared utilities.
//!
//! Syscall handlers are split by group:
//! - `chan.rs`  — channel IPC (create, send, recv, close, poll)
//! - `mem.rs`   — memory mapping (mmap, munmap, shm)
//! - `misc.rs`  — process lifecycle, tracing, clock, shutdown

mod chan;
mod mem;
mod misc;

use crate::arch::sbi;
use crate::arch::trap::TrapFrame;

// Syscall numbers
pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;
pub const SYS_CHAN_RECV_BLOCKING: usize = 204;
pub const SYS_CHAN_SEND_BLOCKING: usize = 207;
pub const SYS_SHM_CREATE: usize = 205;
pub const SYS_SHM_DUP_RO: usize = 206;
pub const SYS_CHAN_POLL_ADD: usize = 208;
pub const SYS_BLOCK: usize = 209;
pub const SYS_MUNMAP: usize = 215;
pub const SYS_MMAP: usize = 222;
pub const SYS_TRACE: usize = 230;
pub const SYS_SHUTDOWN: usize = 231;
pub const SYS_CLOCK: usize = 232;
pub const SYS_MEMINFO: usize = 233;
pub const SYS_KILL: usize = 234;

/// Syscall error type used by all handlers. Converted to a raw usize at the
/// ABI boundary in `handle_syscall`. User-space code in `lib/rvos/src/raw.rs`
/// must decode these same values.
pub(super) enum SyscallError {
    /// Generic error (invalid handle, bad address, resource exhaustion).
    /// ABI value: `usize::MAX`
    Error,
    /// Non-blocking recv found no message.
    /// ABI value: 1
    Empty,
    /// Channel is closed / deactivated.
    /// ABI value: 2
    ChannelClosed,
    /// Non-blocking send: queue is full.
    /// ABI value: 5
    QueueFull,
}

impl SyscallError {
    /// Encode as the raw usize returned to user space in a0.
    fn into_raw(self) -> usize {
        match self {
            SyscallError::Error => usize::MAX,
            SyscallError::Empty => 1,
            SyscallError::ChannelClosed => 2,
            SyscallError::QueueFull => 5,
        }
    }
}

/// Result type for syscall handlers. `Ok(value)` is written to a0;
/// `Err(e)` is encoded via `SyscallError::into_raw()`.
pub(super) type SyscallResult = Result<usize, SyscallError>;

/// Convert a status-only SyscallResult (Ok value is always 0) to raw a0.
///
/// Debug-asserts that the success value doesn't collide with any error code.
/// Use `value_result_to_a0` for syscalls that return handles or addresses.
fn result_to_a0(r: SyscallResult) -> usize {
    match r {
        Ok(v) => {
            debug_assert!(
                !is_error_code(v),
                "syscall Ok({v:#x}) overlaps with error code — \
                 use value_result_to_a0 for value-returning syscalls"
            );
            v
        }
        Err(e) => e.into_raw(),
    }
}

/// Convert a value-returning SyscallResult (Ok value is a handle or address)
/// to raw a0. These syscalls only use `SyscallError::Error` (= usize::MAX),
/// so any Ok value != usize::MAX is unambiguous.
fn value_result_to_a0(r: SyscallResult) -> usize {
    match r {
        Ok(v) => {
            debug_assert_ne!(
                v, usize::MAX,
                "syscall Ok(usize::MAX) is indistinguishable from Error"
            );
            v
        }
        Err(e) => e.into_raw(),
    }
}

/// Returns true if `v` matches any SyscallError encoding.
const fn is_error_code(v: usize) -> bool {
    matches!(v, 1 | 2 | 5 | usize::MAX)
}

/// Set to true to log every syscall (except yield) to the trace ring buffer.
const TRACE_SYSCALLS: bool = false;

pub fn handle_syscall(tf: &mut TrapFrame) {
    tf.sepc += 4;

    let syscall_num = tf.regs[17]; // a7
    let a0 = tf.regs[10];
    let a1 = tf.regs[11];

    // Capture args before dispatch (some handlers overwrite regs)
    let saved_a0 = a0;
    let saved_a1 = a1;

    match syscall_num {
        SYS_EXIT => {
            misc::sys_exit();
        }
        SYS_YIELD => {
            crate::kstat::inc(&crate::kstat::SCHED_YIELDS);
            crate::task::schedule();
            tf.regs[10] = 0;
        }
        SYS_GETPID => {
            tf.regs[10] = crate::task::current_pid();
        }
        SYS_CHAN_CREATE => {
            match chan::sys_chan_create() {
                Ok((ha, hb)) => {
                    tf.regs[10] = ha;
                    tf.regs[11] = hb;
                }
                Err(e) => tf.regs[10] = e.into_raw(),
            }
        }
        SYS_CHAN_SEND => {
            tf.regs[10] = result_to_a0(chan::sys_chan_send(a0, a1));
        }
        SYS_CHAN_RECV => {
            tf.regs[10] = result_to_a0(chan::sys_chan_recv(a0, a1));
        }
        SYS_CHAN_CLOSE => {
            tf.regs[10] = result_to_a0(chan::sys_chan_close(a0));
        }
        SYS_CHAN_RECV_BLOCKING => {
            tf.regs[10] = result_to_a0(chan::sys_chan_recv_blocking(a0, a1));
        }
        SYS_CHAN_SEND_BLOCKING => {
            tf.regs[10] = result_to_a0(chan::sys_chan_send_blocking(a0, a1));
        }
        SYS_CHAN_POLL_ADD => {
            tf.regs[10] = result_to_a0(chan::sys_chan_poll_add(a0));
        }
        SYS_BLOCK => {
            let pid = crate::task::current_pid();
            crate::task::block_process(pid);
            crate::task::schedule();
            tf.regs[10] = 0;
        }
        SYS_SHM_CREATE => {
            tf.regs[10] = value_result_to_a0(mem::sys_shm_create(a0));
        }
        SYS_SHM_DUP_RO => {
            tf.regs[10] = value_result_to_a0(mem::sys_shm_dup_ro(a0));
        }
        SYS_MMAP => {
            tf.regs[10] = value_result_to_a0(mem::sys_mmap(a0, a1));
        }
        SYS_MUNMAP => {
            tf.regs[10] = result_to_a0(mem::sys_munmap(a0, a1));
        }
        SYS_TRACE => {
            tf.regs[10] = result_to_a0(misc::sys_trace(a0, a1));
        }
        SYS_SHUTDOWN => {
            crate::println!("System shutdown requested by PID {}", crate::task::current_pid());
            sbi::sbi_shutdown();
        }
        SYS_CLOCK => {
            let (wall, cpu) = crate::task::global_clock();
            tf.regs[10] = wall as usize;
            tf.regs[11] = cpu as usize;
        }
        SYS_MEMINFO => {
            tf.regs[10] = result_to_a0(mem::sys_meminfo(a0));
        }
        SYS_KILL => {
            tf.regs[10] = result_to_a0(misc::sys_kill(a0, a1));
        }
        _ => {
            crate::println!("Unknown syscall: {}", syscall_num);
            tf.regs[10] = SyscallError::Error.into_raw();
        }
    }

    if TRACE_SYSCALLS && syscall_num != SYS_YIELD {
        let pid = crate::task::current_pid();
        let ret = tf.regs[10];
        trace_syscall(pid, syscall_num, saved_a0, saved_a1, ret);
    }
}

// ============================================================
// Shared utilities used by multiple syscall groups
// ============================================================

/// Translate a user virtual address to a physical address by walking the
/// current process's Sv39 page table. Returns None if unmapped.
pub(super) fn translate_user_va(va: usize) -> Option<usize> {
    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        return None;
    }
    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let pt = crate::mm::page_table::PageTable::from_root(root_ppn);
    let vpn = crate::mm::address::VirtPageNum(va / crate::mm::address::PAGE_SIZE);
    pt.translate(vpn).map(|ppn| {
        ppn.0 * crate::mm::address::PAGE_SIZE + (va % crate::mm::address::PAGE_SIZE)
    })
}

/// Validate a user buffer and return its physical address.
/// Walks the user page table to translate VA->PA. Logs an error on failure.
pub(super) fn validate_user_buffer(ptr: usize, len: usize) -> Result<usize, SyscallError> {
    if len == 0 {
        return Err(SyscallError::Error);
    }
    let pa = match translate_user_va(ptr) {
        Some(pa) => pa,
        None => {
            crate::println!(
                "[syscall] PID {}: invalid user pointer {:#x} (len={}), page not mapped",
                crate::task::current_pid(), ptr, len
            );
            return Err(SyscallError::Error);
        }
    };

    // For cross-page buffers, verify all pages are mapped and contiguous in PA
    let end = match ptr.checked_add(len - 1) {
        Some(e) => e,
        None => {
            crate::println!(
                "[syscall] PID {}: user buffer {:#x}+{} overflows address space",
                crate::task::current_pid(), ptr, len
            );
            return Err(SyscallError::Error);
        }
    };
    let start_page = ptr / crate::mm::address::PAGE_SIZE;
    let end_page = end / crate::mm::address::PAGE_SIZE;
    let pa_base_page = pa / crate::mm::address::PAGE_SIZE;
    for i in 1..=(end_page - start_page) {
        match translate_user_va((start_page + i) * crate::mm::address::PAGE_SIZE) {
            Some(next_pa) if next_pa / crate::mm::address::PAGE_SIZE == pa_base_page + i => {}
            _ => {
                crate::println!(
                    "[syscall] PID {}: user buffer {:#x}+{} spans non-contiguous pages",
                    crate::task::current_pid(), ptr, len
                );
                return Err(SyscallError::Error);
            }
        }
    }
    Ok(pa)
}

/// User-space ABI message layout for ptr::read/write at the syscall boundary.
/// Must match the user-space `Message` in `lib/rvos/src/message.rs`.
/// The kernel `Message` now uses RAII `Cap` types, so this raw struct is
/// needed to translate between user-space ABI and kernel representations.
#[repr(C)]
pub(super) struct UserMessage {
    pub data: [u8; crate::ipc::MAX_MSG_SIZE],
    pub len: usize,
    pub sender_pid: usize,
    pub caps: [usize; crate::ipc::MAX_CAPS],
    pub cap_count: usize,
}

// Compile-time check: UserMessage must match user-space ABI (1080 bytes).
const _: () = assert!(core::mem::size_of::<UserMessage>() == 1080);

// ============================================================
// Syscall tracing helpers
// ============================================================

/// Short name for a syscall number (for trace output).
fn syscall_name(num: usize) -> &'static [u8] {
    match num {
        SYS_EXIT => b"exit",
        SYS_YIELD => b"yield",
        SYS_GETPID => b"getpid",
        SYS_CHAN_CREATE => b"create",
        SYS_CHAN_SEND => b"send",
        SYS_CHAN_RECV => b"recv",
        SYS_CHAN_CLOSE => b"close",
        SYS_CHAN_RECV_BLOCKING => b"recvb",
        SYS_CHAN_SEND_BLOCKING => b"sendb",
        SYS_CHAN_POLL_ADD => b"polladd",
        SYS_BLOCK => b"block",
        SYS_SHM_CREATE => b"shmc",
        SYS_SHM_DUP_RO => b"shmro",
        SYS_MMAP => b"mmap",
        SYS_MUNMAP => b"munmap",
        SYS_TRACE => b"trace",
        SYS_SHUTDOWN => b"shut",
        SYS_CLOCK => b"clock",
        SYS_MEMINFO => b"minfo",
        SYS_KILL => b"kill",
        _ => b"?",
    }
}

/// Format a usize as lowercase hex into buf. Returns bytes written.
fn fmt_hex(mut val: usize, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut i = 0;
    while val > 0 && i < 16 {
        let nibble = (val & 0xF) as u8;
        tmp[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        val >>= 4;
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

/// Log one completed syscall to the trace ring buffer.
fn trace_syscall(pid: usize, num: usize, a0: usize, a1: usize, ret: usize) {
    let mut buf = [0u8; 32];
    let name = syscall_name(num);
    let mut p = 0;
    let n = name.len().min(6);
    buf[p..p + n].copy_from_slice(&name[..n]);
    p += n;
    if p < 31 { buf[p] = b'('; p += 1; }
    p += fmt_hex(a0, &mut buf[p..]);
    if p < 31 { buf[p] = b','; p += 1; }
    p += fmt_hex(a1, &mut buf[p..]);
    if p < 31 { buf[p] = b')'; p += 1; }
    if p < 31 { buf[p] = b'='; p += 1; }
    p += fmt_hex(ret, &mut buf[p..]);
    crate::trace::trace_push(pid, &buf[..p.min(32)]);
}
