//! Miscellaneous syscalls: exit, trace.

use super::validate_user_buffer;

pub fn sys_exit() {
    crate::task::exit_current_from_syscall();
}

/// SYS_TRACE: record a timestamped trace entry.
/// a0 = pointer to label string, a1 = label length.
pub fn sys_trace(label_ptr: usize, label_len: usize) -> usize {
    if label_len == 0 || label_len > 32 {
        return usize::MAX;
    }
    let pa = match validate_user_buffer(label_ptr, label_len) {
        Some(pa) => pa,
        None => return usize::MAX,
    };
    let label = unsafe { core::slice::from_raw_parts(pa as *const u8, label_len) };
    crate::trace::trace_push(crate::task::current_pid(), label);
    0
}
