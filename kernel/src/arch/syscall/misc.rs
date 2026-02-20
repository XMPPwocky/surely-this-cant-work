//! Miscellaneous syscalls: exit, trace.

use super::{validate_user_buffer, SyscallResult, SyscallError};

pub fn sys_exit() {
    crate::task::exit_current_from_syscall();
}

/// SYS_KILL: terminate another process by PID.
/// a0 = target PID, a1 = exit code.
pub fn sys_kill(target_pid: usize, exit_code: usize) -> SyscallResult {
    match crate::task::terminate_process(target_pid, exit_code as i32) {
        Ok(()) => Ok(0),
        Err(_) => Err(SyscallError::Error),
    }
}

/// SYS_TRACE: record a timestamped trace entry.
/// a0 = pointer to label string, a1 = label length.
pub fn sys_trace(label_ptr: usize, label_len: usize) -> SyscallResult {
    if label_len == 0 || label_len > 32 {
        return Err(SyscallError::Error);
    }
    let pa = validate_user_buffer(label_ptr, label_len)?;
    let label = unsafe { core::slice::from_raw_parts(pa as *const u8, label_len) };
    crate::trace::trace_push(crate::task::current_pid(), label);
    Ok(0)
}
