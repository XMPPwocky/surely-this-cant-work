pub mod context;
pub mod process;
pub mod scheduler;

pub use process::{BlockReason, HandleObject, HandleInfo};
pub use scheduler::{
    init, spawn_named, set_block_reason,
    spawn_user_elf_with_boot_channel,
    spawn_user_elf_with_handles,
    schedule, preempt, current_pid, try_current_pid, current_process_channel_count, global_clock,
    terminate_current_process, terminate_process, exit_current_from_syscall,
    block_process, block_with_deadline, force_block_process, wake_process, save_kernel_satp,
    check_deadlines,
    process_list, process_mem_list,
    current_process_handle, current_process_alloc_handle, current_process_take_handle,
    current_process_user_satp, current_process_add_mmap, current_process_remove_mmap,
    current_process_mem_pages, current_process_adjust_mem_pages,
    set_exit_notify_ep,
    // Debug accessors
    process_is_user, process_debug_attached, set_process_debug_state,
    set_debug_suspend_pending, check_and_clear_debug_suspend,
    mark_debug_suspended, clear_debug_suspended,
    read_debug_trap_frame, write_debug_register, write_debug_sepc,
    process_user_satp_by_pid, process_debug_event_ep,
    process_debug_breakpoints, set_process_debug_breakpoints,
};
