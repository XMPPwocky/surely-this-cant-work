#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskContext {
    pub ra: usize,
    pub sp: usize,
    pub s0: usize,
    pub s1: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
}

impl TaskContext {
    pub const fn zero() -> Self {
        TaskContext {
            ra: 0,
            sp: 0,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
        }
    }

    /// Create a new context for a kernel task.
    /// ra = kernel_task_trampoline (enables interrupts), s0 = real entry fn.
    pub fn new(entry: usize, stack_top: usize) -> Self {
        extern "C" {
            fn kernel_task_trampoline();
        }
        TaskContext {
            ra: kernel_task_trampoline as usize,
            sp: stack_top,
            s0: entry,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
        }
    }

    /// Create a context for a user process.
    /// The ra points to user_entry_trampoline which will sret into user mode.
    /// The sp is set to the kernel stack top for this process.
    pub fn new_user_entry(kernel_stack_top: usize) -> Self {
        extern "C" {
            fn user_entry_trampoline();
        }
        TaskContext {
            ra: user_entry_trampoline as usize,
            sp: kernel_stack_top,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
        }
    }
}
