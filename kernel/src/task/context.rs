use crate::arch::csr;
use crate::arch::trap::TrapFrame;

/// Per-task trap context. Lives in the Process struct.
/// `sscratch` always points to the current task's TrapContext.
///
/// Layout (offsets used by trap.S):
///   0..272   TrapFrame (regs[32] + sstatus + sepc)
///   272      kernel_stack_top
///   280      user_satp
#[repr(C)]
pub struct TrapContext {
    pub frame: TrapFrame,
    /// Kernel stack pointer for this task. Used by user-mode trap entry
    /// as the handler stack (sp). Unused for kernel-mode traps (which use
    /// the shared KERNEL_TRAP_STACK).
    pub kernel_stack_top: usize,
    /// User page table satp value. Used by trap exit to switch satp before
    /// returning to user mode. 0 for kernel tasks.
    pub user_satp: usize,
}

impl TrapContext {
    /// Create a zeroed TrapContext (for idle task / kernel tasks before first run).
    pub const fn zero() -> Self {
        TrapContext {
            frame: TrapFrame::zero(),
            kernel_stack_top: 0,
            user_satp: 0,
        }
    }

    /// Create a TrapContext for a kernel task's first run via sret.
    /// sepc = entry function, sstatus has SPP=1 (S-mode) and SPIE=1.
    pub fn new_kernel(entry: usize, stack_top: usize) -> Self {
        // sstatus: SPP=1 (return to S-mode), SPIE=1 (enable interrupts after sret)
        let sstatus = csr::SSTATUS_SPP | csr::SSTATUS_SPIE;
        let mut frame = TrapFrame::zero();
        frame.sepc = entry;
        frame.sstatus = sstatus;
        frame.regs[2] = stack_top; // sp
        TrapContext {
            frame,
            kernel_stack_top: 0, // unused for kernel tasks
            user_satp: 0,
        }
    }

    /// Create a TrapContext for a user task's first run via sret.
    /// sepc = user entry point, sstatus has SPP=0 (U-mode), SPIE=1, SUM=1.
    pub fn new_user(
        entry: usize,
        user_stack_top: usize,
        kernel_stack_top: usize,
        user_satp: usize,
    ) -> Self {
        // sstatus: SPP=0 (return to U-mode), SPIE=1, SUM=1
        let sstatus = csr::SSTATUS_SPIE | csr::SSTATUS_SUM;
        let mut frame = TrapFrame::zero();
        frame.sepc = entry;
        frame.sstatus = sstatus;
        frame.regs[2] = user_stack_top; // sp = user stack
        TrapContext {
            frame,
            kernel_stack_top,
            user_satp,
        }
    }
}

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
    /// ra = kernel_task_trampoline, s0 = real entry fn.
    /// s1 is set later (after Process is placed in the Vec) to the TrapContext ptr.
    pub fn new(entry: usize, stack_top: usize) -> Self {
        extern "C" {
            fn kernel_task_trampoline();
        }
        TaskContext {
            ra: kernel_task_trampoline as *const () as usize,
            sp: stack_top,
            s0: entry,
            s1: 0, // set to &trap_ctx after process is in its final location
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
    /// s1 is set later to the TrapContext ptr.
    pub fn new_user_entry(kernel_stack_top: usize) -> Self {
        extern "C" {
            fn user_entry_trampoline();
        }
        TaskContext {
            ra: user_entry_trampoline as *const () as usize,
            sp: kernel_stack_top,
            s0: 0,
            s1: 0, // set to &trap_ctx after process is in its final location
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
