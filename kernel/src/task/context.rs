use crate::arch::csr;
use crate::arch::trap::TrapFrame;

/// Per-task trap context. Lives in the Process struct.
/// `sscratch` always points to the current task's TrapContext.
///
/// Layout (offsets used by trap.S):
///   0..255   TrapFrame.regs[0..31]   (32 × 8 = 256 bytes)
///   256..511 TrapFrame.fpregs[0..31] (32 × 8 = 256 bytes, f0-f31)
///   512      TrapFrame.fcsr          (8 bytes)
///   520      TrapFrame.sstatus       (8 bytes)
///   528      TrapFrame.sepc          (8 bytes)
///   536      kernel_stack_top
///   544      user_satp
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
        extern "C" {
            fn kernel_task_return_handler();
        }
        // sstatus: SPP=1 (return to S-mode), SPIE=1, FS=Initial (FPU on)
        let sstatus = csr::SSTATUS_SPP | csr::SSTATUS_SPIE | csr::SSTATUS_FS_INITIAL;
        let mut frame = TrapFrame::zero();
        frame.sepc = entry;
        frame.sstatus = sstatus;
        frame.regs[1] = kernel_task_return_handler as *const () as usize; // ra
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
        // sstatus: SPP=0 (return to U-mode), SPIE=1, SUM=1, FS=Initial (FPU on)
        let sstatus = csr::SSTATUS_SPIE | csr::SSTATUS_SUM | csr::SSTATUS_FS_INITIAL;
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
    pub ra: usize,       // offset 0
    pub sp: usize,       // offset 8
    pub s0: usize,       // offset 16
    pub s1: usize,       // offset 24
    pub s2: usize,       // offset 32
    pub s3: usize,       // offset 40
    pub s4: usize,       // offset 48
    pub s5: usize,       // offset 56
    pub s6: usize,       // offset 64
    pub s7: usize,       // offset 72
    pub s8: usize,       // offset 80
    pub s9: usize,       // offset 88
    pub s10: usize,      // offset 96
    pub s11: usize,      // offset 104
    pub fs0: u64,        // offset 112   (callee-saved FP: f8)
    pub fs1: u64,        // offset 120   (f9)
    pub fs2: u64,        // offset 128   (f18)
    pub fs3: u64,        // offset 136   (f19)
    pub fs4: u64,        // offset 144   (f20)
    pub fs5: u64,        // offset 152   (f21)
    pub fs6: u64,        // offset 160   (f22)
    pub fs7: u64,        // offset 168   (f23)
    pub fs8: u64,        // offset 176   (f24)
    pub fs9: u64,        // offset 184   (f25)
    pub fs10: u64,       // offset 192   (f26)
    pub fs11: u64,       // offset 200   (f27)
    pub fcsr: usize,     // offset 208   (only low 32 bits used)
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
            fs0: 0,
            fs1: 0,
            fs2: 0,
            fs3: 0,
            fs4: 0,
            fs5: 0,
            fs6: 0,
            fs7: 0,
            fs8: 0,
            fs9: 0,
            fs10: 0,
            fs11: 0,
            fcsr: 0,
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
            ..Self::zero()
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
            ..Self::zero()
        }
    }
}

// Compile-time assertions: trap.S uses hardcoded offsets into TrapContext.
// If you change the layout of TrapFrame or TrapContext, update trap.S too.
const _: () = {
    assert!(core::mem::offset_of!(TrapFrame, regs) == 0);
    assert!(core::mem::size_of::<[usize; 32]>() == 256);
    assert!(core::mem::offset_of!(TrapFrame, fpregs) == 256);
    assert!(core::mem::offset_of!(TrapFrame, fcsr) == 512);
    assert!(core::mem::offset_of!(TrapFrame, sstatus) == 520);
    assert!(core::mem::offset_of!(TrapFrame, sepc) == 528);
    assert!(core::mem::offset_of!(TrapContext, frame) == 0);
    assert!(core::mem::offset_of!(TrapContext, kernel_stack_top) == 536);
    assert!(core::mem::offset_of!(TrapContext, user_satp) == 544);
};
