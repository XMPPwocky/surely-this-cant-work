    .section .text
    .option arch, +f, +d
    .globl switch_context
    # switch_context(old: *mut TaskContext, new: *const TaskContext)
    # a0 = pointer to old TaskContext (save current state here)
    # a1 = pointer to new TaskContext (load new state from here)
switch_context:
    # Save callee-saved GPRs to old context
    sd      ra,  0(a0)
    sd      sp,  8(a0)
    sd      s0, 16(a0)
    sd      s1, 24(a0)
    sd      s2, 32(a0)
    sd      s3, 40(a0)
    sd      s4, 48(a0)
    sd      s5, 56(a0)
    sd      s6, 64(a0)
    sd      s7, 72(a0)
    sd      s8, 80(a0)
    sd      s9, 88(a0)
    sd      s10, 96(a0)
    sd      s11, 104(a0)

    # Save callee-saved FP registers (fs0-fs11) and fcsr
    fsd     fs0,  112(a0)
    fsd     fs1,  120(a0)
    fsd     fs2,  128(a0)
    fsd     fs3,  136(a0)
    fsd     fs4,  144(a0)
    fsd     fs5,  152(a0)
    fsd     fs6,  160(a0)
    fsd     fs7,  168(a0)
    fsd     fs8,  176(a0)
    fsd     fs9,  184(a0)
    fsd     fs10, 192(a0)
    fsd     fs11, 200(a0)
    frcsr   t0
    sd      t0,   208(a0)

    # Load callee-saved GPRs from new context
    ld      ra,  0(a1)
    ld      sp,  8(a1)
    ld      s0, 16(a1)
    ld      s1, 24(a1)
    ld      s2, 32(a1)
    ld      s3, 40(a1)
    ld      s4, 48(a1)
    ld      s5, 56(a1)
    ld      s6, 64(a1)
    ld      s7, 72(a1)
    ld      s8, 80(a1)
    ld      s9, 88(a1)
    ld      s10, 96(a1)
    ld      s11, 104(a1)

    # Load callee-saved FP registers (fs0-fs11) and fcsr
    fld     fs0,  112(a1)
    fld     fs1,  120(a1)
    fld     fs2,  128(a1)
    fld     fs3,  136(a1)
    fld     fs4,  144(a1)
    fld     fs5,  152(a1)
    fld     fs6,  160(a1)
    fld     fs7,  168(a1)
    fld     fs8,  176(a1)
    fld     fs9,  184(a1)
    fld     fs10, 192(a1)
    fld     fs11, 200(a1)
    ld      t0,   208(a1)
    fscsr   t0

    ret

    .globl kernel_task_trampoline
    .align 2
kernel_task_trampoline:
    # First run of a kernel task. switch_context restored:
    #   s1 = pointer to this task's TrapContext (set by fixup_trap_ctx_ptr)
    #
    # TrapContext.frame is pre-filled with:
    #   sepc    = kernel entry function
    #   sstatus = SPP=1 (S-mode) | SPIE=1 | FS=Initial (FPU on)
    #   sp      = kernel stack top
    #
    # Set sscratch and sret into the kernel task via _restore_from_trap.
    mv      t0, s1
    csrw    sscratch, t0
    j       _restore_from_trap

    .globl user_entry_trampoline
    .align 2
user_entry_trampoline:
    # First run of a user task. switch_context restored:
    #   s1 = pointer to this task's TrapContext (set by fixup_trap_ctx_ptr)
    #
    # TrapContext.frame is pre-filled with:
    #   sepc    = user entry point
    #   sstatus = SPIE=1 | SUM=1 | FS=Initial (FPU on) (SPP=0 for U-mode)
    #   sp      = user stack top
    # TrapContext also has kernel_stack_top and user_satp.
    #
    # Set sscratch and sret into user mode via _restore_from_trap.
    mv      t0, s1
    csrw    sscratch, t0
    j       _restore_from_trap

