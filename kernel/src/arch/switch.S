    .section .text
    .globl switch_context
    # switch_context(old: *mut TaskContext, new: *const TaskContext)
    # a0 = pointer to old TaskContext (save current state here)
    # a1 = pointer to new TaskContext (load new state from here)
switch_context:
    # Save callee-saved registers to old context
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

    # Load callee-saved registers from new context
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

    ret

    .globl kernel_task_trampoline
    .align 2
kernel_task_trampoline:
    # When a kernel task is first scheduled, switch_context loads s0 = entry fn
    # and ret jumps here. We enable interrupts then jump to the entry.
    # Enable sstatus.SIE (bit 1)
    csrsi   sstatus, 2
    # Jump to the actual entry function stored in s0
    jr      s0

    .globl user_entry_trampoline
    .align 2
user_entry_trampoline:
    # This is called (via ret from switch_context) when a user process
    # is scheduled for the first time. At this point:
    #   sp = kernel stack top for this process
    # We need to:
    #   1. Call prepare_user_return() to fill a UserReturnInfo struct
    #   2. Switch satp to user page table
    #   3. Set sscratch = kernel sp
    #   4. Set sepc = user entry point
    #   5. Set sstatus: SPP=0 (user), SPIE=1
    #   6. Set up user sp and sret

    # Allocate 32 bytes on stack for UserReturnInfo struct
    addi    sp, sp, -32
    # Pass pointer to struct as first argument (a0)
    mv      a0, sp
    call    prepare_user_return
    # Now struct on stack: [sp+0]=satp, [sp+8]=sepc, [sp+16]=user_sp, [sp+24]=kernel_sp
    ld      a0, 0(sp)       # satp
    ld      a1, 8(sp)       # sepc
    ld      a2, 16(sp)      # user_sp
    ld      a3, 24(sp)      # kernel_sp
    addi    sp, sp, 32      # deallocate struct

    # Switch to user page table
    csrw    satp, a0
    sfence.vma

    # Set sscratch to kernel stack pointer (for trap entry)
    csrw    sscratch, a3

    # Set sepc to user entry point
    csrw    sepc, a1

    # Set sstatus: clear SPP (bit 8) to return to U-mode, set SPIE (bit 5)
    csrr    t0, sstatus
    li      t1, -257
    and     t0, t0, t1       # Clear SPP
    ori     t0, t0, (1 << 5) # Set SPIE
    # Also set SUM bit so kernel can access user pages when needed
    li      t1, (1 << 18)
    or      t0, t0, t1       # Set SUM
    csrw    sstatus, t0

    # Set user stack pointer
    mv      sp, a2

    # Zero all registers before entering user mode (security)
    li      x1, 0
    li      x3, 0
    li      x4, 0
    li      x5, 0
    li      x6, 0
    li      x7, 0
    li      x8, 0
    li      x9, 0
    li      x10, 0
    li      x11, 0
    li      x12, 0
    li      x13, 0
    li      x14, 0
    li      x15, 0
    li      x16, 0
    li      x17, 0
    li      x18, 0
    li      x19, 0
    li      x20, 0
    li      x21, 0
    li      x22, 0
    li      x23, 0
    li      x24, 0
    li      x25, 0
    li      x26, 0
    li      x27, 0
    li      x28, 0
    li      x29, 0
    li      x30, 0
    li      x31, 0

    sret
