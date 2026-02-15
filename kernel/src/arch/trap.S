    .section .text
    .globl _trap_entry
    .globl _restore_from_trap
    .align 2

# Per-task trap frame design.
#
# sscratch ALWAYS holds a pointer to the current task's TrapContext:
#
#   Offset 0..255:  TrapFrame.regs[0..31]  (32 × 8 = 256 bytes)
#   Offset 256:     TrapFrame.sstatus       (8 bytes)
#   Offset 264:     TrapFrame.sepc          (8 bytes)
#   Offset 272:     kernel_stack_top        (8 bytes)
#   Offset 280:     user_satp              (8 bytes)
#
# On trap entry, all registers are saved to the current task's TrapContext
# (not on a stack). The handler stack is chosen based on SPP:
#   SPP=1 (S-mode): task's own kernel stack (reloaded from saved sp)
#   SPP=0 (U-mode): per-task kernel stack (from TrapContext.kernel_stack_top)
#
# trap_handler() returns a *mut TrapFrame — always the same task's TrapFrame
# (preemption is handled internally via switch_context, not by returning a
# different TrapFrame). The asm epilogue restores from it and srets.

_trap_entry:
    # Swap t0 with sscratch to get TrapContext pointer in t0.
    csrrw   t0, sscratch, t0       # t0 = &TrapContext, sscratch = old t0

    # Save t1 FIRST (we need it to save original t0 from sscratch)
    sd      t1,  48(t0)            # regs[6] = original t1

    # Read original t0 from sscratch and save it
    csrr    t1, sscratch           # t1 = original t0
    sd      t1,  40(t0)            # regs[5] = original t0

    # Save remaining GPRs
    sd      zero, 0(t0)            # regs[0] = 0
    sd      x1,   8(t0)            # regs[1] / ra
    sd      x2,  16(t0)            # regs[2] / sp
    sd      x3,  24(t0)            # regs[3] / gp
    sd      x4,  32(t0)            # regs[4] / tp
    # x5/t0 at 40(t0) — already saved
    # x6/t1 at 48(t0) — already saved
    sd      x7,  56(t0)
    sd      x8,  64(t0)
    sd      x9,  72(t0)
    sd      x10, 80(t0)
    sd      x11, 88(t0)
    sd      x12, 96(t0)
    sd      x13,104(t0)
    sd      x14,112(t0)
    sd      x15,120(t0)
    sd      x16,128(t0)
    sd      x17,136(t0)
    sd      x18,144(t0)
    sd      x19,152(t0)
    sd      x20,160(t0)
    sd      x21,168(t0)
    sd      x22,176(t0)
    sd      x23,184(t0)
    sd      x24,192(t0)
    sd      x25,200(t0)
    sd      x26,208(t0)
    sd      x27,216(t0)
    sd      x28,224(t0)
    sd      x29,232(t0)
    sd      x30,240(t0)
    sd      x31,248(t0)

    # Save sstatus and sepc
    csrr    t1, sstatus
    sd      t1, 256(t0)            # TrapFrame.sstatus
    csrr    t1, sepc
    sd      t1, 264(t0)            # TrapFrame.sepc

    # Restore sscratch = TrapContext pointer (was clobbered during save)
    csrw    sscratch, t0

    # Choose handler stack based on SPP (bit 8 of saved sstatus).
    #   SPP=1 (S-mode trap): task's own kernel stack (resume from saved sp)
    #   SPP=0 (U-mode trap): per-task kernel stack from TrapContext
    ld      t1, 256(t0)            # reload sstatus
    li      t2, (1 << 8)           # SPP mask
    and     t1, t1, t2
    beqz    t1, _user_handler_stack

    # --- S-mode trap: use task's own kernel stack ---
    # The interrupted task was running in S-mode on its own kernel stack.
    # Reload that sp so the handler's call frames live on the task's stack
    # (survives context switches, unlike the shared KERNEL_TRAP_STACK).
    ld      sp, 16(t0)             # reload saved sp from TrapFrame.regs[2]
    j       _call_trap_handler

_user_handler_stack:
    # --- U-mode trap: switch to kernel page table first ---
1:  auipc   t1, %pcrel_hi(KERNEL_SATP_RAW)
    ld      t1, %pcrel_lo(1b)(t1)
    csrw    satp, t1
    sfence.vma

    # Handler stack = per-task kernel stack (for blocking syscalls)
    ld      sp, 272(t0)            # TrapContext.kernel_stack_top

_call_trap_handler:
    # Call trap_handler(&mut TrapFrame) -> *mut TrapFrame
    # TrapFrame is at offset 0 of TrapContext, so t0 works as both.
    mv      a0, t0
    call    trap_handler

    # a0 = pointer to TrapFrame to restore (may be a different task).
    # Since TrapFrame is at offset 0 of TrapContext, a0 also serves as
    # the TrapContext pointer for accessing kernel_stack_top and user_satp.
    mv      t0, a0

    # Update sscratch to the (possibly new) task's TrapContext
    csrw    sscratch, t0

    # Fall through to _restore_from_trap

    .align 2
_restore_from_trap:
    # Restore a task from its TrapContext and sret.
    #
    # Preconditions (set by caller):
    #   t0 = pointer to TrapContext to restore
    #   sscratch = t0
    #
    # Entry points:
    #   - Fall-through from _call_trap_handler (normal trap return)
    #   - kernel_task_trampoline (first run of a kernel task)
    #   - user_entry_trampoline (first run of a user task)

    # Load sstatus for SPP check and for writing to CSR
    ld      t1, 256(t0)            # TrapFrame.sstatus

    # If returning to U-mode (SPP=0), switch to user page table.
    # Kernel memory is identity-mapped in the user page table (without U
    # bit), so TrapContext and code remain accessible after the switch.
    li      t2, (1 << 8)           # SPP mask
    and     t2, t1, t2
    bnez    t2, _skip_user_satp

    ld      t2, 280(t0)           # TrapContext.user_satp
    beqz    t2, _skip_user_satp
    csrw    satp, t2
    sfence.vma

_skip_user_satp:
    # Write sstatus and sepc to CSRs
    csrw    sstatus, t1            # t1 still holds sstatus
    ld      t1, 264(t0)           # TrapFrame.sepc
    csrw    sepc, t1

    # Restore all GPRs (t0 restored last since it's our base pointer)
    ld      x1,   8(t0)
    ld      x2,  16(t0)
    ld      x3,  24(t0)
    ld      x4,  32(t0)
    # x5/t0 — restored last
    ld      x6,  48(t0)
    ld      x7,  56(t0)
    ld      x8,  64(t0)
    ld      x9,  72(t0)
    ld      x10, 80(t0)
    ld      x11, 88(t0)
    ld      x12, 96(t0)
    ld      x13,104(t0)
    ld      x14,112(t0)
    ld      x15,120(t0)
    ld      x16,128(t0)
    ld      x17,136(t0)
    ld      x18,144(t0)
    ld      x19,152(t0)
    ld      x20,160(t0)
    ld      x21,168(t0)
    ld      x22,176(t0)
    ld      x23,184(t0)
    ld      x24,192(t0)
    ld      x25,200(t0)
    ld      x26,208(t0)
    ld      x27,216(t0)
    ld      x28,224(t0)
    ld      x29,232(t0)
    ld      x30,240(t0)
    ld      x31,248(t0)

    # Restore t0 last (ld computes address before writing destination)
    ld      t0,  40(t0)

    sret
