    .section .text
    .globl _trap_entry
    .globl _user_trap_return
    .align 2
_trap_entry:
    # Check if we came from U-mode by reading sstatus.SPP
    # sscratch holds kernel sp when in U-mode, 0 when in S-mode
    csrrw   sp, sscratch, sp
    # If sp (now old sscratch) is zero, we came from S-mode
    bnez    sp, _from_user
    # Came from S-mode: restore sp from sscratch (which now holds our sp)
    csrrw   sp, sscratch, sp

_from_kernel:
    # Allocate TrapFrame on kernel stack: 32 regs + sstatus + sepc = 34 * 8 = 272 bytes
    addi    sp, sp, -272

    # Save x1-x31 (x0 is always zero, skip saving it)
    sd      x1,   8(sp)
    sd      x3,  24(sp)
    sd      x4,  32(sp)
    sd      x5,  40(sp)
    sd      x6,  48(sp)
    sd      x7,  56(sp)
    sd      x8,  64(sp)
    sd      x9,  72(sp)
    sd      x10, 80(sp)
    sd      x11, 88(sp)
    sd      x12, 96(sp)
    sd      x13,104(sp)
    sd      x14,112(sp)
    sd      x15,120(sp)
    sd      x16,128(sp)
    sd      x17,136(sp)
    sd      x18,144(sp)
    sd      x19,152(sp)
    sd      x20,160(sp)
    sd      x21,168(sp)
    sd      x22,176(sp)
    sd      x23,184(sp)
    sd      x24,192(sp)
    sd      x25,200(sp)
    sd      x26,208(sp)
    sd      x27,216(sp)
    sd      x28,224(sp)
    sd      x29,232(sp)
    sd      x30,240(sp)
    sd      x31,248(sp)

    # Save the original sp (before adjustment) into regs[2]
    addi    t0, sp, 272
    sd      t0,  16(sp)

    # Store zero into regs[0]
    sd      zero, 0(sp)

    # Save sstatus and sepc
    csrr    t0, sstatus
    sd      t0, 256(sp)
    csrr    t0, sepc
    sd      t0, 264(sp)

    # Call Rust trap handler with pointer to TrapFrame
    mv      a0, sp
    call    trap_handler

    # Restore sstatus and sepc (may have been modified by handler)
    ld      t0, 256(sp)
    csrw    sstatus, t0
    ld      t0, 264(sp)
    csrw    sepc, t0

    # Restore x1, x3-x31 (skip x0 and x2/sp)
    ld      x1,   8(sp)
    ld      x3,  24(sp)
    ld      x4,  32(sp)
    ld      x5,  40(sp)
    ld      x6,  48(sp)
    ld      x7,  56(sp)
    ld      x8,  64(sp)
    ld      x9,  72(sp)
    ld      x10, 80(sp)
    ld      x11, 88(sp)
    ld      x12, 96(sp)
    ld      x13,104(sp)
    ld      x14,112(sp)
    ld      x15,120(sp)
    ld      x16,128(sp)
    ld      x17,136(sp)
    ld      x18,144(sp)
    ld      x19,152(sp)
    ld      x20,160(sp)
    ld      x21,168(sp)
    ld      x22,176(sp)
    ld      x23,184(sp)
    ld      x24,192(sp)
    ld      x25,200(sp)
    ld      x26,208(sp)
    ld      x27,216(sp)
    ld      x28,224(sp)
    ld      x29,232(sp)
    ld      x30,240(sp)
    ld      x31,248(sp)

    # Restore sp
    addi    sp, sp, 272
    sret

_from_user:
    # sp = kernel stack pointer (from sscratch)
    # sscratch = user sp (we swapped)
    # Allocate TrapFrame on kernel stack
    addi    sp, sp, -272

    # Save x1-x31
    sd      x1,   8(sp)
    sd      x3,  24(sp)
    sd      x4,  32(sp)
    sd      x5,  40(sp)
    sd      x6,  48(sp)
    sd      x7,  56(sp)
    sd      x8,  64(sp)
    sd      x9,  72(sp)
    sd      x10, 80(sp)
    sd      x11, 88(sp)
    sd      x12, 96(sp)
    sd      x13,104(sp)
    sd      x14,112(sp)
    sd      x15,120(sp)
    sd      x16,128(sp)
    sd      x17,136(sp)
    sd      x18,144(sp)
    sd      x19,152(sp)
    sd      x20,160(sp)
    sd      x21,168(sp)
    sd      x22,176(sp)
    sd      x23,184(sp)
    sd      x24,192(sp)
    sd      x25,200(sp)
    sd      x26,208(sp)
    sd      x27,216(sp)
    sd      x28,224(sp)
    sd      x29,232(sp)
    sd      x30,240(sp)
    sd      x31,248(sp)

    # Save user sp (in sscratch) into regs[2]
    csrr    t0, sscratch
    sd      t0,  16(sp)

    # Store zero into regs[0]
    sd      zero, 0(sp)

    # Save sstatus and sepc
    csrr    t0, sstatus
    sd      t0, 256(sp)
    csrr    t0, sepc
    sd      t0, 264(sp)

    # Call Rust trap handler with pointer to TrapFrame
    mv      a0, sp
    call    trap_handler

    # Fall through to _user_trap_return

_user_trap_return:
    # a0 = pointer to TrapFrame (either from above or from sret-to-user path)
    # If we get here from trap_handler, sp still points to the frame
    # Restore sstatus and sepc
    ld      t0, 256(sp)
    csrw    sstatus, t0
    ld      t0, 264(sp)
    csrw    sepc, t0

    # Restore user sp into sscratch
    ld      t0, 16(sp)
    csrw    sscratch, t0

    # Restore x1, x3-x31
    ld      x1,   8(sp)
    ld      x3,  24(sp)
    ld      x4,  32(sp)
    ld      x5,  40(sp)
    ld      x6,  48(sp)
    ld      x7,  56(sp)
    ld      x8,  64(sp)
    ld      x9,  72(sp)
    ld      x10, 80(sp)
    ld      x11, 88(sp)
    ld      x12, 96(sp)
    ld      x13,104(sp)
    ld      x14,112(sp)
    ld      x15,120(sp)
    ld      x16,128(sp)
    ld      x17,136(sp)
    ld      x18,144(sp)
    ld      x19,152(sp)
    ld      x20,160(sp)
    ld      x21,168(sp)
    ld      x22,176(sp)
    ld      x23,184(sp)
    ld      x24,192(sp)
    ld      x25,200(sp)
    ld      x26,208(sp)
    ld      x27,216(sp)
    ld      x28,224(sp)
    ld      x29,232(sp)
    ld      x30,240(sp)
    ld      x31,248(sp)

    # Restore sp from sscratch (user sp), put kernel sp into sscratch
    addi    sp, sp, 272
    csrrw   sp, sscratch, sp
    sret
