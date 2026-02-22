    .section .text.entry
    .globl _start
_start:
    # Save firmware-provided arguments in callee-saved registers.
    # a0 = hart ID, a1 = DTB physical address (RISC-V SBI convention).
    mv      s0, a0
    mv      s1, a1

    # Load stack pointer
    la      sp, _stack_top

    # Zero BSS section (uses t0/t1, preserves s0/s1)
    la      t0, _bss_start
    la      t1, _bss_end
bss_clear:
    bgeu    t0, t1, bss_done
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       bss_clear
bss_done:

    # Pass hart_id and dtb_ptr to Rust entry point
    mv      a0, s0
    mv      a1, s1
    call    kmain

    # If kmain returns, loop forever
halt:
    wfi
    j       halt
