    .section .text.entry
    .globl _start
_start:
    # Load stack pointer
    la      sp, _stack_top

    # Zero BSS section
    la      t0, _bss_start
    la      t1, _bss_end
bss_clear:
    bgeu    t0, t1, bss_done
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       bss_clear
bss_done:

    # Jump to Rust entry point
    call    kmain

    # If kmain returns, loop forever
halt:
    wfi
    j       halt
