OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
    . = 0;
    .text.entry : { *(.text.entry) }
    .text : { *(.text .text.*) }
    .rodata : ALIGN(8) { *(.rodata .rodata.*) }
    .data : ALIGN(8) { *(.data .data.* .sdata .sdata.*) }
    .bss : ALIGN(8) {
        __bss_start = .;
        *(.bss .bss.* .sbss .sbss.* COMMON)
        __bss_end = .;
    }
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .note.*) }
}
