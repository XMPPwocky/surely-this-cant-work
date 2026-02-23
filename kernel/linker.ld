OUTPUT_ARCH(riscv)
ENTRY(_start)

BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;

    _text_start = .;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }
    _text_end = .;

    . = ALIGN(4K);
    _rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }
    _rodata_end = .;

    . = ALIGN(4K);
    _data_start = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    .bss : {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        _bss_end = .;
    }

    . = ALIGN(4K);
    _end = .;

    . += 64K;
    _stack_top = .;

    /DISCARD/ : {
        *(.eh_frame)
    }
}
