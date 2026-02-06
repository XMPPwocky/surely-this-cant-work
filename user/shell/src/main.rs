#![no_std]
#![no_main]
#![allow(dead_code, unreachable_code)]

use core::arch::global_asm;

mod shell;
mod syscall;

global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    jal shell_main
    li a7, 93
    li a0, 0
    ecall
    j .
"#
);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    syscall::sys_exit(1);
    loop {}
}
