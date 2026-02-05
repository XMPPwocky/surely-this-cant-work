#[inline(always)]
fn sbi_call(eid: usize, fid: usize, arg0: usize, arg1: usize, arg2: usize) -> (usize, usize) {
    let error: usize;
    let value: usize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") arg0 => error,
            inlateout("a1") arg1 => value,
            in("a2") arg2,
            in("a6") fid,
            in("a7") eid,
        );
    }
    (error, value)
}

/// Legacy console putchar (EID=0x01)
pub fn sbi_console_putchar(ch: u8) {
    sbi_call(0x01, 0, ch as usize, 0, 0);
}

/// Timer extension: set timer (EID=0x54494D45, FID=0)
pub fn sbi_set_timer(stime: u64) {
    sbi_call(0x54494D45, 0, stime as usize, 0, 0);
}

/// Legacy shutdown (EID=0x08)
pub fn sbi_shutdown() -> ! {
    sbi_call(0x08, 0, 0, 0, 0);
    unreachable!()
}
