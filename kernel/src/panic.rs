use crate::println;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("\n!!! KERNEL PANIC !!!");
    println!("{}", info);

    let scause = crate::arch::csr::read_scause();
    let stval = crate::arch::csr::read_stval();
    let sepc = crate::arch::csr::read_sepc();
    let sstatus = crate::arch::csr::read_sstatus();
    println!("scause:  {:#x}", scause);
    println!("stval:   {:#x}", stval);
    println!("sepc:    {:#x}", sepc);
    println!("sstatus: {:#x}", sstatus);

    // Walk frame pointer chain from the current stack frame
    let fp: usize;
    unsafe { core::arch::asm!("mv {}, s0", out(reg) fp) };
    crate::arch::trap::print_backtrace(fp);

    loop {
        unsafe { core::arch::asm!("wfi"); }
    }
}
