use crate::arch::csr;
use crate::arch::sbi;
use core::sync::atomic::{AtomicUsize, Ordering};

const TIMER_INTERVAL: u64 = 1_000_000; // 100ms at 10MHz

static TICK_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn tick_count() -> usize {
    TICK_COUNT.load(Ordering::Relaxed)
}

#[repr(C)]
pub struct TrapFrame {
    pub regs: [usize; 32], // x0-x31 (x0 slot unused but simplifies indexing)
    pub sstatus: usize,    // offset 256
    pub sepc: usize,       // offset 264
}

#[no_mangle]
pub extern "C" fn trap_handler(tf: &mut TrapFrame) {
    let scause = csr::read_scause();
    let stval = csr::read_stval();
    let is_interrupt = (scause >> 63) & 1 == 1;
    let code = scause & !(1usize << 63);

    if is_interrupt {
        match code {
            5 => {
                // Supervisor timer interrupt
                timer_tick();
            }
            9 => {
                // Supervisor external interrupt
                external_interrupt();
            }
            _ => {
                crate::println!("Unknown interrupt: code={}", code);
            }
        }
    } else {
        match code {
            8 => {
                // Environment call from U-mode
                crate::println!("Ecall from U-mode at sepc={:#x}", tf.sepc);
                tf.sepc += 4; // skip ecall instruction
            }
            2 => {
                // Illegal instruction
                crate::println!(
                    "Illegal instruction at sepc={:#x}, stval={:#x}",
                    tf.sepc, stval
                );
                panic!("Illegal instruction exception");
            }
            12 | 13 | 15 => {
                // Page faults: instruction(12), load(13), store(15)
                let fault_type = match code {
                    12 => "instruction",
                    13 => "load",
                    15 => "store/AMO",
                    _ => "unknown",
                };
                crate::println!(
                    "Page fault ({}): sepc={:#x}, stval={:#x}",
                    fault_type, tf.sepc, stval
                );
                panic!("Unhandled page fault");
            }
            _ => {
                crate::println!(
                    "Unhandled exception: code={}, sepc={:#x}, stval={:#x}",
                    code, tf.sepc, stval
                );
                panic!("Unhandled exception");
            }
        }
    }
}

fn timer_tick() {
    let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count <= 3 {
        crate::println!("[timer] tick {}", count);
    }
    // Set next timer
    let time: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) time);
    }
    sbi::sbi_set_timer(time + TIMER_INTERVAL);

    // Preemptive scheduling: switch to next ready task
    crate::task::schedule();
}

fn external_interrupt() {
    use crate::drivers::plic;
    let irq = plic::plic_claim();
    if irq != 0 {
        match irq {
            10 => {
                // UART interrupt
                let uart = crate::drivers::uart::UART.lock();
                while let Some(ch) = uart.getchar() {
                    crate::print!("{}", ch as char);
                }
            }
            _ => {
                crate::println!("Unknown external interrupt: irq={}", irq);
            }
        }
        plic::plic_complete(irq);
    }
}

pub fn init() {
    extern "C" {
        fn _trap_entry();
    }
    csr::write_stvec(_trap_entry as *const () as usize);
    crate::println!("Trap handler installed at {:#x}", _trap_entry as *const () as usize);
}

pub fn enable_timer() {
    crate::set_csr!("sie", 1 << 5); // STIE
    crate::set_csr!("sie", 1 << 9); // SEIE
    crate::set_csr!("sie", 1 << 1); // SSIE

    let time: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) time);
    }
    sbi::sbi_set_timer(time + TIMER_INTERVAL);

    csr::enable_interrupts();
    crate::println!("Interrupts enabled (timer + external + software)");
}
