use crate::arch::csr;
use crate::arch::sbi;
use core::sync::atomic::{AtomicUsize, Ordering};

const TIMER_INTERVAL: u64 = 1_000_000; // 100ms at 10MHz

static TICK_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn tick_count() -> usize {
    TICK_COUNT.load(Ordering::Relaxed)
}

// Syscall numbers
pub const SYS_WRITE: usize = 64;
pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;

#[repr(C)]
pub struct TrapFrame {
    pub regs: [usize; 32],
    pub sstatus: usize,
    pub sepc: usize,
}

#[no_mangle]
pub extern "C" fn trap_handler(tf: &mut TrapFrame) {
    let scause = csr::read_scause();
    let stval = csr::read_stval();
    let is_interrupt = (scause >> 63) & 1 == 1;
    let code = scause & !(1usize << 63);

    if is_interrupt {
        match code {
            5 => timer_tick(),
            9 => external_interrupt(),
            _ => {
                crate::println!("Unknown interrupt: code={}", code);
            }
        }
    } else {
        match code {
            8 => handle_syscall(tf),
            2 => {
                crate::println!(
                    "Illegal instruction at sepc={:#x}, stval={:#x}",
                    tf.sepc, stval
                );
                panic!("Illegal instruction exception");
            }
            12 | 13 | 15 => {
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

fn handle_syscall(tf: &mut TrapFrame) {
    tf.sepc += 4;

    let syscall_num = tf.regs[17]; // a7
    let a0 = tf.regs[10];
    let a1 = tf.regs[11];
    let a2 = tf.regs[12];

    let result = match syscall_num {
        SYS_WRITE => sys_write(a0, a1, a2),
        SYS_EXIT => sys_exit(a0),
        SYS_YIELD => {
            crate::task::schedule();
            0
        }
        SYS_GETPID => crate::task::current_pid(),
        SYS_CHAN_CREATE => crate::ipc::channel_create(),
        SYS_CHAN_SEND => sys_chan_send(a0, a1),
        SYS_CHAN_RECV => sys_chan_recv(a0, a1),
        SYS_CHAN_CLOSE => {
            crate::ipc::channel_close(a0);
            0
        }
        _ => {
            crate::println!("Unknown syscall: {}", syscall_num);
            usize::MAX
        }
    };

    tf.regs[10] = result;
}

fn sys_write(fd: usize, buf_ptr: usize, len: usize) -> usize {
    if fd != 1 || len == 0 {
        return usize::MAX;
    }
    if buf_ptr < 0x8000_0000 || buf_ptr + len > 0x8800_0000 {
        return usize::MAX;
    }
    // Set SUM bit so we can read user pages from S-mode
    crate::set_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
    let uart = crate::drivers::uart::UART.lock();
    for i in 0..len {
        let byte = unsafe { *((buf_ptr + i) as *const u8) };
        uart.putchar(byte);
    }
    drop(uart);
    crate::clear_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
    len
}

fn sys_exit(_code: usize) -> usize {
    crate::task::exit_current_from_syscall();
    0
}

fn sys_chan_send(chan_id: usize, msg_ptr: usize) -> usize {
    if msg_ptr < 0x8000_0000 || msg_ptr + core::mem::size_of::<crate::ipc::Message>() > 0x8800_0000 {
        return usize::MAX;
    }
    crate::set_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
    let msg = unsafe { &*(msg_ptr as *const crate::ipc::Message) };
    let result = match crate::ipc::channel_send_ref(chan_id, msg) {
        Ok(()) => 0,
        Err(()) => usize::MAX,
    };
    crate::clear_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
    result
}

fn sys_chan_recv(chan_id: usize, msg_buf_ptr: usize) -> usize {
    if msg_buf_ptr < 0x8000_0000 || msg_buf_ptr + core::mem::size_of::<crate::ipc::Message>() > 0x8800_0000 {
        return usize::MAX;
    }
    match crate::ipc::channel_recv(chan_id) {
        Some(msg) => {
            crate::set_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
            unsafe {
                let dst = msg_buf_ptr as *mut crate::ipc::Message;
                core::ptr::write(dst, msg);
            }
            crate::clear_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
            0
        }
        None => 1, // Nothing available
    }
}

fn timer_tick() {
    let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count <= 3 {
        crate::println!("[timer] tick {}", count);
    }
    let time: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) time);
    }
    sbi::sbi_set_timer(time + TIMER_INTERVAL);

    // Preemptive scheduling
    crate::task::schedule();
}

fn external_interrupt() {
    use crate::drivers::plic;
    let irq = plic::plic_claim();
    if irq != 0 {
        match irq {
            10 => {
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
