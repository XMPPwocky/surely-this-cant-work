use crate::arch::csr;
use crate::arch::sbi;
use core::sync::atomic::{AtomicUsize, Ordering};

const TIMER_INTERVAL: u64 = 1_000_000; // 100ms at 10MHz

static TICK_COUNT: AtomicUsize = AtomicUsize::new(0);

// Syscall numbers
pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;
pub const SYS_CHAN_RECV_BLOCKING: usize = 204;

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
                let sstatus_val = tf.sstatus;
                let spp = (sstatus_val >> 8) & 1;
                crate::println!(
                    "Page fault ({}): sepc={:#x}, stval={:#x}, SPP={} ({})",
                    fault_type, tf.sepc, stval, spp,
                    if spp == 1 { "S-mode" } else { "U-mode" }
                );
                crate::println!("  sstatus={:#x} ra={:#x} sp={:#x}",
                    sstatus_val, tf.regs[1], tf.regs[2]);
                crate::println!("  s0={:#x} s1={:#x} s2={:#x}",
                    tf.regs[8], tf.regs[9], tf.regs[10]);
                crate::println!("  current_pid={}", crate::task::current_pid());
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

    match syscall_num {
        SYS_EXIT => {
            sys_exit();
            // doesn't return normally
        }
        SYS_YIELD => {
            crate::task::schedule();
            tf.regs[10] = 0;
        }
        SYS_GETPID => {
            tf.regs[10] = crate::task::current_pid();
        }
        SYS_CHAN_CREATE => {
            sys_chan_create(tf);
        }
        SYS_CHAN_SEND => {
            tf.regs[10] = sys_chan_send(a0, a1);
        }
        SYS_CHAN_RECV => {
            tf.regs[10] = sys_chan_recv(a0, a1);
        }
        SYS_CHAN_CLOSE => {
            tf.regs[10] = sys_chan_close(a0);
        }
        SYS_CHAN_RECV_BLOCKING => {
            sys_chan_recv_blocking(tf);
        }
        _ => {
            crate::println!("Unknown syscall: {}", syscall_num);
            tf.regs[10] = usize::MAX;
        }
    }
}

/// SYS_CHAN_CREATE: create a bidirectional channel pair.
/// Returns handle_a in a0, handle_b in a1.
fn sys_chan_create(tf: &mut TrapFrame) {
    let (ep_a, ep_b) = crate::ipc::channel_create_pair();
    let handle_a = crate::task::current_process_alloc_handle(ep_a);
    let handle_b = crate::task::current_process_alloc_handle(ep_b);
    tf.regs[10] = handle_a;
    tf.regs[11] = handle_b;
}

/// SYS_CHAN_SEND: translate handle -> endpoint, copy message from user, send.
/// If message has a cap, translate cap handle -> global endpoint too.
fn sys_chan_send(handle: usize, msg_ptr: usize) -> usize {
    if !validate_user_ptr(msg_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        return usize::MAX;
    }

    // Translate handle to global endpoint
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(ep) => ep,
        None => return usize::MAX,
    };

    // Read message from user space
    crate::set_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
    let user_msg = unsafe { &*(msg_ptr as *const crate::ipc::Message) };
    let mut msg = user_msg.clone();
    crate::clear_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);

    // Set sender PID
    msg.sender_pid = crate::task::current_pid();

    // Translate cap if present: local handle -> global endpoint
    if msg.cap != crate::ipc::NO_CAP {
        match crate::task::current_process_handle(msg.cap) {
            Some(global_ep) => msg.cap = global_ep,
            None => return usize::MAX, // invalid cap handle
        }
    }

    // Send
    let wake_pid = match crate::ipc::channel_send_ref(endpoint, &msg) {
        Ok(w) => w,
        Err(()) => return usize::MAX,
    };
    if wake_pid != 0 {
        crate::task::wake_process(wake_pid);
    }
    0
}

/// SYS_CHAN_RECV (non-blocking): translate handle, try recv, translate cap in result.
fn sys_chan_recv(handle: usize, msg_buf_ptr: usize) -> usize {
    if !validate_user_ptr(msg_buf_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        return usize::MAX;
    }

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(ep) => ep,
        None => return usize::MAX,
    };

    match crate::ipc::channel_recv(endpoint) {
        Some(mut msg) => {
            // Translate cap: global endpoint -> new local handle in receiver
            if msg.cap != crate::ipc::NO_CAP {
                let local_handle = crate::task::current_process_alloc_handle(msg.cap);
                msg.cap = local_handle;
            }
            crate::set_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
            unsafe {
                core::ptr::write(msg_buf_ptr as *mut crate::ipc::Message, msg);
            }
            crate::clear_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
            0
        }
        None => 1, // Nothing available
    }
}

/// SYS_CHAN_RECV_BLOCKING: like recv but blocks if empty.
fn sys_chan_recv_blocking(tf: &mut TrapFrame) {
    let handle = tf.regs[10];
    let msg_buf_ptr = tf.regs[11];

    if !validate_user_ptr(msg_buf_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        tf.regs[10] = usize::MAX;
        return;
    }

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(ep) => ep,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    loop {
        match crate::ipc::channel_recv(endpoint) {
            Some(mut msg) => {
                // Translate cap
                if msg.cap != crate::ipc::NO_CAP {
                    let local_handle = crate::task::current_process_alloc_handle(msg.cap);
                    msg.cap = local_handle;
                }
                crate::set_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
                unsafe {
                    core::ptr::write(msg_buf_ptr as *mut crate::ipc::Message, msg);
                }
                crate::clear_csr!("sstatus", crate::arch::csr::SSTATUS_SUM);
                tf.regs[10] = 0;
                return;
            }
            None => {
                // Block and wait
                let pid = crate::task::current_pid();
                crate::ipc::channel_set_blocked(endpoint, pid);
                crate::task::block_process(pid);
                crate::task::schedule();
                // Woken up — loop back and retry
            }
        }
    }
}

/// SYS_CHAN_CLOSE: translate handle, free it, close endpoint.
fn sys_chan_close(handle: usize) -> usize {
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(ep) => ep,
        None => return usize::MAX,
    };
    crate::task::current_process_free_handle(handle);
    crate::ipc::channel_close(endpoint);
    0
}

fn sys_exit() {
    crate::task::exit_current_from_syscall();
}

/// Validate that a user pointer is within RAM range.
fn validate_user_ptr(ptr: usize, len: usize) -> bool {
    ptr >= 0x8000_0000 && ptr.wrapping_add(len) <= 0x8800_0000
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
                // UART: read all available chars, then push to TTY
                let mut chars = [0u8; 16];
                let mut count = 0;
                {
                    let uart = crate::drivers::uart::UART.lock();
                    while count < 16 {
                        if let Some(ch) = uart.getchar() {
                            chars[count] = ch;
                            count += 1;
                        } else {
                            break;
                        }
                    }
                }
                // UART lock released; push to TTY
                for i in 0..count {
                    crate::drivers::tty::push_serial_char(chars[i]);
                }
            }
            kbd_irq if Some(kbd_irq) == crate::drivers::virtio::input::irq_number() => {
                crate::drivers::virtio::input::handle_irq();
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
