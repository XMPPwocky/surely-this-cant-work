use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::csr;
use crate::arch::sbi;

const TIMER_INTERVAL: u64 = 1_000_000; // 100ms at 10MHz

/// Per-CPU preemption flag. Set by timer_tick(), checked by trap_handler()
/// after handling the trap. If set, trap_handler calls preempt() to switch
/// to a different task (returning the new task's TrapFrame pointer).
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);


#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    pub regs: [usize; 32],
    pub sstatus: usize,
    pub sepc: usize,
}

impl TrapFrame {
    pub const fn zero() -> Self {
        TrapFrame {
            regs: [0; 32],
            sstatus: 0,
            sepc: 0,
        }
    }
}

/// Trap handler called from trap.S.
///
/// Returns a pointer to the TrapFrame to restore on trap exit.  Normally
/// this is `tf` itself (same task).  When preemption is needed (timer tick
/// set `NEED_RESCHED`), this calls `preempt()` which returns a *different*
/// task's TrapFrame pointer — the asm epilogue then restores that task.
#[no_mangle]
pub extern "C" fn trap_handler(tf: &mut TrapFrame) -> *mut TrapFrame {
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
            8 => super::syscall::handle_syscall(tf),
            2 => {
                let sstatus_val = tf.sstatus;
                let spp = (sstatus_val >> 8) & 1;
                crate::println!(
                    "Illegal instruction at sepc={:#x}, stval={:#x}, SPP={} ({})",
                    tf.sepc, stval, spp,
                    if spp == 1 { "S-mode" } else { "U-mode" }
                );
                if spp == 0 {
                    if let Some(pid) = crate::task::try_current_pid() {
                        crate::println!("  Killing user process PID {} due to illegal instruction", pid);
                    }
                    crate::task::exit_current_from_syscall();
                    return tf as *mut TrapFrame;
                }
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
                if let Some(pid) = crate::task::try_current_pid() {
                    crate::println!("  current_pid={}", pid);
                }
                if spp == 0 {
                    // U-mode fault: kill the faulting process, not the kernel
                    crate::println!("  Killing user process due to page fault");
                    crate::task::terminate_current_process();
                    return tf as *mut TrapFrame;
                }
                // S-mode fault: kernel bug, unrecoverable
                let sp = tf.regs[2];
                let is_stack_overflow = code == 15
                    && stval < sp.wrapping_add(2 * crate::mm::address::PAGE_SIZE);
                if is_stack_overflow {
                    crate::println!("  >>> KERNEL STACK OVERFLOW <<<");
                }
                print_backtrace(tf.regs[8]);
                panic!("Unhandled page fault");
            }
            3 => {
                // Breakpoint (ebreak / c.ebreak)
                let sstatus_val = tf.sstatus;
                let spp = (sstatus_val >> 8) & 1;
                if spp == 0 {
                    // U-mode breakpoint
                    if let Some(pid) = crate::task::try_current_pid() {
                        if crate::task::process_debug_attached(pid) {
                            // Debugger attached: suspend and notify
                            if let Some(event_ep) = crate::task::process_debug_event_ep(pid) {
                                send_debug_event(event_ep, &rvos_proto::debug::DebugEvent::BreakpointHit {
                                    addr: tf.sepc as u64,
                                });
                            }
                            crate::task::mark_debug_suspended(pid);
                            crate::task::force_block_process(pid);
                            crate::task::schedule();
                            return tf as *mut TrapFrame;
                        }
                        // No debugger: kill process
                        crate::println!("  Killing user process PID {} due to breakpoint (no debugger)", pid);
                    }
                    crate::task::terminate_current_process();
                    return tf as *mut TrapFrame;
                }
                // S-mode breakpoint: kernel bug
                panic!("S-mode breakpoint at sepc={:#x}", tf.sepc);
            }
            _ => {
                let sstatus_val = tf.sstatus;
                let spp = (sstatus_val >> 8) & 1;
                crate::println!(
                    "Unhandled exception: code={}, sepc={:#x}, stval={:#x}, SPP={} ({})",
                    code, tf.sepc, stval, spp,
                    if spp == 1 { "S-mode" } else { "U-mode" }
                );
                if spp == 0 {
                    if let Some(pid) = crate::task::try_current_pid() {
                        crate::println!("  Killing user process PID {} due to unhandled exception", pid);
                    }
                    crate::task::terminate_current_process();
                    return tf as *mut TrapFrame;
                }
                panic!("Unhandled exception");
            }
        }
    }

    // After handling the trap: check if debug suspend is pending (U-mode only).
    let spp = (tf.sstatus >> 8) & 1;
    if spp == 0 {
        if let Some(pid) = crate::task::try_current_pid() {
            if let Some(event_ep) = crate::task::check_and_clear_debug_suspend(pid) {
                send_debug_event(event_ep, &rvos_proto::debug::DebugEvent::Suspended {});
                crate::task::mark_debug_suspended(pid);
                crate::task::force_block_process(pid);
                crate::task::schedule();
                return tf as *mut TrapFrame;
            }
        }
    }

    // After handling the trap: check if preemption is needed.
    if NEED_RESCHED.swap(false, Ordering::Relaxed) {
        return crate::task::preempt(tf);
    }
    tf as *mut TrapFrame
}

/// Walk the frame pointer chain and print a backtrace.
///
/// Requires `-C force-frame-pointers=yes`. RISC-V frame layout:
///   [fp - 8]  = saved ra (return address)
///   [fp - 16] = saved previous fp (s0)
///
/// `start_fp` should be the s0 register value from a trap frame,
/// or the current s0 for a live backtrace.
pub fn print_backtrace(start_fp: usize) {
    const KERN_LO: usize = 0x8020_0000;
    const KERN_HI: usize = 0x8800_0000;
    const MAX_DEPTH: usize = 32;

    crate::println!("  Backtrace:");
    let mut fp = start_fp;
    let mut depth = 0;
    while (KERN_LO..KERN_HI).contains(&fp) && fp.is_multiple_of(8) && depth < MAX_DEPTH {
        let ra = unsafe { *((fp - 8) as *const usize) };
        let prev_fp = unsafe { *((fp - 16) as *const usize) };
        crate::println!("    #{}: ra={:#x} fp={:#x}", depth, ra, fp);
        if prev_fp == 0 || prev_fp == fp {
            break;
        }
        fp = prev_fp;
        depth += 1;
    }
    if depth == 0 {
        crate::println!("    (no frames — frame pointers may not be enabled)");
    }
}

/// Send a debug event on the given endpoint (non-blocking, best-effort).
fn send_debug_event(event_ep: usize, event: &rvos_proto::debug::DebugEvent) {
    let mut msg = crate::ipc::Message::new();
    msg.len = rvos_wire::to_bytes(event, &mut msg.data).unwrap_or(0);
    if let Ok(wake) = crate::ipc::channel_send(event_ep, msg) {
        if wake != 0 {
            crate::task::wake_process(wake);
        }
    }
}

fn timer_tick() {
    // Check keyboard DMA buffer canary every tick
    crate::drivers::virtio::input::check_canary();
    let time: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) time);
    }
    sbi::sbi_set_timer(time + TIMER_INTERVAL);

    // Check for expired timer deadlines and wake blocked processes
    crate::task::check_deadlines(time);

    NEED_RESCHED.store(true, Ordering::Relaxed);
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
                for ch in chars.iter().take(count) {
                    crate::drivers::tty::push_serial_char(*ch);
                }
            }
            kbd_irq if Some(kbd_irq) == crate::drivers::virtio::input::irq_number() => {
                crate::drivers::virtio::input::handle_irq();
            }
            tablet_irq if Some(tablet_irq) == crate::drivers::virtio::tablet::irq_number() => {
                crate::drivers::virtio::tablet::handle_irq();
            }
            gpu_irq if Some(gpu_irq) == crate::drivers::virtio::gpu::irq_number() => {
                crate::drivers::virtio::gpu::handle_irq();
            }
            net_irq if Some(net_irq) == crate::drivers::virtio::net::irq_number() => {
                crate::drivers::virtio::net::handle_irq();
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
