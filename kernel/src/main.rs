#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};

mod arch;
mod console;
mod drivers;
mod ipc;
mod mm;
mod panic;
mod sync;
mod task;

global_asm!(include_str!("arch/boot.S"));
global_asm!(include_str!("arch/trap.S"));
global_asm!(include_str!("arch/switch.S"));
global_asm!(include_str!("arch/user_programs.S"));

// Shared state for the IPC ping-pong demo
static PING_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static PONG_CHANNEL: AtomicUsize = AtomicUsize::new(0);
static DEMO_DONE: AtomicBool = AtomicBool::new(false);

/// Get user program bytes from embedded assembly symbols
fn user_hello_code() -> &'static [u8] {
    extern "C" {
        static _user_hello_start: u8;
        static _user_hello_end: u8;
    }
    unsafe {
        let start = &_user_hello_start as *const u8;
        let end = &_user_hello_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

fn user_getpid_code() -> &'static [u8] {
    extern "C" {
        static _user_getpid_start: u8;
        static _user_getpid_end: u8;
    }
    unsafe {
        let start = &_user_getpid_start as *const u8;
        let end = &_user_getpid_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    // ---- Phase 1: Boot and hardware init ----
    drivers::uart::init();

    println!();
    println!("  ________  ____  _____");
    println!("  |_____  \\/ /\\ \\/  __ \\  ___");
    println!("   _ __|  / /  \\    / / / /__\\");
    println!("  | | |\\ \\ \\  / \\  / / /\\___  \\");
    println!("  |_|  \\_\\_\\/ /\\_\\/__/  \\____/");
    println!();
    println!("  rvOS v0.1.0 -- RISC-V 64-bit Microkernel");
    println!("  QEMU virt machine, 128 MiB RAM");
    println!();

    // ---- Phase 2: Memory management ----
    mm::init();

    let root = arch::paging::init_kernel_page_table();
    arch::paging::enable_paging(root);
    println!("[boot] Sv39 paging enabled (root PPN={:#x})", root.0);
    println!("[boot] {} page frames allocated for page tables", mm::frame::frames_allocated());
    println!();

    // Save kernel satp for restoring when returning from user mode
    task::save_kernel_satp();

    // ---- Phase 3: Traps and interrupts ----
    arch::trap::init();
    drivers::plic::init();

    // ---- Phase 3b: VirtIO GPU (optional, nographic mode has no device) ----
    if drivers::virtio::gpu::init() {
        if let Some((fb, w, h)) = drivers::virtio::gpu::framebuffer() {
            console::init_fb(fb, w, h);
            println!("[boot] Framebuffer console active ({}x{})", w, h);
            // Draw animated color logo and offset text below it
            console::draw_boot_logo();
        }
    }

    // ---- Phase 4: Scheduler and IPC ----
    task::init();
    ipc::init();

    // ---- Phase 5: Spawn demo tasks ----
    println!("[demo] Spawning kernel demo tasks...");
    let ch_ping = ipc::channel_create();
    let ch_pong = ipc::channel_create();
    PING_CHANNEL.store(ch_ping, Ordering::SeqCst);
    PONG_CHANNEL.store(ch_pong, Ordering::SeqCst);

    task::spawn_named(task_counter_a, "counter-A");
    task::spawn_named(task_counter_b, "counter-B");
    task::spawn_named(task_ping, "ping");
    task::spawn_named(task_pong, "pong");

    // ---- Phase 5b: Spawn user-mode tasks ----
    println!("[demo] Spawning user-mode tasks...");
    task::spawn_user(user_hello_code(), "user-hello");
    task::spawn_user(user_getpid_code(), "user-getpid");

    // Spawn monitor last (it waits for everyone)
    task::spawn_named(task_monitor, "monitor");
    println!();

    // ---- Phase 6: Enable preemptive scheduling ----
    arch::trap::enable_timer();
    println!("[boot] System ready. Entering idle loop.");
    println!();

    // Idle loop (PID 0): yield to spawned tasks cooperatively.
    // Use a function call to check DEMO_DONE to prevent the compiler
    // from caching the address in a callee-saved register across schedule().
    loop {
        task::schedule();
        if check_demo_done() {
            break;
        }
        console::fb_flush();
        unsafe { core::arch::asm!("wfi"); }
    }

    // ---- Phase 7: Clean shutdown ----
    println!();
    println!("========================================");
    println!("  All demo tasks completed.");
    println!("  Total timer ticks: {}", arch::trap::tick_count());
    println!("  Frames allocated:  {}", mm::frame::frames_allocated());
    println!("========================================");
    println!();
    println!("[shutdown] rvOS shutting down. Goodbye!");

    // Final flush so all output is visible on the GPU framebuffer
    console::fb_flush();

    arch::sbi::sbi_shutdown();
}

// ---------------------------------------------------------------------------
// Demo task: Counter A -- prints 5 iterations with delay
// ---------------------------------------------------------------------------
fn task_counter_a() {
    let pid = task::current_pid();
    for i in 0..5 {
        println!("[counter-A] pid={} iteration {}", pid, i);
        busy_delay(80_000);
    }
    println!("[counter-A] done");
    task::exit_current();
}

// ---------------------------------------------------------------------------
// Demo task: Counter B -- prints 5 iterations with delay
// ---------------------------------------------------------------------------
fn task_counter_b() {
    let pid = task::current_pid();
    for i in 0..5 {
        println!("[counter-B] pid={} iteration {}", pid, i);
        busy_delay(80_000);
    }
    println!("[counter-B] done");
    task::exit_current();
}

// ---------------------------------------------------------------------------
// Demo task: Ping -- sends messages and waits for replies
// ---------------------------------------------------------------------------
fn task_ping() {
    let pid = task::current_pid();
    let ch_ping = PING_CHANNEL.load(Ordering::SeqCst);
    let ch_pong = PONG_CHANNEL.load(Ordering::SeqCst);

    for i in 0..5 {
        let msg = ipc::Message::from_str("ping", pid);
        ipc::channel_send(ch_ping, msg);
        println!("[ping] sent ping #{}", i);

        // Wait for pong reply (busy-poll with yield)
        loop {
            if let Some(reply) = ipc::channel_recv(ch_pong) {
                println!("[ping] received: \"{}\" from PID {}", reply.as_str(), reply.sender_pid);
                break;
            }
            task::schedule();
        }
        busy_delay(50_000);
    }
    println!("[ping] done");
    task::exit_current();
}

// ---------------------------------------------------------------------------
// Demo task: Pong -- receives messages and sends replies
// ---------------------------------------------------------------------------
fn task_pong() {
    let pid = task::current_pid();
    let ch_ping = PING_CHANNEL.load(Ordering::SeqCst);
    let ch_pong = PONG_CHANNEL.load(Ordering::SeqCst);

    for _i in 0..5 {
        // Wait for ping message (busy-poll with yield)
        loop {
            if let Some(msg) = ipc::channel_recv(ch_ping) {
                println!("[pong] received: \"{}\" from PID {}", msg.as_str(), msg.sender_pid);
                // Send pong reply
                let reply = ipc::Message::from_str("pong", pid);
                ipc::channel_send(ch_pong, reply);
                println!("[pong] sent pong reply");
                break;
            }
            task::schedule();
        }
    }
    println!("[pong] done");
    task::exit_current();
}

// ---------------------------------------------------------------------------
// Demo task: Monitor -- waits for other tasks to finish, prints process list
// ---------------------------------------------------------------------------
fn task_monitor() {
    // Wait a bit for other tasks to start
    busy_delay(200_000);

    println!();
    println!("--- Process Listing (mid-demo) ---");
    print!("{}", task::process_list());
    println!("----------------------------------");
    println!();

    // Wait for counter tasks (PIDs 1-4) and user tasks (PIDs 5-6) to finish
    loop {
        let still_running = task::is_alive(1)
            || task::is_alive(2)
            || task::is_alive(3)
            || task::is_alive(4)
            || task::is_alive(5)
            || task::is_alive(6);
        if !still_running {
            break;
        }
        task::schedule();
    }

    println!();
    println!("--- Final Process Listing ---");
    print!("{}", task::process_list());
    println!("-----------------------------");

    // Clean up IPC channels
    let ch_ping = PING_CHANNEL.load(Ordering::SeqCst);
    let ch_pong = PONG_CHANNEL.load(Ordering::SeqCst);
    ipc::channel_close(ch_ping);
    ipc::channel_close(ch_pong);

    // Signal the idle loop to shut down
    DEMO_DONE.store(true, Ordering::SeqCst);
    println!("[monitor] signaled shutdown");

    task::exit_current();
}

/// Check if the demo is done (separate function to prevent the compiler
/// from caching the DEMO_DONE address in a callee-saved register across schedule()).
#[inline(never)]
fn check_demo_done() -> bool {
    DEMO_DONE.load(Ordering::SeqCst)
}

/// Busy-wait delay with cooperative yielding
fn busy_delay(iters: usize) {
    let mut x: usize = 0;
    for i in 0..iters {
        unsafe {
            core::ptr::write_volatile(&mut x as *mut usize, x.wrapping_add(1));
        }
        // Yield periodically to allow other tasks to run
        if i % 20_000 == 0 && i > 0 {
            task::schedule();
        }
    }
}
