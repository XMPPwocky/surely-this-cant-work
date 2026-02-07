#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]

extern crate alloc;

use core::arch::global_asm;

mod arch;
mod console;
mod drivers;
mod ipc;
mod mm;
mod panic;
mod services;
mod sync;
mod task;
mod trace;

global_asm!(include_str!("arch/boot.S"));
global_asm!(include_str!("arch/trap.S"));
global_asm!(include_str!("arch/switch.S"));
global_asm!(include_str!("arch/user_programs.S"));

fn user_shell_code() -> &'static [u8] {
    extern "C" {
        static _user_shell_start: u8;
        static _user_shell_end: u8;
    }
    unsafe {
        let start = &_user_shell_start as *const u8;
        let end = &_user_shell_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

fn user_fs_code() -> &'static [u8] {
    extern "C" {
        static _user_fs_start: u8;
        static _user_fs_end: u8;
    }
    unsafe {
        let start = &_user_fs_start as *const u8;
        let end = &_user_fs_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    // ---- Phase 1: Boot and hardware init ----

    // Drain any chars the UART received during firmware boot BEFORE our init
    // clears the FIFO.  OpenSBI left the UART in a working state, so getchar()
    // is safe even before our own init.  We push directly into the ring buffer
    // (it's a compile-time static, always valid) without calling wake_process.
    {
        let uart = drivers::uart::UART.lock();
        while let Some(ch) = uart.getchar() {
            drivers::tty::SERIAL_INPUT.lock().push(ch);
        }
    }

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
    let gpu_present = drivers::virtio::gpu::init();
    if gpu_present {
        if let Some((fb, w, h)) = drivers::virtio::gpu::framebuffer() {
            console::init_fb(fb, w, h);
            println!("[boot] Framebuffer console active ({}x{})", w, h);
            // Draw animated color logo and offset text below it
            console::draw_boot_logo();
        }
    }

    // ---- Phase 3c: VirtIO keyboard (optional) ----
    if drivers::virtio::input::init() {
        println!("[boot] VirtIO keyboard initialized");
    }

    // ---- Phase 4: Scheduler and IPC ----
    task::init();
    ipc::init();

    // Initialize TTY (ring buffers)
    drivers::tty::init();

    // ---- Phase 5: Create channels and spawn services ----

    // Init server <-> serial console: control channel
    let (init_serial_ep, serial_ctl_ep) = ipc::channel_create_pair();
    services::console::set_serial_control_ep(serial_ctl_ep);

    // Init server <-> FB console: control channel (if GPU)
    let init_fb_ep = if gpu_present {
        let (init_fb_ep, fb_ctl_ep) = ipc::channel_create_pair();
        services::console::set_fb_control_ep(fb_ctl_ep);
        Some(init_fb_ep)
    } else {
        None
    };

    // Sysinfo control channel
    let (init_sysinfo_ep, sysinfo_ctl_ep) = ipc::channel_create_pair();
    services::sysinfo::set_control_ep(sysinfo_ctl_ep);
    services::init::set_sysinfo_control_ep(init_sysinfo_ep);

    // Math service control channel
    let (init_math_ep, math_ctl_ep) = ipc::channel_create_pair();
    services::math::set_control_ep(math_ctl_ep);
    services::init::set_math_control_ep(init_math_ep);

    // Filesystem service: control channel goes to a user-space fs server
    let (init_fs_ep, fs_ctl_ep) = ipc::channel_create_pair();
    services::init::set_fs_control_ep(init_fs_ep);

    // Boot channels for shells
    let (shell_serial_boot_a, shell_serial_boot_b) = ipc::channel_create_pair();
    services::init::register_boot(shell_serial_boot_b, services::init::ConsoleType::Serial, true);

    let shell_fb_boot_a = if gpu_present {
        let (a, b) = ipc::channel_create_pair();
        services::init::register_boot(b, services::init::ConsoleType::Framebuffer, true);
        Some(a)
    } else {
        None
    };

    // Register console service endpoints with init
    services::init::register_console(services::init::ConsoleType::Serial, init_serial_ep);
    if let Some(_fb_ep) = init_fb_ep {
        services::init::register_console(services::init::ConsoleType::Framebuffer, _fb_ep);
    }

    // Spawn services
    task::spawn_named(services::init::init_server, "init");
    task::spawn_named(services::console::serial_console_server, "serial-con");
    if gpu_present {
        task::spawn_named(services::console::fb_console_server, "fb-con");
    }
    task::spawn_named(services::sysinfo::sysinfo_service, "sysinfo");
    task::spawn_named(services::math::math_service, "math");

    // Spawn fs server as a user process with boot channel + control channel
    let (fs_boot_a, fs_boot_b) = ipc::channel_create_pair();
    services::init::register_boot(fs_boot_b, services::init::ConsoleType::Serial, false);
    task::spawn_user_elf_with_handles(user_fs_code(), "fs", fs_boot_a, fs_ctl_ep);

    // hello-std is now loaded from the filesystem by init_server

    // Spawn shells with boot channels
    task::spawn_user_elf_with_boot_channel(user_shell_code(), "shell-serial", shell_serial_boot_a);
    if let Some(boot_a) = shell_fb_boot_a {
        task::spawn_user_elf_with_boot_channel(user_shell_code(), "shell-fb", boot_a);
    }

    // ---- Phase 6: Enable preemptive scheduling ----

    // Drain any chars that arrived at the UART during boot (before IRQs were enabled).
    // They're sitting in the FIFO — move them to the ring buffer so the console server
    // will see them once it starts running.
    {
        let uart = drivers::uart::UART.lock();
        while let Some(ch) = uart.getchar() {
            drivers::tty::SERIAL_INPUT.lock().push(ch);
        }
    }

    arch::trap::enable_timer();
    println!("[boot] System ready.\n");

    // Idle loop: run forever, shell "shutdown" command calls sys_exit
    loop {
        task::schedule();
        console::logo_tick();
        unsafe { core::arch::asm!("wfi"); }
    }
}
