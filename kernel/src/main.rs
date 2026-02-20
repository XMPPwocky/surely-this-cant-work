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
mod kstat;
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
        if let Some((_fb, w, h)) = drivers::virtio::gpu::framebuffer() {
            println!("[boot] VirtIO GPU active ({}x{})", w, h);
        }
    }

    // ---- Phase 3c: VirtIO input devices (keyboard + tablet) ----
    if drivers::virtio::input::init() {
        println!("[boot] VirtIO keyboard initialized");
    }
    if drivers::virtio::tablet::init_from_probe() {
        println!("[boot] VirtIO tablet initialized");
    }

    // ---- Phase 3d: VirtIO network ----
    let net_present = drivers::virtio::net::init();
    if net_present {
        if let Some(mac) = drivers::virtio::net::mac_address() {
            println!("[boot] VirtIO net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }

    // ---- Phase 3e: VirtIO block devices ----
    let blk_count = drivers::virtio::blk::init();
    if blk_count > 0 {
        println!("[boot] {} block device(s) initialized", blk_count);
    }

    // ---- Phase 4: Scheduler and IPC ----
    task::init();
    ipc::init();

    // Initialize TTY (ring buffers)
    drivers::tty::init();

    // ---- Phase 5: Create channels and spawn services ----

    // Init server <-> serial console: control channel
    let (init_serial_ep, serial_ctl_ep) = ipc::channel_create_pair().expect("boot: serial channel");
    services::console::set_serial_control_ep(serial_ctl_ep.into_raw());

    // Tell init server whether GPU is available (controls fs-loaded program launches)
    services::init::set_gpu_present(gpu_present);

    // Init server <-> FB console: control channel (only in non-compositor mode)
    // When GPU is present, the window server replaces fb-con + shell-fb
    let init_fb_ep = if gpu_present {
        // GPU server kernel task
        let (init_gpu_ep, gpu_ctl_ep) = ipc::channel_create_pair().expect("boot: gpu channel");
        services::gpu_server::set_control_ep(gpu_ctl_ep.into_raw());
        services::init::register_service("gpu", init_gpu_ep.into_raw());

        // Keyboard server kernel task
        let (init_kbd_ep, kbd_ctl_ep) = ipc::channel_create_pair().expect("boot: kbd channel");
        services::kbd_server::set_control_ep(kbd_ctl_ep.into_raw());
        services::init::register_service("kbd", init_kbd_ep.into_raw());

        // Mouse server kernel task
        let (init_mouse_ep, mouse_ctl_ep) = ipc::channel_create_pair().expect("boot: mouse channel");
        services::mouse_server::set_control_ep(mouse_ctl_ep.into_raw());
        services::init::register_service("mouse", init_mouse_ep.into_raw());

        // No fb-con control channel — window server takes over the display
        None
    } else {
        None
    };

    // Sysinfo control channel
    let (init_sysinfo_ep, sysinfo_ctl_ep) = ipc::channel_create_pair().expect("boot: sysinfo channel");
    services::sysinfo::set_control_ep(sysinfo_ctl_ep.into_raw());
    services::init::set_sysinfo_control_ep(init_sysinfo_ep.into_raw());

    // Math service control channel
    let (init_math_ep, math_ctl_ep) = ipc::channel_create_pair().expect("boot: math channel");
    services::math::set_control_ep(math_ctl_ep.into_raw());
    services::init::set_math_control_ep(init_math_ep.into_raw());

    // Process debug service control channel
    let (init_debug_ep, debug_ctl_ep) = ipc::channel_create_pair().expect("boot: debug channel");
    services::proc_debug::set_control_ep(debug_ctl_ep.into_raw());
    services::init::register_service("process-debug", init_debug_ep.into_raw());

    // Net server kernel task (only if VirtIO net device is present)
    if net_present {
        let (init_net_ep, net_ctl_ep) = ipc::channel_create_pair().expect("boot: net channel");
        services::net_server::set_control_ep(net_ctl_ep.into_raw());
        services::init::register_service("net-raw", init_net_ep.into_raw());
    }

    // Block device servers (one per detected block device)
    for i in 0..blk_count {
        let (init_blk_ep, blk_ctl_ep) = ipc::channel_create_pair().expect("boot: blk channel");
        services::blk_server::set_control_ep(i, blk_ctl_ep.into_raw());
        services::blk_server::set_device_index(i, i);
        // Register as "blk0", "blk1", etc.
        let name: &str = match i {
            0 => "blk0",
            1 => "blk1",
            2 => "blk2",
            3 => "blk3",
            _ => "blk?",
        };
        services::init::register_service(name, init_blk_ep.into_raw());
    }

    // Timer service kernel task
    let (init_timer_ep, timer_ctl_ep) = ipc::channel_create_pair().expect("boot: timer channel");
    services::timer::set_control_ep(timer_ctl_ep.into_raw());
    services::init::register_service("timer", init_timer_ep.into_raw());

    // Filesystem service: control channel goes to a user-space fs server
    let (init_fs_ep, fs_ctl_ep) = ipc::channel_create_pair().expect("boot: fs channel");
    services::init::set_fs_control_ep(init_fs_ep.into_raw());

    // Boot channels for shells
    let (shell_serial_boot_a, shell_serial_boot_b) = ipc::channel_create_pair().expect("boot: shell channel");
    services::init::register_boot(shell_serial_boot_b, services::init::ConsoleType::Serial, true);

    // FB shell only in non-GPU mode (when GPU present, window-server replaces it)
    let shell_fb_boot_a: Option<ipc::OwnedEndpoint> = None;

    // Register console service endpoints with init
    services::init::register_console(services::init::ConsoleType::Serial, init_serial_ep.into_raw());
    if let Some(_fb_ep) = init_fb_ep {
        services::init::register_console(services::init::ConsoleType::Framebuffer, _fb_ep);
    }

    // Spawn services
    task::spawn_named(services::init::init_server, "init").expect("boot: init");
    task::spawn_named(services::console::serial_console_server, "serial-con").expect("boot: serial-con");
    if gpu_present {
        // GPU present: spawn gpu-server + kbd-server + mouse-server (window-server loaded from fs)
        task::spawn_named(services::gpu_server::gpu_server, "gpu-server").expect("boot: gpu-server");
        task::spawn_named(services::kbd_server::kbd_server, "kbd-server").expect("boot: kbd-server");
        task::spawn_named(services::mouse_server::mouse_server, "mouse-server").expect("boot: mouse-server");
        // fb-con and shell-fb are replaced by the window server
    }
    task::spawn_named(services::sysinfo::sysinfo_service, "sysinfo").expect("boot: sysinfo");
    task::spawn_named(services::math::math_service, "math").expect("boot: math");
    task::spawn_named(services::proc_debug::proc_debug_service, "proc-debug").expect("boot: proc-debug");
    if net_present {
        task::spawn_named(services::net_server::net_server, "net-server").expect("boot: net-server");
    }
    for i in 0..blk_count {
        let name: &str = match i {
            0 => "blk-server0",
            1 => "blk-server1",
            2 => "blk-server2",
            3 => "blk-server3",
            _ => "blk-server?",
        };
        task::spawn_named(services::blk_server::BLK_SERVER_ENTRIES[i], name).expect("boot: blk-server");
    }
    task::spawn_named(services::timer::timer_service, "timer").expect("boot: timer");

    // Spawn fs server as a user process with boot channel + control channel
    let (fs_boot_a, fs_boot_b) = ipc::channel_create_pair().expect("boot: fs-boot channel");
    services::init::register_boot(fs_boot_b, services::init::ConsoleType::Serial, false);
    task::spawn_user_elf_with_handles(user_fs_code(), "fs", fs_boot_a, fs_ctl_ep).expect("boot: fs");

    // hello-std is now loaded from the filesystem by init_server

    // Spawn shells with boot channels
    task::spawn_user_elf_with_boot_channel(user_shell_code(), "shell-serial", shell_serial_boot_a).expect("boot: shell-serial");
    if let Some(boot_a) = shell_fb_boot_a {
        task::spawn_user_elf_with_boot_channel(user_shell_code(), "shell-fb", boot_a).expect("boot: shell-fb");
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
        unsafe { core::arch::asm!("wfi"); }
    }
}
