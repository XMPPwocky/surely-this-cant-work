use crate::arch::csr;
use crate::arch::sbi;
use crate::task::HandleObject;

const TIMER_INTERVAL: u64 = 1_000_000; // 100ms at 10MHz

/// Set to true to log every syscall (except yield) to the trace ring buffer.
/// Format: "name(a0,a1)=ret" with hex values.  Disabled by default.
const TRACE_SYSCALLS: bool = false;


// Syscall numbers
pub const SYS_EXIT: usize = 93;
pub const SYS_YIELD: usize = 124;
pub const SYS_GETPID: usize = 172;
pub const SYS_CHAN_CREATE: usize = 200;
pub const SYS_CHAN_SEND: usize = 201;
pub const SYS_CHAN_RECV: usize = 202;
pub const SYS_CHAN_CLOSE: usize = 203;
pub const SYS_CHAN_RECV_BLOCKING: usize = 204;
pub const SYS_CHAN_SEND_BLOCKING: usize = 207;
pub const SYS_SHM_CREATE: usize = 205;
pub const SYS_SHM_DUP_RO: usize = 206;
pub const SYS_CHAN_POLL_ADD: usize = 208;
pub const SYS_BLOCK: usize = 209;
pub const SYS_MUNMAP: usize = 215;
pub const SYS_MMAP: usize = 222;
pub const SYS_TRACE: usize = 230;
pub const SYS_SHUTDOWN: usize = 231;
pub const SYS_CLOCK: usize = 232;

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
                    return;
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
                    return;
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
                    return;
                }
                panic!("Unhandled exception");
            }
        }
    }
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

fn handle_syscall(tf: &mut TrapFrame) {
    tf.sepc += 4;

    let syscall_num = tf.regs[17]; // a7
    let a0 = tf.regs[10];
    let a1 = tf.regs[11];

    // Capture args before dispatch (some handlers overwrite regs)
    let saved_a0 = a0;
    let saved_a1 = a1;

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
        SYS_CHAN_SEND_BLOCKING => {
            sys_chan_send_blocking(tf);
        }
        SYS_CHAN_POLL_ADD => {
            tf.regs[10] = sys_chan_poll_add(a0);
        }
        SYS_BLOCK => {
            let pid = crate::task::current_pid();
            crate::task::block_process(pid);
            crate::task::schedule();
            tf.regs[10] = 0;
        }
        SYS_SHM_CREATE => {
            tf.regs[10] = sys_shm_create(a0);
        }
        SYS_SHM_DUP_RO => {
            tf.regs[10] = sys_shm_dup_ro(a0);
        }
        SYS_MMAP => {
            tf.regs[10] = sys_mmap(a0, a1);
        }
        SYS_MUNMAP => {
            tf.regs[10] = sys_munmap(a0, a1);
        }
        SYS_TRACE => {
            tf.regs[10] = sys_trace(a0, a1);
        }
        SYS_SHUTDOWN => {
            crate::println!("System shutdown requested by PID {}", crate::task::current_pid());
            sbi::sbi_shutdown();
        }
        SYS_CLOCK => {
            let (wall, cpu) = crate::task::global_clock();
            tf.regs[10] = wall as usize;
            tf.regs[11] = cpu as usize;
        }
        _ => {
            crate::println!("Unknown syscall: {}", syscall_num);
            tf.regs[10] = usize::MAX;
        }
    }

    // Comprehensive syscall tracing (disabled by default; flip TRACE_SYSCALLS to enable)
    if TRACE_SYSCALLS && syscall_num != SYS_YIELD {
        let pid = crate::task::current_pid();
        let ret = tf.regs[10];
        trace_syscall(pid, syscall_num, saved_a0, saved_a1, ret);
    }

}

// ============================================================
// Syscall tracing helpers
// ============================================================

/// Short name for a syscall number (for trace output).
fn syscall_name(num: usize) -> &'static [u8] {
    match num {
        SYS_EXIT => b"exit",
        SYS_YIELD => b"yield",
        SYS_GETPID => b"getpid",
        SYS_CHAN_CREATE => b"create",
        SYS_CHAN_SEND => b"send",
        SYS_CHAN_RECV => b"recv",
        SYS_CHAN_CLOSE => b"close",
        SYS_CHAN_RECV_BLOCKING => b"recvb",
        SYS_CHAN_SEND_BLOCKING => b"sendb",
        SYS_CHAN_POLL_ADD => b"polladd",
        SYS_BLOCK => b"block",
        SYS_SHM_CREATE => b"shmc",
        SYS_SHM_DUP_RO => b"shmro",
        SYS_MMAP => b"mmap",
        SYS_MUNMAP => b"munmap",
        SYS_TRACE => b"trace",
        SYS_SHUTDOWN => b"shut",
        SYS_CLOCK => b"clock",
        _ => b"?",
    }
}

/// Format a usize as lowercase hex into buf. Returns bytes written.
fn fmt_hex(mut val: usize, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut i = 0;
    while val > 0 && i < 16 {
        let nibble = (val & 0xF) as u8;
        tmp[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        val >>= 4;
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

/// Log one completed syscall to the trace ring buffer.
/// Format: "name(a0,a1)=ret" with hex args, fitting in 32 bytes.
fn trace_syscall(pid: usize, num: usize, a0: usize, a1: usize, ret: usize) {
    let mut buf = [0u8; 32];
    let name = syscall_name(num);
    let mut p = 0;
    // name
    let n = name.len().min(6);
    buf[p..p + n].copy_from_slice(&name[..n]);
    p += n;
    // (a0
    if p < 31 { buf[p] = b'('; p += 1; }
    p += fmt_hex(a0, &mut buf[p..]);
    // ,a1
    if p < 31 { buf[p] = b','; p += 1; }
    p += fmt_hex(a1, &mut buf[p..]);
    // )=ret
    if p < 31 { buf[p] = b')'; p += 1; }
    if p < 31 { buf[p] = b'='; p += 1; }
    p += fmt_hex(ret, &mut buf[p..]);
    crate::trace::trace_push(pid, &buf[..p.min(32)]);
}


/// SYS_CHAN_CREATE: create a bidirectional channel pair.
/// Returns handle_a in a0, handle_b in a1.
fn sys_chan_create(tf: &mut TrapFrame) {
    let (ep_a, ep_b) = match crate::ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };
    let handle_a = match crate::task::current_process_alloc_handle(HandleObject::Channel(ep_a)) {
        Some(h) => h,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };
    let handle_b = match crate::task::current_process_alloc_handle(HandleObject::Channel(ep_b)) {
        Some(h) => h,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };
    tf.regs[10] = handle_a;
    tf.regs[11] = handle_b;
}

/// SYS_CHAN_SEND: translate handle -> endpoint, copy message from user, send.
/// Translates all caps in caps[0..cap_count] from local handles to encoded capabilities.
fn sys_chan_send(handle: usize, msg_ptr: usize) -> usize {
    let msg_pa = match validate_user_buffer(msg_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => return usize::MAX,
    };

    // Translate handle to global endpoint (must be a channel)
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => return usize::MAX,
    };

    // Read message from user space via translated PA (kernel identity-maps all RAM)
    let mut msg = unsafe { core::ptr::read(msg_pa as *const crate::ipc::Message) };

    // Clamp msg.len to prevent OOB slicing on untrusted user data
    msg.len = msg.len.min(crate::ipc::MAX_MSG_SIZE);
    msg.cap_count = msg.cap_count.min(crate::ipc::MAX_CAPS);

    // Set sender PID
    msg.sender_pid = crate::task::current_pid();

    // Translate all caps: local handle -> encoded capability
    // Track how many we've successfully translated for rollback on failure
    let mut translated = 0usize;
    for i in 0..msg.cap_count {
        match translate_cap_for_send(msg.caps[i]) {
            Some(encoded) => {
                msg.caps[i] = encoded;
                translated += 1;
            }
            None => {
                // Rollback previously translated caps
                for j in 0..translated {
                    rollback_encoded_cap(msg.caps[j]);
                }
                return usize::MAX;
            }
        }
    }

    // Send
    let wake_pid = match crate::ipc::channel_send_ref(endpoint, &msg) {
        Ok(w) => w,
        Err(crate::ipc::SendError::QueueFull) => return 5, // QUEUE_FULL error code
        Err(_) => return usize::MAX,
    };
    if wake_pid != 0 {
        crate::task::wake_process(wake_pid);
    }
    0
}

/// Translate a user-space cap handle into an encoded capability for the message queue.
/// Increments ref count on success. Returns None on invalid handle.
fn translate_cap_for_send(local_handle: usize) -> Option<usize> {
    if local_handle == crate::ipc::NO_CAP {
        return Some(crate::ipc::NO_CAP);
    }
    match crate::task::current_process_handle(local_handle) {
        Some(HandleObject::Channel(global_ep)) => {
            if !crate::ipc::channel_inc_ref(global_ep) {
                return None;
            }
            Some(crate::ipc::encode_cap_channel(global_ep))
        }
        Some(HandleObject::Shm { id, rw }) => {
            if !crate::ipc::shm_inc_ref(id) {
                return None;
            }
            Some(crate::ipc::encode_cap_shm(id, rw))
        }
        None => None,
    }
}

/// Rollback an encoded cap by decrementing its ref count.
fn rollback_encoded_cap(encoded: usize) {
    match crate::ipc::decode_cap(encoded) {
        crate::ipc::DecodedCap::Channel(ep) => { crate::ipc::channel_close(ep); }
        crate::ipc::DecodedCap::Shm { id, .. } => { crate::ipc::shm_dec_ref(id); }
        crate::ipc::DecodedCap::None => {}
    }
}

/// Install a received capability into the current process's handle table.
/// Returns the local handle index, or NO_CAP on failure.
fn install_received_cap(encoded_cap: usize) -> usize {
    match crate::ipc::decode_cap(encoded_cap) {
        crate::ipc::DecodedCap::None => crate::ipc::NO_CAP,
        crate::ipc::DecodedCap::Channel(global_ep) => {
            match crate::task::current_process_alloc_handle(HandleObject::Channel(global_ep)) {
                Some(h) => h,
                None => {
                    crate::ipc::channel_close(global_ep);
                    crate::ipc::NO_CAP
                }
            }
        }
        crate::ipc::DecodedCap::Shm { id, rw } => {
            match crate::task::current_process_alloc_handle(HandleObject::Shm { id, rw }) {
                Some(h) => h,
                None => {
                    crate::ipc::shm_dec_ref(id);
                    crate::ipc::NO_CAP
                }
            }
        }
    }
}

/// Install all received caps in a message into the current process's handle table.
fn install_received_caps(msg: &mut crate::ipc::Message) {
    for i in 0..msg.cap_count {
        if msg.caps[i] != crate::ipc::NO_CAP {
            msg.caps[i] = install_received_cap(msg.caps[i]);
        }
    }
}

/// SYS_CHAN_RECV (non-blocking): translate handle, try recv, translate caps in result.
fn sys_chan_recv(handle: usize, msg_buf_ptr: usize) -> usize {
    let msg_pa = match validate_user_buffer(msg_buf_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => return usize::MAX,
    };

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => return usize::MAX,
    };

    let (msg, send_wake) = crate::ipc::channel_recv(endpoint);
    if send_wake != 0 {
        crate::task::wake_process(send_wake);
    }
    match msg {
        Some(mut msg) => {
            install_received_caps(&mut msg);
            unsafe {
                core::ptr::write(msg_pa as *mut crate::ipc::Message, msg);
            }
            0
        }
        None => {
            if !crate::ipc::channel_is_active(endpoint) {
                2 // ChannelClosed
            } else {
                1 // Nothing available
            }
        }
    }
}

/// SYS_CHAN_RECV_BLOCKING: like recv but blocks if empty.
fn sys_chan_recv_blocking(tf: &mut TrapFrame) {
    let handle = tf.regs[10];
    let msg_buf_ptr = tf.regs[11];
    let msg_pa = match validate_user_buffer(msg_buf_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    let cur_pid = crate::task::current_pid();
    loop {
        let (msg, send_wake) = crate::ipc::channel_recv(endpoint);
        if send_wake != 0 {
            crate::task::wake_process(send_wake);
        }
        match msg {
            Some(mut msg) => {
                install_received_caps(&mut msg);
                unsafe {
                    core::ptr::write(msg_pa as *mut crate::ipc::Message, msg);
                }
                tf.regs[10] = 0;
                return;
            }
            None => {
                if !crate::ipc::channel_is_active(endpoint) {
                    tf.regs[10] = 2; // ChannelClosed
                    return;
                }
                crate::ipc::channel_set_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
            }
        }
    }
}

/// SYS_CHAN_SEND_BLOCKING: like send but blocks if queue full.
fn sys_chan_send_blocking(tf: &mut TrapFrame) {
    let handle = tf.regs[10];
    let msg_ptr = tf.regs[11];
    let msg_pa = match validate_user_buffer(msg_ptr, core::mem::size_of::<crate::ipc::Message>()) {
        Some(pa) => pa,
        None => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    // Translate handle to global endpoint
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => {
            tf.regs[10] = usize::MAX;
            return;
        }
    };

    // Read message from user space
    let mut msg = unsafe { core::ptr::read(msg_pa as *const crate::ipc::Message) };
    msg.len = msg.len.min(crate::ipc::MAX_MSG_SIZE);
    msg.cap_count = msg.cap_count.min(crate::ipc::MAX_CAPS);
    msg.sender_pid = crate::task::current_pid();

    // Translate all caps
    let mut translated = 0usize;
    for i in 0..msg.cap_count {
        match translate_cap_for_send(msg.caps[i]) {
            Some(encoded) => {
                msg.caps[i] = encoded;
                translated += 1;
            }
            None => {
                for j in 0..translated {
                    rollback_encoded_cap(msg.caps[j]);
                }
                tf.regs[10] = usize::MAX;
                return;
            }
        }
    }

    let cur_pid = crate::task::current_pid();
    loop {
        match crate::ipc::channel_send_ref(endpoint, &msg) {
            Ok(wake) => {
                if wake != 0 {
                    crate::task::wake_process(wake);
                }
                tf.regs[10] = 0;
                return;
            }
            Err(crate::ipc::SendError::QueueFull) => {
                if !crate::ipc::channel_is_active(endpoint) {
                    tf.regs[10] = usize::MAX;
                    return;
                }
                crate::ipc::channel_set_send_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
            }
            Err(_) => {
                tf.regs[10] = usize::MAX;
                return;
            }
        }
    }
}

/// SYS_CHAN_POLL_ADD: register the calling process as blocked-waiting on a
/// channel handle so that any future send to that endpoint will wake us.
/// Call this for every handle of interest, then call SYS_BLOCK to sleep.
/// The wakeup_pending flag prevents races between the last poll_add and block.
fn sys_chan_poll_add(handle: usize) -> usize {
    let endpoint = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => ep,
        _ => return usize::MAX,
    };
    let pid = crate::task::current_pid();
    crate::ipc::channel_set_blocked(endpoint, pid);
    0
}

/// SYS_CHAN_CLOSE: close a handle (channel or SHM).
fn sys_chan_close(handle: usize) -> usize {
    match crate::task::current_process_handle(handle) {
        Some(HandleObject::Channel(ep)) => {
            crate::task::current_process_free_handle(handle);
            crate::ipc::channel_close(ep);
            0
        }
        Some(HandleObject::Shm { id, .. }) => {
            crate::task::current_process_free_handle(handle);
            crate::ipc::shm_dec_ref(id);
            0
        }
        None => usize::MAX,
    }
}

/// SYS_SHM_CREATE: create a shared memory region and return a RW handle.
fn sys_shm_create(size: usize) -> usize {
    if size == 0 {
        return usize::MAX;
    }

    let page_count = size.div_ceil(crate::mm::address::PAGE_SIZE);

    // Allocate contiguous physical frames
    let ppn = match crate::mm::frame::frame_alloc_contiguous(page_count) {
        Some(ppn) => ppn,
        None => return usize::MAX,
    };

    // Zero the allocated pages
    let base_pa = ppn.0 * crate::mm::address::PAGE_SIZE;
    crate::println!("[shm_create] PID {} pages={} range={:#x}..{:#x} (ppn {:#x}..{:#x})",
        crate::task::current_pid(), page_count, base_pa, base_pa + page_count * crate::mm::address::PAGE_SIZE,
        ppn.0, ppn.0 + page_count);

    unsafe {
        core::ptr::write_bytes(base_pa as *mut u8, 0, page_count * crate::mm::address::PAGE_SIZE);
    }

    // Create SHM region in global table
    let shm_id = match crate::ipc::shm_create(ppn, page_count) {
        Some(id) => id,
        None => {
            // Table full, free the frames
            for i in 0..page_count {
                crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + i));
            }
            return usize::MAX;
        }
    };

    // Install RW handle in caller's handle table
    match crate::task::current_process_alloc_handle(HandleObject::Shm { id: shm_id, rw: true }) {
        Some(local_handle) => local_handle,
        None => {
            // Handle table full, clean up
            crate::ipc::shm_dec_ref(shm_id);
            usize::MAX
        }
    }
}

/// SYS_SHM_DUP_RO: duplicate a SHM handle as read-only.
fn sys_shm_dup_ro(handle: usize) -> usize {
    // Look up the handle - must be SHM
    let shm_id = match crate::task::current_process_handle(handle) {
        Some(HandleObject::Shm { id, .. }) => id,
        _ => return usize::MAX,
    };

    // Increment ref_count
    if !crate::ipc::shm_inc_ref(shm_id) {
        return usize::MAX;
    }

    // Install RO handle
    match crate::task::current_process_alloc_handle(HandleObject::Shm { id: shm_id, rw: false }) {
        Some(local_handle) => local_handle,
        None => {
            crate::ipc::shm_dec_ref(shm_id);
            usize::MAX
        }
    }
}

/// SYS_MMAP: map pages into process address space.
/// a0 == 0: anonymous mapping (allocate fresh pages)
/// a0 != 0: SHM handle mapping (map shared region)
fn sys_mmap(shm_handle: usize, length: usize) -> usize {
    if length == 0 {
        return usize::MAX;
    }

    if shm_handle == 0 {
        // Anonymous mapping (existing behavior)
        sys_mmap_anonymous(length)
    } else {
        // SHM-backed mapping
        sys_mmap_shm(shm_handle, length)
    }
}

fn sys_mmap_anonymous(length: usize) -> usize {
    let pages = length.div_ceil(crate::mm::address::PAGE_SIZE);

    // Allocate contiguous physical pages
    let ppn = match crate::mm::frame::frame_alloc_contiguous(pages) {
        Some(ppn) => ppn,
        None => return usize::MAX,
    };

    let base_pa = ppn.0 * crate::mm::address::PAGE_SIZE;

    // Zero the allocated pages
    unsafe {
        core::ptr::write_bytes(base_pa as *mut u8, 0, pages * crate::mm::address::PAGE_SIZE);
    }

    // Get current process's user_satp and map pages into its page table
    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        // Not a user process
        for i in 0..pages {
            crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + i));
        }
        return usize::MAX;
    }

    // Extract root PPN from satp (lower 44 bits)
    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));

    // Create a PageTable wrapper to map pages with U+R+W
    let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);

    for i in 0..pages {
        let vpn = crate::mm::address::VirtPageNum(ppn.0 + i);
        let page_ppn = crate::mm::address::PhysPageNum(ppn.0 + i);
        pt.map(vpn, page_ppn,
            crate::mm::page_table::PTE_R |
            crate::mm::page_table::PTE_W |
            crate::mm::page_table::PTE_U);
    }

    // Record mmap region in process (anonymous: shm_id = None)
    if !crate::task::current_process_add_mmap(ppn.0, pages, None) {
        // mmap region table full - unmap and free
        let mut pt2 = crate::mm::page_table::PageTable::from_root(root_ppn);
        for i in 0..pages {
            pt2.unmap(crate::mm::address::VirtPageNum(ppn.0 + i));
            crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + i));
        }
        unsafe { core::arch::asm!("sfence.vma"); }
        return usize::MAX;
    }

    // Flush TLB
    unsafe { core::arch::asm!("sfence.vma"); }

    // Track memory pages
    crate::task::current_process_adjust_mem_pages(pages as i32);

    base_pa // VA = PA due to identity mapping
}

fn sys_mmap_shm(shm_handle: usize, length: usize) -> usize {
    // Look up the SHM handle
    let (shm_id, rw) = match crate::task::current_process_handle(shm_handle) {
        Some(HandleObject::Shm { id, rw }) => (id, rw),
        _ => return usize::MAX,
    };

    // Get region info
    let (base_ppn, region_page_count) = match crate::ipc::shm_get_info(shm_id) {
        Some(info) => info,
        None => return usize::MAX,
    };

    let map_pages = length.div_ceil(crate::mm::address::PAGE_SIZE);

    // Validate: requested length must not exceed region size
    if map_pages > region_page_count {
        return usize::MAX;
    }

    // Get current process's user_satp
    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        return usize::MAX;
    }

    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);

    // Determine page table flags based on handle permission
    let flags = if rw {
        crate::mm::page_table::PTE_R | crate::mm::page_table::PTE_W | crate::mm::page_table::PTE_U
    } else {
        crate::mm::page_table::PTE_R | crate::mm::page_table::PTE_U
    };

    crate::println!("[mmap_shm] PID {} shm={} pages={} range={:#x}..{:#x}",
        crate::task::current_pid(), shm_id, map_pages,
        base_ppn.0 * crate::mm::address::PAGE_SIZE,
        (base_ppn.0 + map_pages) * crate::mm::address::PAGE_SIZE);

    // Map the SHM pages into the process's page table (identity-mapped: VA == PA)
    for i in 0..map_pages {
        let vpn = crate::mm::address::VirtPageNum(base_ppn.0 + i);
        let page_ppn = crate::mm::address::PhysPageNum(base_ppn.0 + i);
        pt.map(vpn, page_ppn, flags);
    }

    // Record mmap region (SHM-backed: shm_id = Some(id))
    if !crate::task::current_process_add_mmap(base_ppn.0, map_pages, Some(shm_id)) {
        // Table full - unmap
        let mut pt2 = crate::mm::page_table::PageTable::from_root(root_ppn);
        for i in 0..map_pages {
            pt2.unmap(crate::mm::address::VirtPageNum(base_ppn.0 + i));
        }
        unsafe { core::arch::asm!("sfence.vma"); }
        return usize::MAX;
    }

    // Flush TLB
    unsafe { core::arch::asm!("sfence.vma"); }

    // Track memory pages
    crate::task::current_process_adjust_mem_pages(map_pages as i32);

    base_ppn.0 * crate::mm::address::PAGE_SIZE // VA = PA
}

fn sys_munmap(addr: usize, length: usize) -> usize {
    if length == 0 || !addr.is_multiple_of(crate::mm::address::PAGE_SIZE) {
        return usize::MAX;
    }

    let pages = length.div_ceil(crate::mm::address::PAGE_SIZE);
    let base_ppn = addr / crate::mm::address::PAGE_SIZE;

    // Validate and remove from process tracking
    let shm_id = match crate::task::current_process_remove_mmap(base_ppn, pages) {
        Some(shm_id) => shm_id, // None = anonymous, Some(id) = SHM-backed
        None => return usize::MAX, // Not found
    };

    // Get user_satp
    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        return usize::MAX;
    }

    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);

    // Unmap pages
    for i in 0..pages {
        let vpn = crate::mm::address::VirtPageNum(base_ppn + i);
        pt.unmap(vpn);
        if shm_id.is_none() {
            // Anonymous: free the physical frame
            crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(base_ppn + i));
        }
        // SHM-backed: do NOT free the physical frame
    }

    // Track memory pages
    crate::task::current_process_adjust_mem_pages(-(pages as i32));

    // Flush TLB
    unsafe { core::arch::asm!("sfence.vma"); }

    0
}

fn sys_exit() {
    crate::task::exit_current_from_syscall();
}

/// SYS_TRACE: record a timestamped trace entry.
/// a0 = pointer to label string, a1 = label length.
fn sys_trace(label_ptr: usize, label_len: usize) -> usize {
    if label_len == 0 || label_len > 32 {
        return usize::MAX;
    }
    let pa = match validate_user_buffer(label_ptr, label_len) {
        Some(pa) => pa,
        None => return usize::MAX,
    };
    let label = unsafe { core::slice::from_raw_parts(pa as *const u8, label_len) };
    crate::trace::trace_push(crate::task::current_pid(), label);
    0
}

/// Translate a user virtual address to a physical address by walking the
/// current process's Sv39 page table. Returns None if unmapped.
fn translate_user_va(va: usize) -> Option<usize> {
    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        return None;
    }
    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let pt = crate::mm::page_table::PageTable::from_root(root_ppn);
    let vpn = crate::mm::address::VirtPageNum(va / crate::mm::address::PAGE_SIZE);
    pt.translate(vpn).map(|ppn| {
        ppn.0 * crate::mm::address::PAGE_SIZE + (va % crate::mm::address::PAGE_SIZE)
    })
}

/// Validate a user buffer and return its physical address.
/// Walks the user page table to translate VA->PA. Logs an error on failure.
fn validate_user_buffer(ptr: usize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let pa = match translate_user_va(ptr) {
        Some(pa) => pa,
        None => {
            crate::println!(
                "[syscall] PID {}: invalid user pointer {:#x} (len={}), page not mapped",
                crate::task::current_pid(), ptr, len
            );
            return None;
        }
    };

    // For cross-page buffers, verify all pages are mapped and contiguous in PA
    let start_page = ptr / crate::mm::address::PAGE_SIZE;
    let end_page = (ptr + len - 1) / crate::mm::address::PAGE_SIZE;
    let pa_base_page = pa / crate::mm::address::PAGE_SIZE;
    for i in 1..=(end_page - start_page) {
        match translate_user_va((start_page + i) * crate::mm::address::PAGE_SIZE) {
            Some(next_pa) if next_pa / crate::mm::address::PAGE_SIZE == pa_base_page + i => {}
            _ => {
                crate::println!(
                    "[syscall] PID {}: user buffer {:#x}+{} spans non-contiguous pages",
                    crate::task::current_pid(), ptr, len
                );
                return None;
            }
        }
    }
    Some(pa)
}

fn timer_tick() {
    // Check keyboard DMA buffer canary every tick
    crate::drivers::virtio::input::check_canary();
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
