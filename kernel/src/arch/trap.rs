use crate::arch::csr;
use crate::arch::sbi;
use crate::task::HandleObject;
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
pub const SYS_CHAN_SEND_BLOCKING: usize = 207;
pub const SYS_SHM_CREATE: usize = 205;
pub const SYS_SHM_DUP_RO: usize = 206;
pub const SYS_MUNMAP: usize = 215;
pub const SYS_MMAP: usize = 222;
pub const SYS_TRACE: usize = 230;
pub const SYS_SHUTDOWN: usize = 231;

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

    // Trace non-trivial syscalls (skip yield/getpid/trace to reduce noise)
    let trace_this = !matches!(syscall_num, SYS_YIELD | SYS_GETPID | SYS_TRACE
        | SYS_CHAN_SEND | SYS_CHAN_SEND_BLOCKING | SYS_CHAN_RECV | SYS_CHAN_RECV_BLOCKING);
    if trace_this {
        let pid = crate::task::current_pid();
        let mut label = [0u8; 16];
        label[..4].copy_from_slice(b"sc=\0");
        let n = fmt_usize(syscall_num, &mut label[3..]);
        crate::trace::trace_push(pid, &label[..3 + n]);
    }

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
        _ => {
            crate::println!("Unknown syscall: {}", syscall_num);
            tf.regs[10] = usize::MAX;
        }
    }

    if trace_this {
        let pid = crate::task::current_pid();
        let mut label = [0u8; 16];
        label[..7].copy_from_slice(b"sc-end=");
        let n = fmt_usize(syscall_num, &mut label[7..]);
        crate::trace::trace_push(pid, &label[..7 + n]);
    }
}

/// Format a usize as decimal into buf. Returns number of bytes written.
fn fmt_usize(mut val: usize, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

/// SYS_CHAN_CREATE: create a bidirectional channel pair.
/// Returns handle_a in a0, handle_b in a1.
fn sys_chan_create(tf: &mut TrapFrame) {
    let (ep_a, ep_b) = crate::ipc::channel_create_pair();
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
/// If message has a cap, translate cap handle -> encoded capability.
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

    // Set sender PID
    msg.sender_pid = crate::task::current_pid();

    // Translate cap if present: local handle -> encoded capability
    if msg.cap != crate::ipc::NO_CAP {
        match crate::task::current_process_handle(msg.cap) {
            Some(HandleObject::Channel(global_ep)) => {
                if !crate::ipc::channel_inc_ref(global_ep) {
                    return usize::MAX;
                }
                msg.cap = crate::ipc::encode_cap_channel(global_ep);
            }
            Some(HandleObject::Shm { id, rw }) => {
                // Increment ref_count for the SHM region being transferred
                if !crate::ipc::shm_inc_ref(id) {
                    return usize::MAX;
                }
                msg.cap = crate::ipc::encode_cap_shm(id, rw);
            }
            None => return usize::MAX, // invalid cap handle
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

/// Install a received capability into the current process's handle table.
/// Returns the local handle index to write into msg.cap, or NO_CAP on failure.
fn install_received_cap(encoded_cap: usize) -> usize {
    match crate::ipc::decode_cap(encoded_cap) {
        crate::ipc::DecodedCap::None => crate::ipc::NO_CAP,
        crate::ipc::DecodedCap::Channel(global_ep) => {
            match crate::task::current_process_alloc_handle(HandleObject::Channel(global_ep)) {
                Some(h) => h,
                None => {
                    // Failed to install; decrement ref_count since it was incremented on send
                    crate::ipc::channel_close(global_ep);
                    crate::ipc::NO_CAP
                }
            }
        }
        crate::ipc::DecodedCap::Shm { id, rw } => {
            match crate::task::current_process_alloc_handle(HandleObject::Shm { id, rw }) {
                Some(h) => h,
                None => {
                    // Failed to install; decrement ref_count since it was incremented on send
                    crate::ipc::shm_dec_ref(id);
                    crate::ipc::NO_CAP
                }
            }
        }
    }
}

/// SYS_CHAN_RECV (non-blocking): translate handle, try recv, translate cap in result.
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
            // Translate cap: encoded capability -> new local handle in receiver
            if msg.cap != crate::ipc::NO_CAP {
                msg.cap = install_received_cap(msg.cap);
            }
            // Write to user buffer via translated PA
            unsafe {
                core::ptr::write(msg_pa as *mut crate::ipc::Message, msg);
            }
            0
        }
        None => 1, // Nothing available
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
                // Translate cap
                if msg.cap != crate::ipc::NO_CAP {
                    msg.cap = install_received_cap(msg.cap);
                }
                // Write to user buffer via translated PA
                unsafe {
                    core::ptr::write(msg_pa as *mut crate::ipc::Message, msg);
                }
                tf.regs[10] = 0;
                return;
            }
            None => {
                // Check if the channel was closed by the peer
                if !crate::ipc::channel_is_active(endpoint) {
                    // Return a zero-length message to signal EOF
                    let eof = crate::ipc::Message::new();
                    unsafe {
                        core::ptr::write(msg_pa as *mut crate::ipc::Message, eof);
                    }
                    tf.regs[10] = 0;
                    return;
                }
                // Block and wait
                crate::ipc::channel_set_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
                // Woken up — loop back and retry
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
    msg.sender_pid = crate::task::current_pid();

    // Translate cap if present
    if msg.cap != crate::ipc::NO_CAP {
        match crate::task::current_process_handle(msg.cap) {
            Some(HandleObject::Channel(global_ep)) => {
                if !crate::ipc::channel_inc_ref(global_ep) {
                    tf.regs[10] = usize::MAX;
                    return;
                }
                msg.cap = crate::ipc::encode_cap_channel(global_ep);
            }
            Some(HandleObject::Shm { id, rw }) => {
                if !crate::ipc::shm_inc_ref(id) {
                    tf.regs[10] = usize::MAX;
                    return;
                }
                msg.cap = crate::ipc::encode_cap_shm(id, rw);
            }
            None => {
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
                // Check if channel was closed
                if !crate::ipc::channel_is_active(endpoint) {
                    tf.regs[10] = usize::MAX;
                    return;
                }
                // Block until a recv frees a slot
                crate::ipc::channel_set_send_blocked(endpoint, cur_pid);
                crate::task::block_process(cur_pid);
                crate::task::schedule();
                // Woken up — retry
            }
            Err(_) => {
                tf.regs[10] = usize::MAX;
                return;
            }
        }
    }
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

    let page_count = (size + crate::mm::address::PAGE_SIZE - 1) / crate::mm::address::PAGE_SIZE;

    // Allocate contiguous physical frames
    let ppn = match crate::mm::frame::frame_alloc_contiguous(page_count) {
        Some(ppn) => ppn,
        None => return usize::MAX,
    };

    // Zero the allocated pages
    let base_pa = ppn.0 * crate::mm::address::PAGE_SIZE;
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
    let pages = (length + crate::mm::address::PAGE_SIZE - 1) / crate::mm::address::PAGE_SIZE;

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

    let map_pages = (length + crate::mm::address::PAGE_SIZE - 1) / crate::mm::address::PAGE_SIZE;

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
    if length == 0 || addr % crate::mm::address::PAGE_SIZE != 0 {
        return usize::MAX;
    }

    let pages = (length + crate::mm::address::PAGE_SIZE - 1) / crate::mm::address::PAGE_SIZE;
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
