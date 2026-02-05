use crate::task::context::TaskContext;
use crate::mm::address::{PhysPageNum, PAGE_SIZE};
use crate::mm::frame;
use crate::mm::page_table::{PageTable, PTE_R, PTE_W, PTE_X, PTE_U};
use core::sync::atomic::{AtomicUsize, Ordering};

const KERNEL_STACK_PAGES: usize = 4; // 16 KiB
const KERNEL_STACK_SIZE: usize = KERNEL_STACK_PAGES * PAGE_SIZE;

const USER_STACK_PAGES: usize = 4; // 16 KiB
const USER_STACK_SIZE: usize = USER_STACK_PAGES * PAGE_SIZE;

// User code is placed at this address
pub const USER_CODE_BASE: usize = 0x8040_0000;
// User stack top (grows downward from here)
pub const USER_STACK_TOP: usize = 0x8060_0000;
pub const USER_STACK_BASE: usize = USER_STACK_TOP - USER_STACK_SIZE;

pub const MAX_PROCS: usize = 64;
const NAME_LEN: usize = 16;

static NEXT_PID: AtomicUsize = AtomicUsize::new(1);

fn alloc_pid() -> usize {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Dead,
}

pub struct Process {
    pub pid: usize,
    pub state: ProcessState,
    pub context: TaskContext,
    pub kernel_stack_base: usize,
    pub kernel_stack_top: usize,
    pub is_user: bool,
    pub user_satp: usize, // satp value for user page table (0 = kernel task)
    name: [u8; NAME_LEN],
    name_len: usize,
}

impl Process {
    /// Create a new kernel task with the given entry function
    pub fn new_kernel(entry: fn()) -> Self {
        let pid = alloc_pid();

        let stack_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_PAGES)
            .expect("Failed to allocate kernel stack");
        let stack_base = stack_ppn.0 * PAGE_SIZE;
        let stack_top = stack_base + KERNEL_STACK_SIZE;

        let context = TaskContext::new(entry as usize, stack_top);

        Process {
            pid,
            state: ProcessState::Ready,
            context,
            kernel_stack_base: stack_base,
            kernel_stack_top: stack_top,
            is_user: false,
            user_satp: 0,
            name: [0u8; NAME_LEN],
            name_len: 0,
        }
    }

    /// Create a user process.
    /// `user_code` is the machine code bytes to run in U-mode.
    /// We create a new page table, copy code to user pages, set up user stack.
    pub fn new_user(user_code: &[u8]) -> Self {
        let pid = alloc_pid();

        // Allocate kernel stack for this process (used during traps)
        let kstack_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_PAGES)
            .expect("Failed to allocate kernel stack for user process");
        let kstack_base = kstack_ppn.0 * PAGE_SIZE;
        let kstack_top = kstack_base + KERNEL_STACK_SIZE;

        // Create a new page table for this user process
        let mut pt = create_user_page_table(user_code);
        let satp = pt.satp();

        // Leak the page table (it needs to live as long as the process)
        core::mem::forget(pt);

        // Set up context: the "ra" will point to a trampoline that
        // sets up sscratch and sret's to user mode
        // We use a special entry that will jump to user mode
        let context = TaskContext::new_user_entry(kstack_top);

        Process {
            pid,
            state: ProcessState::Ready,
            context,
            kernel_stack_base: kstack_base,
            kernel_stack_top: kstack_top,
            is_user: true,
            user_satp: satp,
            name: [0u8; NAME_LEN],
            name_len: 0,
        }
    }

    /// Create a "dummy" process representing the boot/idle task (PID 0)
    pub fn new_idle() -> Self {
        let mut p = Process {
            pid: 0,
            state: ProcessState::Running,
            context: TaskContext::zero(),
            kernel_stack_base: 0,
            kernel_stack_top: 0,
            is_user: false,
            user_satp: 0,
            name: [0u8; NAME_LEN],
            name_len: 0,
        };
        p.set_name("idle");
        p
    }

    pub fn set_name(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let len = bytes.len().min(NAME_LEN);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name_len = len;
    }

    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("???")
    }
}

/// Create a user page table:
/// - Identity-map all kernel memory (without U bit)
/// - Map user code pages at USER_CODE_BASE (with U bit)
/// - Map user stack pages at USER_STACK_BASE (with U bit)
fn create_user_page_table(user_code: &[u8]) -> PageTable {
    extern "C" {
        static _text_start: u8;
        static _text_end: u8;
        static _rodata_start: u8;
        static _rodata_end: u8;
        static _data_start: u8;
        fn _stack_top();
    }

    let text_start = unsafe { &_text_start as *const u8 as usize };
    let text_end = unsafe { &_text_end as *const u8 as usize };
    let rodata_start = unsafe { &_rodata_start as *const u8 as usize };
    let rodata_end = unsafe { &_rodata_end as *const u8 as usize };
    let data_start = unsafe { &_data_start as *const u8 as usize };
    let stack_top = _stack_top as *const () as usize;

    let mut pt = PageTable::new();

    crate::println!("[user-pt] free_start={:#x} user_region={:#x}..{:#x}",
        (stack_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1),
        USER_CODE_BASE, USER_STACK_TOP);

    // Identity-map SBI region
    pt.map_range(0x8000_0000, 0x8000_0000, text_start - 0x8000_0000, PTE_R | PTE_X);

    // Identity-map kernel text as R+X (no U bit)
    pt.map_range(text_start, text_start, text_end - text_start, PTE_R | PTE_X);

    // Identity-map rodata as R (no U bit)
    pt.map_range(rodata_start, rodata_start, rodata_end - rodata_start, PTE_R);

    // Identity-map data + bss + stack as R+W (no U bit)
    pt.map_range(data_start, data_start, stack_top - data_start, PTE_R | PTE_W);

    // Identity-map free memory region as R+W (no U bit)
    // Skip the user code and stack regions to avoid double-mapping
    let free_start = (stack_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let user_region_start = USER_CODE_BASE;
    let user_region_end = USER_STACK_TOP;
    // Map free memory before the user region
    if free_start < user_region_start {
        pt.map_range(free_start, free_start, user_region_start - free_start, PTE_R | PTE_W);
    }
    // Map free memory after the user region
    if user_region_end < 0x8800_0000 {
        pt.map_range(user_region_end, user_region_end, 0x8800_0000 - user_region_end, PTE_R | PTE_W);
    }

    // Identity-map UART
    pt.map_range(0x1000_0000, 0x1000_0000, PAGE_SIZE, PTE_R | PTE_W);

    // Identity-map PLIC
    pt.map_range(0x0C00_0000, 0x0C00_0000, 0x0400_0000, PTE_R | PTE_W);

    // Identity-map CLINT
    pt.map_range(0x0200_0000, 0x0200_0000, 0x0001_0000, PTE_R | PTE_W);

    // Identity-map VirtIO
    pt.map_range(0x1000_1000, 0x1000_1000, 0x0000_8000, PTE_R | PTE_W);

    // Now allocate and map user code pages with U bit
    let code_pages = (user_code.len() + PAGE_SIZE - 1) / PAGE_SIZE;
    let code_pages = if code_pages == 0 { 1 } else { code_pages };
    let code_ppn = frame::frame_alloc_contiguous(code_pages)
        .expect("Failed to allocate user code pages");
    // Copy user code into these pages
    let code_dst = code_ppn.0 * PAGE_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            user_code.as_ptr(),
            code_dst as *mut u8,
            user_code.len(),
        );
    }
    // Map code pages at USER_CODE_BASE with U+R+X
    for i in 0..code_pages {
        let vpn = crate::mm::address::VirtPageNum((USER_CODE_BASE + i * PAGE_SIZE) / PAGE_SIZE);
        let ppn = PhysPageNum(code_ppn.0 + i);
        pt.map(vpn, ppn, PTE_R | PTE_X | PTE_U);
    }

    // Allocate and map user stack pages with U bit
    let stack_ppn = frame::frame_alloc_contiguous(USER_STACK_PAGES)
        .expect("Failed to allocate user stack pages");
    for i in 0..USER_STACK_PAGES {
        let vpn = crate::mm::address::VirtPageNum((USER_STACK_BASE + i * PAGE_SIZE) / PAGE_SIZE);
        let ppn = PhysPageNum(stack_ppn.0 + i);
        pt.map(vpn, ppn, PTE_R | PTE_W | PTE_U);
    }

    pt
}
