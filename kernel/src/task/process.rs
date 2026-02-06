use crate::task::context::TaskContext;
use crate::mm::address::{PhysPageNum, VirtPageNum, PAGE_SIZE};
use crate::mm::frame;
use crate::mm::page_table::{PageTable, PTE_R, PTE_W, PTE_X, PTE_U};
use core::sync::atomic::{AtomicUsize, Ordering};

const KERNEL_STACK_PAGES: usize = 4; // 16 KiB
const KERNEL_STACK_SIZE: usize = KERNEL_STACK_PAGES * PAGE_SIZE;

const USER_STACK_PAGES: usize = 8; // 32 KiB
const USER_STACK_SIZE: usize = USER_STACK_PAGES * PAGE_SIZE;

pub const MAX_PROCS: usize = 64;
pub const MAX_HANDLES: usize = 16;
pub const MAX_MMAP_REGIONS: usize = 32;
const NAME_LEN: usize = 16;

#[derive(Clone, Copy, Debug)]
pub enum HandleObject {
    Channel(usize),              // global endpoint ID
    Shm { id: usize, rw: bool }, // global SHM ID + permission flag
}

#[derive(Clone, Copy)]
pub struct MmapRegion {
    pub base_ppn: usize,
    pub page_count: usize,
    pub shm_id: Option<usize>, // None = anonymous, Some(id) = SHM-backed
}

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
    #[allow(dead_code)]
    pub kernel_stack_base: usize,
    pub kernel_stack_top: usize,
    pub is_user: bool,
    pub user_satp: usize,      // satp value for user page table (0 = kernel task)
    pub user_entry: usize,     // virtual (= physical) address of user code
    pub user_stack_top: usize, // virtual (= physical) address of user stack top
    pub handles: [Option<HandleObject>; MAX_HANDLES], // local handle -> HandleObject
    pub mmap_regions: [Option<MmapRegion>; MAX_MMAP_REGIONS],
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
            user_entry: 0,
            user_stack_top: 0,
            handles: [None; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
            name: [0u8; NAME_LEN],
            name_len: 0,
        }
    }

    /// Create a user process.
    /// `user_code` is the machine code bytes to run in U-mode.
    /// User code and stack are identity-mapped (VA=PA) in a per-process
    /// page table, so addresses work under both kernel and user page tables.
    #[allow(dead_code)]
    pub fn new_user(user_code: &[u8]) -> Self {
        let pid = alloc_pid();

        // Allocate kernel stack for this process (used during traps)
        let kstack_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_PAGES)
            .expect("Failed to allocate kernel stack for user process");
        let kstack_base = kstack_ppn.0 * PAGE_SIZE;
        let kstack_top = kstack_base + KERNEL_STACK_SIZE;

        // Allocate user code pages
        let code_pages = (user_code.len() + PAGE_SIZE - 1) / PAGE_SIZE;
        let code_pages = if code_pages == 0 { 1 } else { code_pages };
        let code_ppn = frame::frame_alloc_contiguous(code_pages)
            .expect("Failed to allocate user code pages");
        let code_phys = code_ppn.0 * PAGE_SIZE;

        // Copy user code into the allocated pages
        unsafe {
            core::ptr::copy_nonoverlapping(
                user_code.as_ptr(),
                code_phys as *mut u8,
                user_code.len(),
            );
        }

        // Allocate user stack pages
        let stack_ppn = frame::frame_alloc_contiguous(USER_STACK_PAGES)
            .expect("Failed to allocate user stack pages");
        let stack_phys_base = stack_ppn.0 * PAGE_SIZE;
        let stack_phys_top = stack_phys_base + USER_STACK_SIZE;

        // Create user page table with identity-mapped user pages
        let pt = create_user_page_table_identity(
            code_ppn, code_pages, stack_ppn, USER_STACK_PAGES,
        );
        let satp = pt.satp();
        core::mem::forget(pt);

        let context = TaskContext::new_user_entry(kstack_top);

        Process {
            pid,
            state: ProcessState::Ready,
            context,
            kernel_stack_base: kstack_base,
            kernel_stack_top: kstack_top,
            is_user: true,
            user_satp: satp,
            user_entry: code_phys,
            user_stack_top: stack_phys_top,
            handles: [None; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
            name: [0u8; NAME_LEN],
            name_len: 0,
        }
    }

    /// Create a user process from an ELF binary.
    /// Parses ELF, loads PT_LOAD segments, creates page table.
    pub fn new_user_elf(elf_data: &[u8]) -> Self {
        let pid = alloc_pid();

        // Allocate kernel stack
        let kstack_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_PAGES)
            .expect("Failed to allocate kernel stack for user process");
        let kstack_base = kstack_ppn.0 * PAGE_SIZE;
        let kstack_top = kstack_base + KERNEL_STACK_SIZE;

        // Load ELF
        let loaded = crate::mm::elf::load_elf(elf_data)
            .expect("Failed to load ELF binary");

        // Allocate user stack
        let stack_ppn = frame::frame_alloc_contiguous(USER_STACK_PAGES)
            .expect("Failed to allocate user stack pages");
        let stack_phys_base = stack_ppn.0 * PAGE_SIZE;
        let stack_phys_top = stack_phys_base + USER_STACK_SIZE;

        // Create page table: map code at its original VA, stack at identity
        let pt = create_user_page_table_elf(
            loaded.code_ppn, loaded.total_pages, loaded.base_va,
            stack_ppn, USER_STACK_PAGES,
        );
        let satp = pt.satp();
        core::mem::forget(pt);

        let context = TaskContext::new_user_entry(kstack_top);

        Process {
            pid,
            state: ProcessState::Ready,
            context,
            kernel_stack_base: kstack_base,
            kernel_stack_top: kstack_top,
            is_user: true,
            user_satp: satp,
            user_entry: loaded.entry_va,
            user_stack_top: stack_phys_top,
            handles: [None; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
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
            user_entry: 0,
            user_stack_top: 0,
            handles: [None; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
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

    /// Allocate a handle in this process's table for the given HandleObject.
    /// Returns the local handle index, or None if the table is full.
    pub fn alloc_handle(&mut self, obj: HandleObject) -> Option<usize> {
        for (i, slot) in self.handles.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(obj);
                return Some(i);
            }
        }
        None
    }

    /// Look up a local handle to get the HandleObject.
    pub fn lookup_handle(&self, handle: usize) -> Option<HandleObject> {
        if handle < MAX_HANDLES {
            self.handles[handle]
        } else {
            None
        }
    }

    /// Free a local handle.
    pub fn free_handle(&mut self, handle: usize) {
        if handle < MAX_HANDLES {
            self.handles[handle] = None;
        }
    }

    /// Record an mmap region in the first free slot. Returns true on success, false if full.
    pub fn add_mmap_region(&mut self, base_ppn: usize, page_count: usize, shm_id: Option<usize>) -> bool {
        for slot in self.mmap_regions.iter_mut() {
            if slot.is_none() {
                *slot = Some(MmapRegion { base_ppn, page_count, shm_id });
                return true;
            }
        }
        false
    }

    /// Remove an mmap region matching base_ppn and page_count.
    /// Returns Some(shm_id) if found (shm_id is None for anonymous, Some(id) for SHM-backed).
    pub fn remove_mmap_region(&mut self, base_ppn: usize, page_count: usize) -> Option<Option<usize>> {
        for slot in self.mmap_regions.iter_mut() {
            if let Some(ref region) = slot {
                if region.base_ppn == base_ppn && region.page_count == page_count {
                    let shm_id = region.shm_id;
                    *slot = None;
                    return Some(shm_id);
                }
            }
        }
        None
    }
}

/// Create a user page table with identity-mapped user pages.
/// All kernel memory is identity-mapped without U bit.
/// User code and stack pages are identity-mapped WITH U bit at their
/// physical addresses, so the same addresses work under both kernel
/// and user page tables (critical for syscall buffer access).
/// Create a user page table that maps code at its original ELF virtual addresses.
/// Code pages are mapped at base_va, stack pages are identity-mapped at their PA.
fn create_user_page_table_elf(
    code_ppn: PhysPageNum,
    code_pages: usize,
    base_va: usize,
    stack_ppn: PhysPageNum,
    stack_pages: usize,
) -> PageTable {
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

    // Identity-map SBI region
    pt.map_range(0x8000_0000, 0x8000_0000, text_start - 0x8000_0000, PTE_R | PTE_X);

    // Identity-map kernel text as R+X (no U bit)
    pt.map_range(text_start, text_start, text_end - text_start, PTE_R | PTE_X);

    // Identity-map rodata as R (no U bit)
    pt.map_range(rodata_start, rodata_start, rodata_end - rodata_start, PTE_R);

    // Identity-map data + bss + stack as R+W (no U bit)
    pt.map_range(data_start, data_start, stack_top - data_start, PTE_R | PTE_W);

    // Identity-map free memory as R+W (no U bit), skipping user code+stack pages
    let free_start = (stack_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let code_start = code_ppn.0 * PAGE_SIZE;
    let code_end = code_start + code_pages * PAGE_SIZE;
    let ustack_start = stack_ppn.0 * PAGE_SIZE;
    let ustack_end = ustack_start + stack_pages * PAGE_SIZE;

    let mut excludes: [(usize, usize); 2] = [(code_start, code_end), (ustack_start, ustack_end)];
    if excludes[0].0 > excludes[1].0 {
        excludes.swap(0, 1);
    }

    let mut cursor = free_start;
    let ram_end: usize = 0x8800_0000;
    for &(ex_start, ex_end) in &excludes {
        if cursor < ex_start {
            pt.map_range(cursor, cursor, ex_start - cursor, PTE_R | PTE_W);
        }
        if ex_end > cursor {
            cursor = ex_end;
        }
    }
    if cursor < ram_end {
        pt.map_range(cursor, cursor, ram_end - cursor, PTE_R | PTE_W);
    }

    // Identity-map UART
    pt.map_range(0x1000_0000, 0x1000_0000, PAGE_SIZE, PTE_R | PTE_W);

    // Identity-map PLIC
    pt.map_range(0x0C00_0000, 0x0C00_0000, 0x0400_0000, PTE_R | PTE_W);

    // Identity-map CLINT
    pt.map_range(0x0200_0000, 0x0200_0000, 0x0001_0000, PTE_R | PTE_W);

    // Identity-map VirtIO
    pt.map_range(0x1000_1000, 0x1000_1000, 0x0000_8000, PTE_R | PTE_W);

    // Map user code pages at their original ELF VAs with U+R+W+X
    let base_vpn = base_va / PAGE_SIZE;
    for i in 0..code_pages {
        pt.map(VirtPageNum(base_vpn + i), PhysPageNum(code_ppn.0 + i), PTE_R | PTE_W | PTE_X | PTE_U);
    }

    // Identity-map user stack pages with U+R+W at their physical address
    for i in 0..stack_pages {
        let addr = stack_ppn.0 + i;
        pt.map(VirtPageNum(addr), PhysPageNum(addr), PTE_R | PTE_W | PTE_U);
    }

    pt
}

#[allow(dead_code)]
fn create_user_page_table_identity(
    code_ppn: PhysPageNum,
    code_pages: usize,
    stack_ppn: PhysPageNum,
    stack_pages: usize,
) -> PageTable {
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

    // Identity-map SBI region
    pt.map_range(0x8000_0000, 0x8000_0000, text_start - 0x8000_0000, PTE_R | PTE_X);

    // Identity-map kernel text as R+X (no U bit)
    pt.map_range(text_start, text_start, text_end - text_start, PTE_R | PTE_X);

    // Identity-map rodata as R (no U bit)
    pt.map_range(rodata_start, rodata_start, rodata_end - rodata_start, PTE_R);

    // Identity-map data + bss + stack as R+W (no U bit)
    pt.map_range(data_start, data_start, stack_top - data_start, PTE_R | PTE_W);

    // Identity-map ALL free memory as R+W (no U bit).
    // The user code/stack pages are allocated from this pool and will be
    // re-mapped below with the U bit (the second map call will override).
    // Actually, we need to skip the user pages to avoid double-mapping.
    let free_start = (stack_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Compute ranges to skip (user code and stack physical pages)
    let code_start = code_ppn.0 * PAGE_SIZE;
    let code_end = code_start + code_pages * PAGE_SIZE;
    let ustack_start = stack_ppn.0 * PAGE_SIZE;
    let ustack_end = ustack_start + stack_pages * PAGE_SIZE;

    // Build a list of (start, end) ranges to exclude, sorted
    let mut excludes: [(usize, usize); 2] = [(code_start, code_end), (ustack_start, ustack_end)];
    if excludes[0].0 > excludes[1].0 {
        excludes.swap(0, 1);
    }

    // Map free memory, skipping excluded ranges
    let mut cursor = free_start;
    let ram_end: usize = 0x8800_0000;
    for &(ex_start, ex_end) in &excludes {
        if cursor < ex_start {
            pt.map_range(cursor, cursor, ex_start - cursor, PTE_R | PTE_W);
        }
        if ex_end > cursor {
            cursor = ex_end;
        }
    }
    if cursor < ram_end {
        pt.map_range(cursor, cursor, ram_end - cursor, PTE_R | PTE_W);
    }

    // Identity-map UART
    pt.map_range(0x1000_0000, 0x1000_0000, PAGE_SIZE, PTE_R | PTE_W);

    // Identity-map PLIC
    pt.map_range(0x0C00_0000, 0x0C00_0000, 0x0400_0000, PTE_R | PTE_W);

    // Identity-map CLINT
    pt.map_range(0x0200_0000, 0x0200_0000, 0x0001_0000, PTE_R | PTE_W);

    // Identity-map VirtIO
    pt.map_range(0x1000_1000, 0x1000_1000, 0x0000_8000, PTE_R | PTE_W);

    // Identity-map user code pages with U+R+W+X at their physical address
    // (includes .text, .rodata, .data, .bss — all in the same contiguous region)
    for i in 0..code_pages {
        let addr = code_ppn.0 + i;
        pt.map(VirtPageNum(addr), PhysPageNum(addr), PTE_R | PTE_W | PTE_X | PTE_U);
    }

    // Identity-map user stack pages with U+R+W at their physical address
    for i in 0..stack_pages {
        let addr = stack_ppn.0 + i;
        pt.map(VirtPageNum(addr), PhysPageNum(addr), PTE_R | PTE_W | PTE_U);
    }

    pt
}
