use crate::task::context::{TaskContext, TrapContext};
use crate::mm::address::{PhysPageNum, VirtPageNum, PAGE_SIZE};
use crate::mm::frame;
use crate::mm::page_table::{PageTable, PTE_R, PTE_W, PTE_X, PTE_U};
use crate::mm::heap::{PgtbAlloc, PGTB_ALLOC};
const KERNEL_STACK_PAGES: usize = 16; // 64 KiB
const KERNEL_STACK_SIZE: usize = KERNEL_STACK_PAGES * PAGE_SIZE;
pub const KERNEL_GUARD_PAGES: usize = 1; // guard page at bottom of each kernel stack
/// Total pages allocated per kernel stack (guard + usable)
pub const KERNEL_STACK_ALLOC_PAGES: usize = KERNEL_STACK_PAGES + KERNEL_GUARD_PAGES;

const USER_STACK_PAGES: usize = 8; // 32 KiB
const USER_STACK_SIZE: usize = USER_STACK_PAGES * PAGE_SIZE;

pub const MAX_PROCS: usize = 64;
pub const MAX_HANDLES: usize = 32;
pub const MAX_MMAP_REGIONS: usize = 256;
pub const MAX_BREAKPOINTS: usize = 8;
const NAME_LEN: usize = 16;

/// Non-Copy handle object holding RAII resource wrappers.
/// Drop on HandleObject auto-decrements the underlying resource's ref count.
#[derive(Debug)]
pub enum HandleObject {
    Channel(crate::ipc::OwnedEndpoint),
    Shm { owned: crate::ipc::OwnedShm, rw: bool },
}

/// Lightweight, Copy descriptor returned by handle lookups.
/// Contains only raw IDs — no ownership, no ref counting.
#[derive(Clone, Copy, Debug)]
pub enum HandleInfo {
    Channel(usize),              // raw global endpoint ID
    Shm { id: usize, rw: bool }, // raw global SHM ID + permission flag
}

impl HandleObject {
    pub fn info(&self) -> HandleInfo {
        match self {
            HandleObject::Channel(ep) => HandleInfo::Channel(ep.raw()),
            HandleObject::Shm { owned, rw } => HandleInfo::Shm { id: owned.raw(), rw: *rw },
        }
    }
}

#[derive(Clone, Copy)]
pub struct MmapRegion {
    pub base_ppn: usize,
    pub page_count: usize,
    pub shm_id: Option<usize>, // None = anonymous, Some(id) = SHM-backed
}

/// Read the RISC-V `rdtime` counter (10 MHz on QEMU virt).
#[inline(always)]
pub fn rdtime() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t) };
    t
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Dead,
}

/// What a Blocked process is waiting on. Used for `ps` display and
/// future deadlock detection (feature 0011).
#[derive(Debug, Clone, Copy)]
pub enum BlockReason {
    /// Not blocked, or reason not specified.
    None,
    /// Waiting to receive on a channel endpoint.
    IpcRecv(usize),
    /// Waiting to send on a channel endpoint (queue full).
    IpcSend(usize),
    /// Sleeping until a deadline (rdtime tick).
    Timer(u64),
    /// Blocked in sys_block (event poll).
    Poll,
    /// Suspended by debugger.
    DebugSuspend,
}

pub struct Process {
    pub state: ProcessState,
    pub block_reason: BlockReason,
    pub trap_ctx: TrapContext,
    pub context: TaskContext,
    #[allow(dead_code)]
    pub kernel_stack_base: usize,
    #[allow(dead_code)]
    pub kernel_stack_top: usize,
    pub is_user: bool,
    pub user_satp: usize,      // satp value for user page table (0 = kernel task)
    #[allow(dead_code)]
    pub user_entry: usize,     // virtual (= physical) address of user code
    pub user_stack_top: usize, // virtual (= physical) address of user stack top
    pub handles: [Option<HandleObject>; MAX_HANDLES], // local handle -> HandleObject
    pub mmap_regions: [Option<MmapRegion>; MAX_MMAP_REGIONS],
    name: [u8; NAME_LEN],
    name_len: usize,
    // CPU accounting (EWMA, scaled by 10000 = 100%)
    pub ewma_1s: u32,
    pub ewma_1m: u32,
    pub last_switched_away: u64, // rdtime when last switched away
    // Memory accounting
    pub mem_pages: u32,          // total physical pages owned
    // Wakeup pending flag: set when wake_process is called on a Running/Ready process.
    // Checked by block_process to avoid the "check-then-block" race.
    pub wakeup_pending: bool,
    // Timer deadline: if nonzero and the process is Blocked, the scheduler
    // will wake it when rdtime() >= wake_deadline. Used by timer service.
    pub wake_deadline: u64,
    // Exit notification endpoint: if nonzero, kernel sends exit code on this
    // endpoint when the process exits, then closes it. NOT in the handle table.
    pub exit_notify_ep: usize,
    // --- Resource cleanup fields (used by exit_current_from_syscall) ---
    /// Page table node frames to free on exit (empty for kernel tasks)
    pub pt_frames: alloc::vec::Vec<PhysPageNum, PgtbAlloc>,
    /// PPN of first code page (0 for kernel tasks)
    pub code_ppn: usize,
    /// Number of code pages (0 for kernel tasks)
    pub code_pages: usize,
    // --- Debug state (used by process-debug service) ---
    pub debug_attached: bool,
    pub debug_event_ep: usize,       // event channel endpoint (0 = none)
    pub debug_suspend_pending: bool,
    pub debug_suspended: bool,
    pub debug_breakpoints: [(usize, u16); MAX_BREAKPOINTS], // (addr, original_2_bytes)
    pub debug_breakpoint_count: usize,
    // Scheduler latency: rdtime when this process was last enqueued
    pub enqueue_time: u64,
}

/// Unmap a guard page in the kernel page table so any access causes a fault.
fn setup_guard_page(guard_addr: usize) {
    let satp: usize = crate::read_csr!("satp");
    let root_ppn = PhysPageNum(satp & ((1usize << 44) - 1));
    let vpn = VirtPageNum(guard_addr / PAGE_SIZE);
    let indices = vpn.indices();

    // Walk L2 → L1 → L0 and clear the leaf PTE
    let l2_table = root_ppn.as_page_table();
    if !l2_table[indices[2]].is_valid() { return; }
    let l1_ppn = l2_table[indices[2]].ppn();
    let l1_table = l1_ppn.as_page_table();
    if !l1_table[indices[1]].is_valid() || l1_table[indices[1]].is_leaf() { return; }
    let l0_ppn = l1_table[indices[1]].ppn();
    let l0_table = l0_ppn.as_page_table();
    // Clear PTE (V=0) — any access faults
    l0_table[indices[0]] = crate::mm::page_table::PageTableEntry::empty();
    unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) guard_addr); }
}

/// Restore a guard page's PTE in the kernel page table.
/// Must be called before freeing the guard page back to the frame allocator,
/// otherwise the page will have an empty PTE and any future allocation that
/// reuses it will fault when the kernel tries to access (e.g. memset) it.
pub fn restore_guard_page(guard_addr: usize) {
    use crate::mm::page_table::{PageTableEntry, PTE_V, PTE_R, PTE_W, PTE_A, PTE_D};

    let satp: usize = crate::read_csr!("satp");
    let root_ppn = PhysPageNum(satp & ((1usize << 44) - 1));
    let vpn = VirtPageNum(guard_addr / PAGE_SIZE);
    let ppn = PhysPageNum(guard_addr / PAGE_SIZE); // identity-mapped
    let indices = vpn.indices();

    let l2_table = root_ppn.as_page_table();
    if !l2_table[indices[2]].is_valid() { return; }
    let l1_ppn = l2_table[indices[2]].ppn();
    let l1_table = l1_ppn.as_page_table();
    if !l1_table[indices[1]].is_valid() || l1_table[indices[1]].is_leaf() { return; }
    let l0_ppn = l1_table[indices[1]].ppn();
    let l0_table = l0_ppn.as_page_table();
    // Restore as kernel R+W identity-mapped page
    l0_table[indices[0]] = PageTableEntry::new(ppn, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D);
    unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) guard_addr); }
}

impl Process {
    /// Create a new kernel task with the given entry function.
    /// Returns Err if frame allocation fails.
    pub fn new_kernel(entry: fn()) -> Result<Self, &'static str> {
        let alloc_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_ALLOC_PAGES)
            .ok_or("failed to allocate kernel stack")?;
        let alloc_base = alloc_ppn.0 * PAGE_SIZE;
        // Guard page at bottom, usable stack above it
        let guard_addr = alloc_base;
        let stack_base = alloc_base + KERNEL_GUARD_PAGES * PAGE_SIZE;
        let stack_top = stack_base + KERNEL_STACK_SIZE;
        setup_guard_page(guard_addr);

        let context = TaskContext::new(entry as usize, stack_top);
        let trap_ctx = TrapContext::new_kernel(entry as usize, stack_top);

        Ok(Process {
            state: ProcessState::Ready,
            block_reason: BlockReason::None,
            trap_ctx,
            context,
            kernel_stack_base: stack_base,
            kernel_stack_top: stack_top,
            is_user: false,
            user_satp: 0,
            user_entry: 0,
            user_stack_top: 0,
            handles: [const { None }; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
            name: [0u8; NAME_LEN],
            name_len: 0,
            ewma_1s: 0,
            ewma_1m: 0,
            last_switched_away: rdtime(),
            mem_pages: KERNEL_STACK_ALLOC_PAGES as u32,
            wakeup_pending: false,
            wake_deadline: 0,
            exit_notify_ep: 0,
            pt_frames: alloc::vec::Vec::new_in(PGTB_ALLOC),
            code_ppn: 0,
            code_pages: 0,
            debug_attached: false,
            debug_event_ep: 0,
            debug_suspend_pending: false,
            debug_suspended: false,
            debug_breakpoints: [(0, 0); MAX_BREAKPOINTS],
            debug_breakpoint_count: 0,
            enqueue_time: 0,
        })
    }

    /// Create a user process.
    /// `user_code` is the machine code bytes to run in U-mode.
    /// User code and stack are identity-mapped (VA=PA) in a per-process
    /// page table, so addresses work under both kernel and user page tables.
    /// Returns Err if frame allocation fails.
    #[allow(dead_code)]
    pub fn new_user(user_code: &[u8]) -> Result<Self, &'static str> {
        // Allocate kernel stack for this process (used during traps)
        let kstack_alloc_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_ALLOC_PAGES)
            .ok_or("failed to allocate kernel stack")?;
        let kstack_alloc_base = kstack_alloc_ppn.0 * PAGE_SIZE;
        let kstack_base = kstack_alloc_base + KERNEL_GUARD_PAGES * PAGE_SIZE;
        let kstack_top = kstack_base + KERNEL_STACK_SIZE;
        setup_guard_page(kstack_alloc_base);

        // Allocate user code pages
        let n_code_pages = user_code.len().div_ceil(PAGE_SIZE);
        let n_code_pages = if n_code_pages == 0 { 1 } else { n_code_pages };
        let code_ppn = frame::frame_alloc_contiguous(n_code_pages)
            .ok_or("failed to allocate user code pages")?;
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
            .ok_or("failed to allocate user stack pages")?;
        let stack_phys_base = stack_ppn.0 * PAGE_SIZE;
        let stack_phys_top = stack_phys_base + USER_STACK_SIZE;

        // Create user page table with identity-mapped user pages
        let pt = create_user_page_table_identity(
            code_ppn, n_code_pages, stack_ppn, USER_STACK_PAGES,
        )?;
        let satp = pt.satp();
        let pt_frames = pt.take_frames();

        let context = TaskContext::new_user_entry(kstack_top);
        let trap_ctx = TrapContext::new_user(code_phys, stack_phys_top, kstack_top, satp);

        Ok(Process {
            state: ProcessState::Ready,
            block_reason: BlockReason::None,
            trap_ctx,
            context,
            kernel_stack_base: kstack_base,
            kernel_stack_top: kstack_top,
            is_user: true,
            user_satp: satp,
            user_entry: code_phys,
            user_stack_top: stack_phys_top,
            handles: [const { None }; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
            name: [0u8; NAME_LEN],
            name_len: 0,
            ewma_1s: 0,
            ewma_1m: 0,
            last_switched_away: rdtime(),
            mem_pages: (KERNEL_STACK_ALLOC_PAGES + n_code_pages + USER_STACK_PAGES) as u32,
            wakeup_pending: false,
            wake_deadline: 0,
            exit_notify_ep: 0,
            pt_frames,
            code_ppn: code_ppn.0,
            code_pages: n_code_pages,
            debug_attached: false,
            debug_event_ep: 0,
            debug_suspend_pending: false,
            debug_suspended: false,
            debug_breakpoints: [(0, 0); MAX_BREAKPOINTS],
            debug_breakpoint_count: 0,
            enqueue_time: 0,
        })
    }

    /// Create a user process from an ELF binary.
    /// Parses ELF, loads PT_LOAD segments, creates page table.
    /// Returns Err if frame allocation or ELF loading fails.
    pub fn new_user_elf(elf_data: &[u8]) -> Result<Self, &'static str> {
        crate::trace::trace_kernel(b"new_user_elf-enter");

        // Allocate kernel stack
        let kstack_alloc_ppn = frame::frame_alloc_contiguous(KERNEL_STACK_ALLOC_PAGES)
            .ok_or("failed to allocate kernel stack")?;
        let kstack_alloc_base = kstack_alloc_ppn.0 * PAGE_SIZE;
        let kstack_base = kstack_alloc_base + KERNEL_GUARD_PAGES * PAGE_SIZE;
        let kstack_top = kstack_base + KERNEL_STACK_SIZE;
        setup_guard_page(kstack_alloc_base);

        // Load ELF
        let loaded = crate::mm::elf::load_elf(elf_data)?;

        // Allocate user stack
        let stack_ppn = frame::frame_alloc_contiguous(USER_STACK_PAGES)
            .ok_or("failed to allocate user stack pages")?;
        let stack_phys_base = stack_ppn.0 * PAGE_SIZE;
        let stack_phys_top = stack_phys_base + USER_STACK_SIZE;

        // Create page table: map code at its original VA, stack at identity
        let pt = create_user_page_table_elf(
            loaded.code_ppn, loaded.total_pages, loaded.base_va,
            stack_ppn, USER_STACK_PAGES,
        )?;
        let satp = pt.satp();
        let pt_frames = pt.take_frames();

        let context = TaskContext::new_user_entry(kstack_top);
        let trap_ctx = TrapContext::new_user(loaded.entry_va, stack_phys_top, kstack_top, satp);

        crate::trace::trace_kernel(b"new_user_elf-exit");
        Ok(Process {
            state: ProcessState::Ready,
            block_reason: BlockReason::None,
            trap_ctx,
            context,
            kernel_stack_base: kstack_base,
            kernel_stack_top: kstack_top,
            is_user: true,
            user_satp: satp,
            user_entry: loaded.entry_va,
            user_stack_top: stack_phys_top,
            handles: [const { None }; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
            name: [0u8; NAME_LEN],
            name_len: 0,
            ewma_1s: 0,
            ewma_1m: 0,
            last_switched_away: rdtime(),
            mem_pages: (KERNEL_STACK_ALLOC_PAGES + loaded.total_pages + USER_STACK_PAGES) as u32,
            wakeup_pending: false,
            wake_deadline: 0,
            exit_notify_ep: 0,
            pt_frames,
            code_ppn: loaded.code_ppn.0,
            code_pages: loaded.total_pages,
            debug_attached: false,
            debug_event_ep: 0,
            debug_suspend_pending: false,
            debug_suspended: false,
            debug_breakpoints: [(0, 0); MAX_BREAKPOINTS],
            debug_breakpoint_count: 0,
            enqueue_time: 0,
        })
    }

    /// Create a "dummy" process representing the boot/idle task (PID 0)
    pub fn new_idle() -> Self {
        let mut p = Process {
            state: ProcessState::Running,
            block_reason: BlockReason::None,
            trap_ctx: TrapContext::zero(),
            context: TaskContext::zero(),
            kernel_stack_base: 0,
            kernel_stack_top: 0,
            is_user: false,
            user_satp: 0,
            user_entry: 0,
            user_stack_top: 0,
            handles: [const { None }; MAX_HANDLES],
            mmap_regions: [None; MAX_MMAP_REGIONS],
            name: [0u8; NAME_LEN],
            name_len: 0,
            ewma_1s: 0,
            ewma_1m: 0,
            last_switched_away: rdtime(),
            mem_pages: 0, // idle task doesn't own any pages
            wakeup_pending: false,
            wake_deadline: 0,
            exit_notify_ep: 0,
            pt_frames: alloc::vec::Vec::new_in(PGTB_ALLOC),
            code_ppn: 0,
            code_pages: 0,
            debug_attached: false,
            debug_event_ep: 0,
            debug_suspend_pending: false,
            debug_suspended: false,
            debug_breakpoints: [(0, 0); MAX_BREAKPOINTS],
            debug_breakpoint_count: 0,
            enqueue_time: 0,
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

    /// Look up a local handle to get lightweight info (no ownership transfer).
    pub fn lookup_handle(&self, handle: usize) -> Option<HandleInfo> {
        if handle < MAX_HANDLES {
            self.handles[handle].as_ref().map(|obj| obj.info())
        } else {
            None
        }
    }

    /// Take a handle out of the table, returning the HandleObject.
    /// The caller owns the returned object. Dropping it auto-closes the resource.
    ///
    /// IMPORTANT: Do NOT call this while holding the SCHEDULER lock, then drop
    /// the result while still holding it. OwnedEndpoint::drop → channel_close
    /// → wake_process → SCHEDULER lock = deadlock. Use .take() under lock,
    /// drop outside.
    pub fn take_handle(&mut self, handle: usize) -> Option<HandleObject> {
        if handle < MAX_HANDLES {
            self.handles[handle].take()
        } else {
            None
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
) -> Result<PageTable, &'static str> {
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

    let mut pt = PageTable::new()?;

    // Identity-map SBI region
    pt.map_range(0x8000_0000, 0x8000_0000, text_start - 0x8000_0000, PTE_R | PTE_X)?;

    // Identity-map kernel text as R+X (no U bit)
    pt.map_range(text_start, text_start, text_end - text_start, PTE_R | PTE_X)?;

    // Identity-map rodata as R (no U bit)
    pt.map_range(rodata_start, rodata_start, rodata_end - rodata_start, PTE_R)?;

    // Identity-map data + bss + stack as R+W (no U bit)
    pt.map_range(data_start, data_start, stack_top - data_start, PTE_R | PTE_W)?;

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
            pt.map_range(cursor, cursor, ex_start - cursor, PTE_R | PTE_W)?;
        }
        if ex_end > cursor {
            cursor = ex_end;
        }
    }
    if cursor < ram_end {
        pt.map_range(cursor, cursor, ram_end - cursor, PTE_R | PTE_W)?;
    }

    // Identity-map UART
    pt.map_range(0x1000_0000, 0x1000_0000, PAGE_SIZE, PTE_R | PTE_W)?;

    // Identity-map PLIC
    pt.map_range(0x0C00_0000, 0x0C00_0000, 0x0400_0000, PTE_R | PTE_W)?;

    // Identity-map CLINT
    pt.map_range(0x0200_0000, 0x0200_0000, 0x0001_0000, PTE_R | PTE_W)?;

    // Identity-map VirtIO
    pt.map_range(0x1000_1000, 0x1000_1000, 0x0000_8000, PTE_R | PTE_W)?;

    // Map user code pages at their original ELF VAs with U+R+W+X
    let base_vpn = base_va / PAGE_SIZE;
    for i in 0..code_pages {
        pt.map(VirtPageNum(base_vpn + i), PhysPageNum(code_ppn.0 + i), PTE_R | PTE_W | PTE_X | PTE_U)?;
    }

    // Identity-map user stack pages with U+R+W at their physical address
    for i in 0..stack_pages {
        let addr = stack_ppn.0 + i;
        pt.map(VirtPageNum(addr), PhysPageNum(addr), PTE_R | PTE_W | PTE_U)?;
    }

    Ok(pt)
}

#[allow(dead_code)]
fn create_user_page_table_identity(
    code_ppn: PhysPageNum,
    code_pages: usize,
    stack_ppn: PhysPageNum,
    stack_pages: usize,
) -> Result<PageTable, &'static str> {
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

    let mut pt = PageTable::new()?;

    // Identity-map SBI region
    pt.map_range(0x8000_0000, 0x8000_0000, text_start - 0x8000_0000, PTE_R | PTE_X)?;

    // Identity-map kernel text as R+X (no U bit)
    pt.map_range(text_start, text_start, text_end - text_start, PTE_R | PTE_X)?;

    // Identity-map rodata as R (no U bit)
    pt.map_range(rodata_start, rodata_start, rodata_end - rodata_start, PTE_R)?;

    // Identity-map data + bss + stack as R+W (no U bit)
    pt.map_range(data_start, data_start, stack_top - data_start, PTE_R | PTE_W)?;

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
            pt.map_range(cursor, cursor, ex_start - cursor, PTE_R | PTE_W)?;
        }
        if ex_end > cursor {
            cursor = ex_end;
        }
    }
    if cursor < ram_end {
        pt.map_range(cursor, cursor, ram_end - cursor, PTE_R | PTE_W)?;
    }

    // Identity-map UART
    pt.map_range(0x1000_0000, 0x1000_0000, PAGE_SIZE, PTE_R | PTE_W)?;

    // Identity-map PLIC
    pt.map_range(0x0C00_0000, 0x0C00_0000, 0x0400_0000, PTE_R | PTE_W)?;

    // Identity-map CLINT
    pt.map_range(0x0200_0000, 0x0200_0000, 0x0001_0000, PTE_R | PTE_W)?;

    // Identity-map VirtIO
    pt.map_range(0x1000_1000, 0x1000_1000, 0x0000_8000, PTE_R | PTE_W)?;

    // Identity-map user code pages with U+R+W+X at their physical address
    // (includes .text, .rodata, .data, .bss — all in the same contiguous region)
    for i in 0..code_pages {
        let addr = code_ppn.0 + i;
        pt.map(VirtPageNum(addr), PhysPageNum(addr), PTE_R | PTE_W | PTE_X | PTE_U)?;
    }

    // Identity-map user stack pages with U+R+W at their physical address
    for i in 0..stack_pages {
        let addr = stack_ppn.0 + i;
        pt.map(VirtPageNum(addr), PhysPageNum(addr), PTE_R | PTE_W | PTE_U)?;
    }

    Ok(pt)
}
