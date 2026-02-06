use crate::mm::address::{PhysAddr, PhysPageNum, VirtPageNum, PAGE_SIZE};
use crate::mm::frame;

// PTE flag bits
pub const PTE_V: usize = 1 << 0; // Valid
pub const PTE_R: usize = 1 << 1; // Read
pub const PTE_W: usize = 1 << 2; // Write
pub const PTE_X: usize = 1 << 3; // Execute
pub const PTE_U: usize = 1 << 4; // User
pub const PTE_G: usize = 1 << 5; // Global
pub const PTE_A: usize = 1 << 6; // Accessed
pub const PTE_D: usize = 1 << 7; // Dirty

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PageTableEntry(pub usize);

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: usize) -> Self {
        PageTableEntry((ppn.0 << 10) | flags)
    }

    pub fn empty() -> Self {
        PageTableEntry(0)
    }

    pub fn ppn(&self) -> PhysPageNum {
        PhysPageNum((self.0 >> 10) & 0xFFF_FFFF_FFFF)
    }

    pub fn flags(&self) -> usize {
        self.0 & 0xFF
    }

    pub fn is_valid(&self) -> bool {
        self.0 & PTE_V != 0
    }

    pub fn is_leaf(&self) -> bool {
        let flags = self.flags();
        (flags & PTE_V != 0) && (flags & (PTE_R | PTE_W | PTE_X) != 0)
    }
}

/// Sv39 three-level page table
pub struct PageTable {
    root_ppn: PhysPageNum,
    /// Frames allocated for page table nodes (not including mapped pages)
    frames: alloc::vec::Vec<PhysPageNum>,
}

impl PageTable {
    pub fn new() -> Self {
        let root = frame::frame_alloc().expect("frame_alloc failed for page table root");
        PageTable {
            root_ppn: root,
            frames: alloc::vec![root],
        }
    }

    /// Wrap an existing page table root for runtime modifications.
    /// The `frames` vec starts empty -- we don't track existing PT frames.
    /// New PT frames allocated during map() are tracked but NOT freed on drop
    /// because the page table outlives this wrapper (caller must mem::forget).
    pub fn from_root(root_ppn: PhysPageNum) -> Self {
        PageTable {
            root_ppn,
            frames: alloc::vec::Vec::new(),
        }
    }

    pub fn root_ppn(&self) -> PhysPageNum {
        self.root_ppn
    }

    /// Build the satp value for Sv39 mode
    pub fn satp(&self) -> usize {
        (8usize << 60) | self.root_ppn.0
    }

    /// Map a single virtual page to a physical page
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: usize) {
        let indices = vpn.indices();
        let mut current_ppn = self.root_ppn;

        // Walk levels 2, 1
        for level in (1..3).rev() {
            let pte_table = current_ppn.as_page_table();
            let idx = indices[level];
            if !pte_table[idx].is_valid() {
                // Allocate a new page table frame
                let new_frame = frame::frame_alloc().expect("frame_alloc failed for page table");
                self.frames.push(new_frame);
                pte_table[idx] = PageTableEntry::new(new_frame, PTE_V);
            }
            current_ppn = pte_table[idx].ppn();
        }

        // Level 0: set the leaf entry (allow overwriting, e.g. upgrading permissions for mmap)
        let pte_table = current_ppn.as_page_table();
        let idx = indices[0];
        pte_table[idx] = PageTableEntry::new(ppn, flags | PTE_V | PTE_A | PTE_D);
    }

    /// Unmap a virtual page, returning its physical page number
    pub fn unmap(&mut self, vpn: VirtPageNum) -> PhysPageNum {
        let indices = vpn.indices();
        let mut current_ppn = self.root_ppn;

        for level in (1..3).rev() {
            let pte_table = current_ppn.as_page_table();
            let idx = indices[level];
            assert!(pte_table[idx].is_valid(), "unmap: invalid PTE at level {}", level);
            current_ppn = pte_table[idx].ppn();
        }

        let pte_table = current_ppn.as_page_table();
        let idx = indices[0];
        assert!(pte_table[idx].is_valid(), "unmap: page not mapped at VPN {:#x}", vpn.0);
        let ppn = pte_table[idx].ppn();
        pte_table[idx] = PageTableEntry::empty();
        ppn
    }

    /// Translate a virtual page number to physical page number
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PhysPageNum> {
        let indices = vpn.indices();
        let mut current_ppn = self.root_ppn;

        for level in (1..3).rev() {
            let pte_table = current_ppn.as_page_table();
            let idx = indices[level];
            if !pte_table[idx].is_valid() {
                return None;
            }
            // Check if this is a superpage (leaf at non-zero level)
            if pte_table[idx].is_leaf() {
                return Some(pte_table[idx].ppn());
            }
            current_ppn = pte_table[idx].ppn();
        }

        let pte_table = current_ppn.as_page_table();
        let idx = indices[0];
        if pte_table[idx].is_valid() {
            Some(pte_table[idx].ppn())
        } else {
            None
        }
    }

    /// Map a contiguous range of virtual addresses to physical addresses (identity map helper)
    pub fn map_range(
        &mut self,
        va_start: usize,
        pa_start: usize,
        size: usize,
        flags: usize,
    ) {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        for i in 0..pages {
            let vpn = VirtPageNum((va_start + i * PAGE_SIZE) / PAGE_SIZE);
            let ppn = PhysPageNum((pa_start + i * PAGE_SIZE) / PAGE_SIZE);
            self.map(vpn, ppn, flags);
        }
    }
}

impl Drop for PageTable {
    fn drop(&mut self) {
        // Free all page table frames
        for &frame in &self.frames {
            frame::frame_dealloc(frame);
        }
    }
}
