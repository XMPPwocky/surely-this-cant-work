use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use crate::sync::SpinLock;

const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
const MIN_ORDER: usize = 5;   // 32 bytes
const MAX_ORDER: usize = 22;  // 4 MiB
const NUM_ORDERS: usize = MAX_ORDER - MIN_ORDER + 1; // 18

static mut HEAP_SPACE: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

// ============================================================
// Tag accounting
// ============================================================

const MAX_TAGS: usize = 32;

/// Build a u32 pool tag from a 4-byte ASCII literal.
pub const fn tag(bytes: &[u8; 4]) -> u32 {
    (bytes[0] as u32)
        | ((bytes[1] as u32) << 8)
        | ((bytes[2] as u32) << 16)
        | ((bytes[3] as u32) << 24)
}

/// The default tag for all untagged allocations (GlobalAlloc path).
pub const TAG_UNTAGGED: u32 = tag(b"????");

/// Convert a tag back to a 4-byte ASCII string.
pub fn tag_to_str(t: u32) -> [u8; 4] {
    [
        (t & 0xFF) as u8,
        ((t >> 8) & 0xFF) as u8,
        ((t >> 16) & 0xFF) as u8,
        ((t >> 24) & 0xFF) as u8,
    ]
}

/// Per-tag statistics.
#[derive(Clone, Copy)]
pub struct TagStats {
    pub tag: u32,
    pub current_bytes: usize,
    pub peak_bytes: usize,
    pub alloc_count: usize,
}

impl TagStats {
    const fn empty() -> Self {
        TagStats { tag: 0, current_bytes: 0, peak_bytes: 0, alloc_count: 0 }
    }
}

// ============================================================
// Buddy allocator
// ============================================================

struct BuddyAllocator {
    base: usize,
    free_lists: [*mut usize; NUM_ORDERS],
    bitmap: [u8; 16384],
    // Tag accounting
    tag_stats: [TagStats; MAX_TAGS],
    tag_count: usize,
    total_used: usize,
}

unsafe impl Send for BuddyAllocator {}

/// Compute the buddy order for a given size (standalone, no &self needed).
fn order_for_size(size: usize) -> usize {
    let size = size.max(1 << MIN_ORDER);
    let order = (usize::BITS - (size - 1).leading_zeros()) as usize;
    order.max(MIN_ORDER).min(MAX_ORDER)
}

impl BuddyAllocator {
    const fn new() -> Self {
        BuddyAllocator {
            base: 0,
            free_lists: [ptr::null_mut(); NUM_ORDERS],
            bitmap: [0u8; 16384],
            tag_stats: [TagStats::empty(); MAX_TAGS],
            tag_count: 0,
            total_used: 0,
        }
    }

    unsafe fn init(&mut self, start: *mut u8, size: usize) {
        assert!(size == HEAP_SIZE);
        self.base = start as usize;
        let idx = MAX_ORDER - MIN_ORDER;
        self.free_lists[idx] = start as *mut usize;
        *(start as *mut usize) = 0;
    }

    fn order_for_size(&self, size: usize) -> usize {
        order_for_size(size)
    }

    fn bitmap_index(&self, order: usize, block_offset: usize) -> usize {
        let level_offset = (1 << (MAX_ORDER - MIN_ORDER)) - (1 << (MAX_ORDER - order));
        let index_within = block_offset >> (order + 1);
        level_offset + index_within
    }

    fn toggle_bit(&mut self, bit_idx: usize) -> bool {
        let byte = bit_idx / 8;
        let bit = bit_idx % 8;
        self.bitmap[byte] ^= 1 << bit;
        (self.bitmap[byte] >> bit) & 1 == 1
    }

    fn list_index(order: usize) -> usize {
        order - MIN_ORDER
    }

    fn push_free(&mut self, order: usize, addr: usize) {
        let idx = Self::list_index(order);
        let ptr = addr as *mut usize;
        unsafe {
            *ptr = self.free_lists[idx] as usize;
        }
        self.free_lists[idx] = ptr;
    }

    fn pop_free(&mut self, order: usize) -> Option<usize> {
        let idx = Self::list_index(order);
        let head = self.free_lists[idx];
        if head.is_null() {
            return None;
        }
        let addr = head as usize;
        unsafe {
            self.free_lists[idx] = (*head) as *mut usize;
        }
        Some(addr)
    }

    fn remove_free(&mut self, order: usize, addr: usize) -> bool {
        let idx = Self::list_index(order);
        let target = addr as *mut usize;

        if self.free_lists[idx] == target {
            unsafe {
                self.free_lists[idx] = (*target) as *mut usize;
            }
            return true;
        }

        let mut current = self.free_lists[idx];
        while !current.is_null() {
            let next = unsafe { (*current) as *mut usize };
            if next == target {
                unsafe {
                    (*current) = *target;
                }
                return true;
            }
            current = next;
        }
        false
    }

    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let effective = layout.size().max(layout.align());
        let order = self.order_for_size(effective);

        if order > MAX_ORDER {
            return ptr::null_mut();
        }

        let mut found_order = None;
        for o in order..=MAX_ORDER {
            if !self.free_lists[Self::list_index(o)].is_null() {
                found_order = Some(o);
                break;
            }
        }

        let found_order = match found_order {
            Some(o) => o,
            None => return ptr::null_mut(),
        };

        let block_addr = self.pop_free(found_order).unwrap();
        let block_offset = block_addr - self.base;

        if found_order < MAX_ORDER {
            let bit_idx = self.bitmap_index(found_order, block_offset);
            self.toggle_bit(bit_idx);
        }

        let mut current_order = found_order;
        while current_order > order {
            current_order -= 1;
            let buddy_addr = block_addr + (1 << current_order);
            self.push_free(current_order, buddy_addr);
            if current_order < MAX_ORDER {
                let buddy_offset = buddy_addr - self.base;
                let bit_idx = self.bitmap_index(current_order, block_offset.min(buddy_offset));
                self.toggle_bit(bit_idx);
            }
        }

        block_addr as *mut u8
    }

    fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        let addr = ptr as usize;
        let effective = layout.size().max(1 << MIN_ORDER);
        let mut order = self.order_for_size(effective);
        let mut block_addr = addr;

        loop {
            if order >= MAX_ORDER {
                self.push_free(order, block_addr);
                return;
            }

            let block_offset = block_addr - self.base;
            let bit_idx = self.bitmap_index(order, block_offset);
            let bit_is_set = self.toggle_bit(bit_idx);

            if bit_is_set {
                self.push_free(order, block_addr);
                return;
            }

            let buddy_addr = self.base + (block_offset ^ (1 << order));
            self.remove_free(order, buddy_addr);

            block_addr = block_addr.min(buddy_addr);
            order += 1;
        }
    }

    // --- Tagged allocation ---

    /// Find or create a tag stats entry. Returns index.
    fn find_or_create_tag(&mut self, t: u32) -> usize {
        for i in 0..self.tag_count {
            if self.tag_stats[i].tag == t {
                return i;
            }
        }
        if self.tag_count < MAX_TAGS {
            let idx = self.tag_count;
            self.tag_stats[idx].tag = t;
            self.tag_count += 1;
            idx
        } else {
            // Overflow: lump into slot 0 (TAG_UNTAGGED)
            0
        }
    }

    fn alloc_tagged(&mut self, layout: Layout, t: u32) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            let effective = layout.size().max(layout.align());
            let actual = 1usize << order_for_size(effective);
            let idx = self.find_or_create_tag(t);
            let s = &mut self.tag_stats[idx];
            s.current_bytes += actual;
            s.alloc_count += 1;
            if s.current_bytes > s.peak_bytes {
                s.peak_bytes = s.current_bytes;
            }
            self.total_used += actual;
        }
        ptr
    }

    fn dealloc_tagged(&mut self, ptr: *mut u8, layout: Layout, t: u32) {
        let effective = layout.size().max(layout.align()).max(1 << MIN_ORDER);
        let actual = 1usize << order_for_size(effective);
        let idx = self.find_or_create_tag(t);
        let s = &mut self.tag_stats[idx];
        s.current_bytes = s.current_bytes.saturating_sub(actual);
        if s.alloc_count > 0 {
            s.alloc_count -= 1;
        }
        self.total_used = self.total_used.saturating_sub(actual);
        self.dealloc(ptr, layout);
    }

    fn snapshot_stats(&self) -> ([TagStats; MAX_TAGS], usize, usize) {
        (self.tag_stats, self.tag_count, self.total_used)
    }
}

// ============================================================
// Global allocator (routes through tagged accounting)
// ============================================================

struct LockedHeap(SpinLock<BuddyAllocator>);

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc_tagged(layout, TAG_UNTAGGED)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc_tagged(ptr, layout, TAG_UNTAGGED);
    }
}

#[global_allocator]
static HEAP: LockedHeap = LockedHeap(SpinLock::new(BuddyAllocator::new()));

pub fn init() {
    unsafe {
        let start = core::ptr::addr_of_mut!(HEAP_SPACE) as *mut u8;
        HEAP.0.lock().init(start, HEAP_SIZE);
    }
    crate::println!("Heap initialized: {} KiB (buddy allocator)", HEAP_SIZE / 1024);
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!(
        "Heap allocation failed: size={}, align={}",
        layout.size(),
        layout.align()
    );
}

// ============================================================
// Public stats API
// ============================================================

/// Return (per-tag stats array, tag count, total used bytes).
pub fn heap_stats() -> ([TagStats; MAX_TAGS], usize, usize) {
    HEAP.0.lock().snapshot_stats()
}

/// Total heap size in bytes.
pub const fn heap_total_size() -> usize {
    HEAP_SIZE
}

// ============================================================
// TaggedAlloc<TAG> — ZST allocator for the Allocator trait
// ============================================================

/// A zero-sized allocator that delegates to the global buddy heap under a
/// specific pool tag. Use with `Vec<T, TaggedAlloc<TAG>>` etc.
pub struct TaggedAlloc<const TAG: u32>;

impl<const TAG: u32> Clone for TaggedAlloc<TAG> {
    fn clone(&self) -> Self { Self }
}
impl<const TAG: u32> Copy for TaggedAlloc<TAG> {}

unsafe impl<const TAG: u32> core::alloc::Allocator for TaggedAlloc<TAG> {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, core::alloc::AllocError> {
        let ptr = HEAP.0.lock().alloc_tagged(layout, TAG);
        if ptr.is_null() {
            return Err(core::alloc::AllocError);
        }
        let effective = layout.size().max(layout.align());
        let actual_size = 1usize << order_for_size(effective);
        Ok(unsafe { NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(ptr, actual_size)) })
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        HEAP.0.lock().dealloc_tagged(ptr.as_ptr(), layout, TAG);
    }
}

// ============================================================
// Convenience type aliases and const instances
// ============================================================

pub type IpcAlloc  = TaggedAlloc<{tag(b"IPC_")}>;
pub type SchdAlloc = TaggedAlloc<{tag(b"SCHD")}>;
pub type PgtbAlloc = TaggedAlloc<{tag(b"PGTB")}>;
pub type InitAlloc = TaggedAlloc<{tag(b"INIT")}>;
pub type TracAlloc = TaggedAlloc<{tag(b"TRAC")}>;

/// Const instances for use with `Vec::new_in()` / `VecDeque::new_in()`.
pub const IPC_ALLOC:  IpcAlloc  = TaggedAlloc;
pub const SCHD_ALLOC: SchdAlloc = TaggedAlloc;
pub const PGTB_ALLOC: PgtbAlloc = TaggedAlloc;
pub const INIT_ALLOC: InitAlloc = TaggedAlloc;
pub const TRAC_ALLOC: TracAlloc = TaggedAlloc;
