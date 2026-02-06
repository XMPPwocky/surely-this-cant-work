use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use crate::sync::SpinLock;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB
const MIN_ORDER: usize = 5;   // 32 bytes
const MAX_ORDER: usize = 20;  // 1 MiB
const NUM_ORDERS: usize = MAX_ORDER - MIN_ORDER + 1; // 16

static mut HEAP_SPACE: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

struct BuddyAllocator {
    base: usize,
    free_lists: [*mut usize; NUM_ORDERS],  // free_lists[i] = head of free list for order (i + MIN_ORDER)
    bitmap: [u8; 4096],
}

unsafe impl Send for BuddyAllocator {}

impl BuddyAllocator {
    const fn new() -> Self {
        BuddyAllocator {
            base: 0,
            free_lists: [ptr::null_mut(); NUM_ORDERS],
            bitmap: [0u8; 4096],
        }
    }

    unsafe fn init(&mut self, start: *mut u8, size: usize) {
        assert!(size == HEAP_SIZE);
        self.base = start as usize;
        // The entire heap is one free block at MAX_ORDER
        let idx = MAX_ORDER - MIN_ORDER;  // index 15
        self.free_lists[idx] = start as *mut usize;
        *(start as *mut usize) = 0; // null next pointer
    }

    fn order_for_size(&self, size: usize) -> usize {
        let size = size.max(1 << MIN_ORDER);
        let order = (usize::BITS - (size - 1).leading_zeros()) as usize;
        order.max(MIN_ORDER).min(MAX_ORDER)
    }

    fn bitmap_index(&self, order: usize, block_offset: usize) -> usize {
        // offset into bitmap for this order level
        let level_offset = (1 << (MAX_ORDER - MIN_ORDER)) - (1 << (MAX_ORDER - order));
        // index within this level
        let index_within = block_offset >> (order + 1);
        level_offset + index_within
    }

    fn toggle_bit(&mut self, bit_idx: usize) -> bool {
        let byte = bit_idx / 8;
        let bit = bit_idx % 8;
        self.bitmap[byte] ^= 1 << bit;
        // Return the NEW value of the bit (after toggle)
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

        // Check if head
        if self.free_lists[idx] == target {
            unsafe {
                self.free_lists[idx] = (*target) as *mut usize;
            }
            return true;
        }

        // Walk the list
        let mut current = self.free_lists[idx];
        while !current.is_null() {
            let next = unsafe { (*current) as *mut usize };
            if next == target {
                unsafe {
                    (*current) = *target; // skip over target
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

        // Find the smallest order with a free block
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

        // Pop a block from found_order
        let block_addr = self.pop_free(found_order).unwrap();
        let block_offset = block_addr - self.base;

        // Toggle buddy bit at found_order
        if found_order < MAX_ORDER {
            let bit_idx = self.bitmap_index(found_order, block_offset);
            self.toggle_bit(bit_idx);
        }

        // Split down to the requested order
        let mut current_order = found_order;
        while current_order > order {
            current_order -= 1;
            // The "upper half" buddy goes on the free list at current_order
            let buddy_addr = block_addr + (1 << current_order);
            self.push_free(current_order, buddy_addr);
            // Toggle buddy bit at current_order (we're splitting, so one half is allocated, one is free)
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
                // Can't merge beyond max order -- just add to free list
                self.push_free(order, block_addr);
                return;
            }

            let block_offset = block_addr - self.base;
            let bit_idx = self.bitmap_index(order, block_offset);
            let bit_is_set = self.toggle_bit(bit_idx);

            if bit_is_set {
                // Buddy is NOT free -- just add this block to free list
                self.push_free(order, block_addr);
                return;
            }

            // Buddy IS free -- remove it from free list and merge
            let buddy_addr = self.base + (block_offset ^ (1 << order));
            self.remove_free(order, buddy_addr);

            // Merged block starts at the lower address
            block_addr = block_addr.min(buddy_addr);
            order += 1;
        }
    }
}

struct LockedHeap(SpinLock<BuddyAllocator>);

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(ptr, layout);
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
