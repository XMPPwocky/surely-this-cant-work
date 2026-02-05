use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use crate::sync::SpinLock;

const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

static mut HEAP_SPACE: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

/// Free block header in the linked list.
struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}

const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>();

struct FreeListAllocator {
    head: *mut FreeBlock,
}

unsafe impl Send for FreeListAllocator {}

impl FreeListAllocator {
    const fn new() -> Self {
        FreeListAllocator {
            head: ptr::null_mut(),
        }
    }

    unsafe fn init(&mut self, start: *mut u8, size: usize) {
        let block = start as *mut FreeBlock;
        (*block).size = size;
        (*block).next = ptr::null_mut();
        self.head = block;
    }

    fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(MIN_BLOCK_SIZE);
        let align = layout.align();

        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head;

        while !current.is_null() {
            let block_addr = current as usize;
            let block_size = unsafe { (*current).size };
            let block_end = block_addr + block_size;

            // Align the start within this block
            let aligned_start = (block_addr + align - 1) & !(align - 1);
            let alloc_end = aligned_start + size;

            if alloc_end <= block_end {
                let next = unsafe { (*current).next };
                let leading = aligned_start - block_addr;
                let trailing = block_end - alloc_end;

                // Remove this block from the list
                if prev.is_null() {
                    self.head = next;
                } else {
                    unsafe { (*prev).next = next; }
                }

                // Put back trailing space as a free block
                if trailing >= MIN_BLOCK_SIZE {
                    let trail = alloc_end as *mut FreeBlock;
                    unsafe {
                        (*trail).size = trailing;
                        (*trail).next = self.head;
                    }
                    self.head = trail;
                }

                // Put back leading space as a free block
                if leading >= MIN_BLOCK_SIZE {
                    let lead = block_addr as *mut FreeBlock;
                    unsafe {
                        (*lead).size = leading;
                        (*lead).next = self.head;
                    }
                    self.head = lead;
                }

                return aligned_start as *mut u8;
            }

            prev = current;
            current = unsafe { (*current).next };
        }

        ptr::null_mut()
    }

    fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(MIN_BLOCK_SIZE);
        let free_addr = ptr as usize;

        // Insert in address-sorted order for coalescing
        let free_block = free_addr as *mut FreeBlock;
        unsafe {
            (*free_block).size = size;
            (*free_block).next = ptr::null_mut();
        }

        if self.head.is_null() || free_addr < self.head as usize {
            unsafe { (*free_block).next = self.head; }
            self.head = free_block;
            self.coalesce_from(free_block);
            return;
        }

        // Find insertion point
        let mut current = self.head;
        loop {
            let next = unsafe { (*current).next };
            if next.is_null() || free_addr < next as usize {
                unsafe {
                    (*free_block).next = next;
                    (*current).next = free_block;
                }
                self.coalesce_from(free_block);
                self.coalesce_from(current);
                return;
            }
            current = next;
        }
    }

    /// Try to merge `block` with its successor if they are adjacent.
    fn coalesce_from(&self, block: *mut FreeBlock) {
        if block.is_null() {
            return;
        }
        unsafe {
            let next = (*block).next;
            if !next.is_null() {
                let block_end = (block as usize) + (*block).size;
                if block_end == next as usize {
                    (*block).size += (*next).size;
                    (*block).next = (*next).next;
                }
            }
        }
    }
}

struct LockedHeap(SpinLock<FreeListAllocator>);

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(ptr, layout);
    }
}

#[global_allocator]
static HEAP: LockedHeap = LockedHeap(SpinLock::new(FreeListAllocator::new()));

pub fn init() {
    unsafe {
        let start = core::ptr::addr_of_mut!(HEAP_SPACE) as *mut u8;
        HEAP.0.lock().init(start, HEAP_SIZE);
    }
    crate::println!("Heap initialized: {} KiB", HEAP_SIZE / 1024);
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!(
        "Heap allocation failed: size={}, align={}",
        layout.size(),
        layout.align()
    );
}
