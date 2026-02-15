use crate::mm::address::{PhysPageNum, PAGE_SIZE};
use crate::sync::SpinLock;

const RAM_BASE: usize = 0x8000_0000;
const RAM_END: usize = 0x8800_0000;
const TOTAL_FRAMES: usize = (RAM_END - RAM_BASE) / PAGE_SIZE; // 32768
const BITMAP_LEN: usize = TOTAL_FRAMES.div_ceil(64); // 512

struct FrameAllocator {
    bitmap: [u64; BITMAP_LEN],
    /// First frame index available for allocation (everything below is reserved)
    first_free: usize,
    allocated: usize,
}

impl FrameAllocator {
    const fn new() -> Self {
        FrameAllocator {
            bitmap: [0u64; BITMAP_LEN],
            first_free: 0,
            allocated: 0,
        }
    }

    fn init(&mut self, kernel_end_addr: usize) {
        let first_free_addr = (kernel_end_addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let first_free_frame = (first_free_addr - RAM_BASE) / PAGE_SIZE;
        self.first_free = first_free_frame;

        // Mark all frames below first_free as used (SBI + kernel image + stack)
        for i in 0..first_free_frame {
            self.set_used(i);
        }
    }

    fn set_used(&mut self, frame_idx: usize) {
        assert!(frame_idx < TOTAL_FRAMES, "set_used: frame_idx {} out of range", frame_idx);
        let word = frame_idx / 64;
        let bit = frame_idx % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn set_free(&mut self, frame_idx: usize) {
        assert!(frame_idx < TOTAL_FRAMES, "set_free: frame_idx {} out of range", frame_idx);
        let word = frame_idx / 64;
        let bit = frame_idx % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }

    fn is_used(&self, frame_idx: usize) -> bool {
        assert!(frame_idx < TOTAL_FRAMES, "is_used: frame_idx {} out of range", frame_idx);
        let word = frame_idx / 64;
        let bit = frame_idx % 64;
        (self.bitmap[word] >> bit) & 1 == 1
    }

    fn alloc(&mut self) -> Option<PhysPageNum> {
        for i in self.first_free..TOTAL_FRAMES {
            if !self.is_used(i) {
                self.set_used(i);
                self.allocated += 1;
                let ppn = PhysPageNum((RAM_BASE / PAGE_SIZE) + i);
                ppn.zero_page();
                return Some(ppn);
            }
        }
        None
    }

    fn dealloc(&mut self, ppn: PhysPageNum) {
        let frame_idx = ppn.0 - (RAM_BASE / PAGE_SIZE);
        assert!(frame_idx < TOTAL_FRAMES, "frame_dealloc: ppn out of range");
        assert!(self.is_used(frame_idx), "frame_dealloc: double free");
        self.set_free(frame_idx);
        self.allocated -= 1;
    }

    fn alloc_contiguous(&mut self, count: usize) -> Option<PhysPageNum> {
        if count == 0 {
            return None;
        }
        let mut run_start = self.first_free;
        let mut run_len = 0usize;
        for i in self.first_free..TOTAL_FRAMES {
            if self.is_used(i) {
                run_start = i + 1;
                run_len = 0;
            } else {
                run_len += 1;
                if run_len == count {
                    for f in run_start..run_start + count {
                        self.set_used(f);
                    }
                    self.allocated += count;
                    let ppn = PhysPageNum((RAM_BASE / PAGE_SIZE) + run_start);
                    for f in 0..count {
                        PhysPageNum(ppn.0 + f).zero_page();
                    }
                    return Some(ppn);
                }
            }
        }
        None
    }
}

static FRAME_ALLOCATOR: SpinLock<FrameAllocator> = SpinLock::new(FrameAllocator::new());

pub fn init() {
    extern "C" {
        fn _stack_top();
    }
    let kernel_end = _stack_top as *const () as usize;
    FRAME_ALLOCATOR.lock().init(kernel_end);
    let alloc = FRAME_ALLOCATOR.lock();
    crate::println!(
        "Frame allocator: {} frames reserved, {} total ({} MiB free)",
        alloc.first_free,
        TOTAL_FRAMES,
        (TOTAL_FRAMES - alloc.first_free) * PAGE_SIZE / 1024 / 1024
    );
}

pub fn frame_alloc() -> Option<PhysPageNum> {
    FRAME_ALLOCATOR.lock().alloc()
}

pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.lock().dealloc(ppn);
}

pub fn frame_alloc_contiguous(count: usize) -> Option<PhysPageNum> {
    FRAME_ALLOCATOR.lock().alloc_contiguous(count)
}

pub fn frames_allocated() -> usize {
    FRAME_ALLOCATOR.lock().allocated
}

pub const fn frames_total() -> usize {
    TOTAL_FRAMES
}
