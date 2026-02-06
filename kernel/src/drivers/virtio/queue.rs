/// Split virtqueue implementation for VirtIO.

use core::sync::atomic::{fence, Ordering};
use crate::mm::frame;
use crate::mm::address::PAGE_SIZE;
use super::mmio;

pub const QUEUE_SIZE: usize = 16;
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; QUEUE_SIZE],
}

pub struct Virtqueue {
    pub desc: *mut VirtqDesc,
    pub avail: *mut VirtqAvail,
    pub used: *mut VirtqUsed,
    /// Physical addresses for DMA registration
    #[allow(dead_code)]
    pub desc_phys: usize,
    #[allow(dead_code)]
    pub avail_phys: usize,
    #[allow(dead_code)]
    pub used_phys: usize,
    /// Free descriptor tracking: free_head points to first free desc, each free desc's `next` chains
    free_head: u16,
    free_count: u16,
    /// Our shadow of the last used idx we've consumed
    last_used_idx: u16,
}

impl Virtqueue {
    /// Allocate and initialise a virtqueue. Registers it on the device.
    /// Detects v1 (legacy) vs v2 (modern) MMIO and uses the appropriate setup.
    pub fn new(base: usize, queue_idx: u32) -> Self {
        let version = mmio::device_version(base);

        // Select queue
        mmio::write_reg(base, mmio::REG_QUEUE_SEL, queue_idx);

        let max = mmio::read_reg(base, mmio::REG_QUEUE_NUM_MAX);
        assert!(max as usize >= QUEUE_SIZE, "virtqueue max too small");

        // Set queue size
        mmio::write_reg(base, mmio::REG_QUEUE_NUM, QUEUE_SIZE as u32);

        let (desc_phys, avail_phys, used_phys);

        if version == 1 {
            // Legacy (v1): desc, avail, and used must be in a contiguous region.
            // Layout:
            //   offset 0:    descriptor table  (QUEUE_SIZE * 16 = 256 bytes)
            //   offset 256:  available ring     (4 + 2 * QUEUE_SIZE = 36 bytes)
            //   offset 4096: used ring          (aligned to QueueAlign = 4096)
            // Total: 2 pages
            let region = frame::frame_alloc_contiguous(2).expect("virtqueue v1 alloc");
            let region_phys = region.0 << 12;

            // Zero the entire 2-page region
            unsafe {
                core::ptr::write_bytes(region_phys as *mut u8, 0, PAGE_SIZE * 2);
            }

            desc_phys = region_phys;
            avail_phys = region_phys + QUEUE_SIZE * 16; // offset 256
            used_phys = region_phys + PAGE_SIZE;        // offset 4096

            // Tell device: alignment and page frame number
            mmio::write_reg(base, mmio::REG_QUEUE_ALIGN, PAGE_SIZE as u32);
            mmio::write_reg(base, mmio::REG_QUEUE_PFN, (region_phys >> 12) as u32);
        } else {
            // Modern (v2): separate pages for each component
            let desc_frame = frame::frame_alloc().expect("virtqueue desc alloc");
            desc_phys = desc_frame.0 << 12;
            let avail_frame = frame::frame_alloc().expect("virtqueue avail alloc");
            avail_phys = avail_frame.0 << 12;
            let used_frame = frame::frame_alloc().expect("virtqueue used alloc");
            used_phys = used_frame.0 << 12;

            // Tell device about the queue addresses (v2 registers)
            mmio::write_reg(base, mmio::REG_QUEUE_DESC_LOW, desc_phys as u32);
            mmio::write_reg(base, mmio::REG_QUEUE_DESC_HIGH, (desc_phys >> 32) as u32);
            mmio::write_reg(base, mmio::REG_QUEUE_AVAIL_LOW, avail_phys as u32);
            mmio::write_reg(base, mmio::REG_QUEUE_AVAIL_HIGH, (avail_phys >> 32) as u32);
            mmio::write_reg(base, mmio::REG_QUEUE_USED_LOW, used_phys as u32);
            mmio::write_reg(base, mmio::REG_QUEUE_USED_HIGH, (used_phys >> 32) as u32);

            // Mark queue ready (v2 only)
            mmio::write_reg(base, mmio::REG_QUEUE_READY, 1);
        }

        let desc = desc_phys as *mut VirtqDesc;
        let avail = avail_phys as *mut VirtqAvail;
        let used = used_phys as *mut VirtqUsed;

        // Init free list: chain all descriptors
        for i in 0..QUEUE_SIZE as u16 {
            unsafe {
                let d = &mut *desc.add(i as usize);
                d.addr = 0;
                d.len = 0;
                d.flags = 0;
                d.next = if i + 1 < QUEUE_SIZE as u16 { i + 1 } else { 0xFFFF };
            }
        }

        // Zero avail ring
        unsafe {
            let a = &mut *avail;
            a.flags = 0;
            a.idx = 0;
            for slot in a.ring.iter_mut() {
                *slot = 0;
            }
        }

        // Zero used ring
        unsafe {
            let u = &mut *used;
            u.flags = 0;
            u.idx = 0;
        }

        Virtqueue {
            desc,
            avail,
            used,
            desc_phys,
            avail_phys,
            used_phys,
            free_head: 0,
            free_count: QUEUE_SIZE as u16,
            last_used_idx: 0,
        }
    }

    /// Allocate a descriptor from the free list.
    pub fn alloc_desc(&mut self) -> Option<u16> {
        if self.free_count == 0 {
            return None;
        }
        let idx = self.free_head;
        let desc = unsafe { &*self.desc.add(idx as usize) };
        self.free_head = desc.next;
        self.free_count -= 1;
        Some(idx)
    }

    /// Return a descriptor to the free list.
    pub fn free_desc(&mut self, idx: u16) {
        unsafe {
            let d = &mut *self.desc.add(idx as usize);
            d.addr = 0;
            d.len = 0;
            d.flags = 0;
            d.next = self.free_head;
        }
        self.free_head = idx;
        self.free_count += 1;
    }

    /// Free a descriptor chain starting at `head`.
    pub fn free_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let d = unsafe { &*self.desc.add(idx as usize) };
            let has_next = d.flags & VIRTQ_DESC_F_NEXT != 0;
            let next = d.next;
            self.free_desc(idx);
            if has_next {
                idx = next;
            } else {
                break;
            }
        }
    }

    /// Write a descriptor entry.
    pub fn write_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
        unsafe {
            let d = &mut *self.desc.add(idx as usize);
            d.addr = addr;
            d.len = len;
            d.flags = flags;
            d.next = next;
        }
    }

    /// Push a descriptor head index into the available ring.
    pub fn push_avail(&mut self, desc_idx: u16) {
        let avail = unsafe { &mut *self.avail };
        let ring_idx = avail.idx as usize % QUEUE_SIZE;
        avail.ring[ring_idx] = desc_idx;
        fence(Ordering::SeqCst);
        avail.idx = avail.idx.wrapping_add(1);
        fence(Ordering::SeqCst);
    }

    /// Pop a completed element from the used ring, returning (desc head, bytes written).
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::SeqCst);
        let used = unsafe { &*self.used };
        if self.last_used_idx == used.idx {
            return None;
        }
        let ring_idx = self.last_used_idx as usize % QUEUE_SIZE;
        let elem = used.ring[ring_idx];
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some((elem.id as u16, elem.len))
    }

    /// Notify the device about new available buffers.
    pub fn notify(&self, base: usize, queue_idx: u32) {
        fence(Ordering::SeqCst);
        mmio::write_reg(base, mmio::REG_QUEUE_NOTIFY, queue_idx);
    }
}

/// Allocate a buffer from the frame allocator for use as a DMA buffer.
/// Returns (virtual/physical addr, size).
pub fn alloc_dma_buffer(pages: usize) -> usize {
    if pages == 1 {
        let f = frame::frame_alloc().expect("dma buffer alloc");
        f.0 << 12
    } else {
        let f = frame::frame_alloc_contiguous(pages).expect("dma buffer contiguous alloc");
        f.0 << 12
    }
}
