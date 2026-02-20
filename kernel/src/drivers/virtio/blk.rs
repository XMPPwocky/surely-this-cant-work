//! VirtIO Block driver.
//!
//! Implements a VirtIO blk device driver for virtio-blk-device.
//! Supports up to MAX_BLK_DEVICES block devices. Each device uses a single
//! requestq (queue 0) with 3-descriptor chains: outhdr → data → status.

use core::sync::atomic::{AtomicUsize, Ordering};
use super::mmio;
use super::queue::{Virtqueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, alloc_dma_buffer};

// ── VirtIO block constants (from virtio_blk.h) ──────────────────

const VIRTIO_BLK_T_IN: u32 = 0;   // read
const VIRTIO_BLK_T_OUT: u32 = 1;  // write
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_OK: u8 = 0;

const VIRTIO_BLK_F_RO: u32 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

/// Sector size in bytes.
pub const SECTOR_SIZE: usize = 512;

/// Maximum number of sectors per single request.
/// Limited by our data buffer allocation (8 pages = 32 KB = 64 sectors).
const MAX_SECTORS_PER_REQ: u32 = 64;

/// Maximum block devices.
const MAX_BLK_DEVICES: usize = 4;

// ── outhdr layout (16 bytes, device-readable) ────────────────────

/// Size of struct virtio_blk_outhdr: { type: u32, ioprio: u32, sector: u64 }
const OUTHDR_SIZE: usize = 16;

// ── Per-device state ─────────────────────────────────────────────

struct BlkDevice {
    base: usize,
    irq: u32,
    requestq: Virtqueue,
    capacity_sectors: u64,
    read_only: bool,
    has_flush: bool,
    /// DMA buffer for the outhdr (16 bytes, fits in 1 page).
    outhdr_buf: usize,
    /// DMA buffer for the status byte (1 byte, shares a page with outhdr).
    status_buf: usize,
    /// DMA buffer for data transfer (8 pages = 32 KB).
    data_buf: usize,
}

static mut DEVICES: [Option<BlkDevice>; MAX_BLK_DEVICES] = [const { None }; MAX_BLK_DEVICES];
static DEVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Per-device wake PID for IRQ handling.
static BLK_WAKE_PIDS: [AtomicUsize; MAX_BLK_DEVICES] = [const { AtomicUsize::new(0) }; MAX_BLK_DEVICES];

/// Initialize all VirtIO block devices.
/// Returns the number of devices found.
pub fn init() -> usize {
    let result = mmio::probe_all(mmio::DEVICE_ID_BLK);
    let mut count = 0;

    for i in 0..result.count {
        if count >= MAX_BLK_DEVICES {
            crate::println!("[blk] warning: more than {} block devices, ignoring extras", MAX_BLK_DEVICES);
            break;
        }
        let (base, slot) = result.entries[i];
        if let Some(dev) = init_one(base, slot) {
            crate::println!(
                "[blk] blk{}: {} sectors ({}), {}{}",
                count,
                dev.capacity_sectors,
                format_size(dev.capacity_sectors * SECTOR_SIZE as u64),
                if dev.read_only { "RO" } else { "RW" },
                if dev.has_flush { " +flush" } else { "" },
            );
            unsafe {
                core::ptr::addr_of_mut!(DEVICES[count]).write(Some(dev));
            }
            count += 1;
        }
    }

    DEVICE_COUNT.store(count, Ordering::Relaxed);
    count
}

/// Format a byte count as a human-readable string (e.g., "16 MiB").
fn format_size(bytes: u64) -> &'static str {
    if bytes >= 1024 * 1024 * 1024 {
        "GiB+"
    } else if bytes >= 16 * 1024 * 1024 {
        "16 MiB"
    } else if bytes >= 4 * 1024 * 1024 {
        "4 MiB"
    } else if bytes >= 1024 * 1024 {
        "MiB+"
    } else {
        "< 1 MiB"
    }
}

/// Initialize a single block device.
fn init_one(base: usize, slot: usize) -> Option<BlkDevice> {
    crate::println!("[blk] Found VirtIO blk at {:#x} (slot {})", base, slot);

    // Custom handshake: we need to negotiate F_RO and F_FLUSH features.
    let (read_only, has_flush) = blk_init_device(base)?;

    // Set up requestq (queue 0)
    let requestq = Virtqueue::new(base, 0);

    // Set DRIVER_OK
    mmio::driver_ok(base);

    // Read capacity from config space (offset 0, u64 LE = sectors)
    let cap_lo = mmio::read_config_u32_le(base, 0) as u64;
    let cap_hi = mmio::read_config_u32_le(base, 4) as u64;
    let capacity_sectors = cap_lo | (cap_hi << 32);

    // Compute IRQ: QEMU virt machine uses IRQ = 1 + slot
    let irq = 1 + slot as u32;

    // Allocate DMA buffers
    // outhdr (16 bytes) + status (1 byte) share a single page
    let outhdr_page = alloc_dma_buffer(1);
    unsafe {
        core::ptr::write_bytes(outhdr_page as *mut u8, 0, 4096);
    }
    let outhdr_buf = outhdr_page;
    let status_buf = outhdr_page + OUTHDR_SIZE; // status byte right after outhdr

    // Data buffer: 8 pages (32 KB) for up to 64 sectors
    let data_buf = alloc_dma_buffer(8);
    unsafe {
        core::ptr::write_bytes(data_buf as *mut u8, 0, 8 * 4096);
    }

    // Enable IRQ in PLIC
    crate::drivers::plic::enable_irq(irq);

    Some(BlkDevice {
        base,
        irq,
        requestq,
        capacity_sectors,
        read_only,
        has_flush,
        outhdr_buf,
        status_buf,
        data_buf,
    })
}

/// Perform the VirtIO device handshake, negotiating F_RO and F_FLUSH.
/// Returns Some((read_only, has_flush)) on success.
fn blk_init_device(base: usize) -> Option<(bool, bool)> {
    // 1. Reset
    mmio::write_reg(base, mmio::REG_STATUS, 0);

    // 2. ACKNOWLEDGE
    mmio::write_reg(base, mmio::REG_STATUS, mmio::STATUS_ACKNOWLEDGE);

    // 3. DRIVER
    mmio::write_reg(
        base,
        mmio::REG_STATUS,
        mmio::STATUS_ACKNOWLEDGE | mmio::STATUS_DRIVER,
    );

    let version = mmio::device_version(base);

    if version == 1 {
        // Legacy: set guest page size
        mmio::write_reg(base, mmio::REG_GUEST_PAGE_SIZE, 4096);

        // Read device features
        mmio::write_reg(base, mmio::REG_DEVICE_FEATURES_SEL, 0);
        let dev_features = mmio::read_reg(base, mmio::REG_DEVICE_FEATURES);

        let read_only = dev_features & VIRTIO_BLK_F_RO != 0;
        let has_flush = dev_features & VIRTIO_BLK_F_FLUSH != 0;

        // Accept F_RO (if set) and F_FLUSH (if available)
        let accepted = dev_features & (VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES_SEL, 0);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES, accepted);

        // No FEATURES_OK step for legacy
        Some((read_only, has_flush))
    } else {
        // Modern v2 handshake
        mmio::write_reg(base, mmio::REG_DEVICE_FEATURES_SEL, 0);
        let dev_features = mmio::read_reg(base, mmio::REG_DEVICE_FEATURES);

        let read_only = dev_features & VIRTIO_BLK_F_RO != 0;
        let has_flush = dev_features & VIRTIO_BLK_F_FLUSH != 0;

        let accepted = dev_features & (VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES_SEL, 0);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES, accepted);

        mmio::write_reg(base, mmio::REG_DEVICE_FEATURES_SEL, 1);
        let _ = mmio::read_reg(base, mmio::REG_DEVICE_FEATURES);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES_SEL, 1);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES, 0);

        // FEATURES_OK
        mmio::write_reg(
            base,
            mmio::REG_STATUS,
            mmio::STATUS_ACKNOWLEDGE | mmio::STATUS_DRIVER | mmio::STATUS_FEATURES_OK,
        );

        let status = mmio::read_reg(base, mmio::REG_STATUS);
        if status & mmio::STATUS_FEATURES_OK == 0 {
            return None;
        }

        Some((read_only, has_flush))
    }
}

/// Return the number of initialized block devices.
pub fn device_count() -> usize {
    DEVICE_COUNT.load(Ordering::Relaxed)
}

/// Return the capacity in sectors for device `idx`.
pub fn capacity(idx: usize) -> u64 {
    unsafe {
        match (*core::ptr::addr_of!(DEVICES[idx])).as_ref() {
            Some(dev) => dev.capacity_sectors,
            None => 0,
        }
    }
}

/// Return whether device `idx` is read-only.
pub fn is_read_only(idx: usize) -> bool {
    unsafe {
        match (*core::ptr::addr_of!(DEVICES[idx])).as_ref() {
            Some(dev) => dev.read_only,
            None => false,
        }
    }
}

/// Return the IRQ number for device `idx`.
pub fn irq_number(idx: usize) -> Option<u32> {
    unsafe { (*core::ptr::addr_of!(DEVICES[idx])).as_ref().map(|d| d.irq) }
}

/// Set the PID to wake when block device `idx` fires an IRQ.
pub fn set_wake_pid(idx: usize, pid: usize) {
    if idx < MAX_BLK_DEVICES {
        BLK_WAKE_PIDS[idx].store(pid, Ordering::Relaxed);
    }
}

/// Read `count` sectors starting at `sector` into `dst`.
/// `dst` must be large enough for `count * 512` bytes.
/// Returns true on success.
pub fn read_sectors(idx: usize, sector: u64, count: u32, dst: *mut u8) -> bool {
    if count == 0 || count > MAX_SECTORS_PER_REQ {
        return false;
    }
    let dev = unsafe {
        match (*core::ptr::addr_of_mut!(DEVICES[idx])).as_mut() {
            Some(d) => d,
            None => return false,
        }
    };

    if sector + count as u64 > dev.capacity_sectors {
        return false;
    }

    let data_len = count as usize * SECTOR_SIZE;

    // Write outhdr
    write_outhdr(dev.outhdr_buf, VIRTIO_BLK_T_IN, sector);

    // Clear status
    unsafe { (dev.status_buf as *mut u8).write_volatile(0xFF); }

    // Build 3-descriptor chain: outhdr → data(device-writable) → status(device-writable)
    let d0 = dev.requestq.alloc_desc().expect("blk: no desc for outhdr");
    let d1 = dev.requestq.alloc_desc().expect("blk: no desc for data");
    let d2 = dev.requestq.alloc_desc().expect("blk: no desc for status");

    dev.requestq.write_desc(d0, dev.outhdr_buf as u64, OUTHDR_SIZE as u32, VIRTQ_DESC_F_NEXT, d1);
    dev.requestq.write_desc(d1, dev.data_buf as u64, data_len as u32, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, d2);
    dev.requestq.write_desc(d2, dev.status_buf as u64, 1, VIRTQ_DESC_F_WRITE, 0);

    dev.requestq.push_avail(d0);
    dev.requestq.notify(dev.base, 0);

    // Poll for completion
    loop {
        if let Some((head, _len)) = dev.requestq.pop_used() {
            dev.requestq.free_chain(head);
            break;
        }
        unsafe { core::arch::asm!("wfi"); }
    }

    let status = unsafe { (dev.status_buf as *const u8).read_volatile() };
    if status != VIRTIO_BLK_S_OK {
        return false;
    }

    // Copy data from DMA buffer to caller's buffer
    unsafe {
        core::ptr::copy_nonoverlapping(dev.data_buf as *const u8, dst, data_len);
    }

    true
}

/// Write `count` sectors starting at `sector` from `src`.
/// `src` must contain `count * 512` bytes.
/// Returns true on success.
pub fn write_sectors(idx: usize, sector: u64, count: u32, src: *const u8) -> bool {
    if count == 0 || count > MAX_SECTORS_PER_REQ {
        return false;
    }
    let dev = unsafe {
        match (*core::ptr::addr_of_mut!(DEVICES[idx])).as_mut() {
            Some(d) => d,
            None => return false,
        }
    };

    if dev.read_only {
        return false;
    }

    if sector + count as u64 > dev.capacity_sectors {
        return false;
    }

    let data_len = count as usize * SECTOR_SIZE;

    // Copy data from caller's buffer to DMA buffer
    unsafe {
        core::ptr::copy_nonoverlapping(src, dev.data_buf as *mut u8, data_len);
    }

    // Write outhdr
    write_outhdr(dev.outhdr_buf, VIRTIO_BLK_T_OUT, sector);

    // Clear status
    unsafe { (dev.status_buf as *mut u8).write_volatile(0xFF); }

    // Build 3-descriptor chain: outhdr → data(device-readable) → status(device-writable)
    let d0 = dev.requestq.alloc_desc().expect("blk: no desc for outhdr");
    let d1 = dev.requestq.alloc_desc().expect("blk: no desc for data");
    let d2 = dev.requestq.alloc_desc().expect("blk: no desc for status");

    dev.requestq.write_desc(d0, dev.outhdr_buf as u64, OUTHDR_SIZE as u32, VIRTQ_DESC_F_NEXT, d1);
    dev.requestq.write_desc(d1, dev.data_buf as u64, data_len as u32, VIRTQ_DESC_F_NEXT, d2);
    dev.requestq.write_desc(d2, dev.status_buf as u64, 1, VIRTQ_DESC_F_WRITE, 0);

    dev.requestq.push_avail(d0);
    dev.requestq.notify(dev.base, 0);

    // Poll for completion
    loop {
        if let Some((head, _len)) = dev.requestq.pop_used() {
            dev.requestq.free_chain(head);
            break;
        }
        unsafe { core::arch::asm!("wfi"); }
    }

    let status = unsafe { (dev.status_buf as *const u8).read_volatile() };
    status == VIRTIO_BLK_S_OK
}

/// Flush cached writes to stable storage.
/// Returns true on success, false if device doesn't support flush or on error.
pub fn flush(idx: usize) -> bool {
    let dev = unsafe {
        match (*core::ptr::addr_of_mut!(DEVICES[idx])).as_mut() {
            Some(d) => d,
            None => return false,
        }
    };

    if !dev.has_flush {
        // No flush support — treat as success (writes are synchronous)
        return true;
    }

    // Write outhdr (sector ignored for flush)
    write_outhdr(dev.outhdr_buf, VIRTIO_BLK_T_FLUSH, 0);

    // Clear status
    unsafe { (dev.status_buf as *mut u8).write_volatile(0xFF); }

    // Build 2-descriptor chain: outhdr → status (no data)
    let d0 = dev.requestq.alloc_desc().expect("blk: no desc for flush outhdr");
    let d1 = dev.requestq.alloc_desc().expect("blk: no desc for flush status");

    dev.requestq.write_desc(d0, dev.outhdr_buf as u64, OUTHDR_SIZE as u32, VIRTQ_DESC_F_NEXT, d1);
    dev.requestq.write_desc(d1, dev.status_buf as u64, 1, VIRTQ_DESC_F_WRITE, 0);

    dev.requestq.push_avail(d0);
    dev.requestq.notify(dev.base, 0);

    // Poll for completion
    loop {
        if let Some((head, _len)) = dev.requestq.pop_used() {
            dev.requestq.free_chain(head);
            break;
        }
        unsafe { core::arch::asm!("wfi"); }
    }

    let status = unsafe { (dev.status_buf as *const u8).read_volatile() };
    status == VIRTIO_BLK_S_OK
}

/// Handle a block device IRQ for the given MMIO slot.
/// Called from the trap handler.
pub fn handle_irq(slot: usize) {
    // Find which device index corresponds to this slot
    let count = DEVICE_COUNT.load(Ordering::Relaxed);
    for i in 0..count {
        let dev = unsafe {
            match (*core::ptr::addr_of_mut!(DEVICES[i])).as_mut() {
                Some(d) => d,
                None => continue,
            }
        };

        let expected_irq = 1 + ((dev.base - 0x1000_1000) / 0x1000) as u32;
        let incoming_irq = 1 + slot as u32;
        if expected_irq != incoming_irq {
            continue;
        }

        // Acknowledge interrupt
        let intr_status = mmio::read_reg(dev.base, mmio::REG_INTERRUPT_STATUS);
        mmio::write_reg(dev.base, mmio::REG_INTERRUPT_ACK, intr_status);

        // Wake the registered service process
        let pid = BLK_WAKE_PIDS[i].load(Ordering::Relaxed);
        if pid != 0 {
            crate::task::wake_process(pid);
        }

        return;
    }
}

// ── Helpers ──────────────────────────────────────────────────────

/// Write the outhdr structure to the DMA buffer.
fn write_outhdr(buf: usize, req_type: u32, sector: u64) {
    unsafe {
        // type: u32 at offset 0
        (buf as *mut u32).write_volatile(req_type);
        // ioprio: u32 at offset 4 (always 0)
        ((buf + 4) as *mut u32).write_volatile(0);
        // sector: u64 at offset 8
        ((buf + 8) as *mut u64).write_volatile(sector);
    }
}
