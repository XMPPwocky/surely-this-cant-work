//! Platform abstraction layer.
//!
//! Provides [`PlatformInfo`] — a single source of truth for all
//! hardware-specific constants (RAM range, device addresses, IRQ numbers,
//! timer frequency).  Populated from the FDT at early boot; falls back to
//! QEMU virt defaults if FDT parsing fails.

pub mod fdt;

use crate::sync::SpinLock;

/// Maximum number of VirtIO MMIO slots we track.
pub const MAX_VIRTIO_SLOTS: usize = 8;

/// Maximum supported RAM (1 GiB).  Determines static bitmap size in the
/// frame allocator.
pub const MAX_RAM_BYTES: usize = 1024 * 1024 * 1024;

// ── Types ────────────────────────────────────────────────────────────

/// A physical memory region.
#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    pub base: usize,
    pub size: usize,
}

/// A VirtIO MMIO device discovered from FDT.
#[derive(Clone, Copy, Debug)]
pub struct VirtioMmioSlot {
    pub base: usize,
    pub irq: u32,
}

/// Everything the kernel needs to know about the hardware.
#[derive(Clone, Copy, Debug)]
pub struct PlatformInfo {
    // ── Memory ───────────────────────────────────────────────────────
    pub ram: MemRegion,

    // ── Boot hart ────────────────────────────────────────────────────
    pub boot_hart_id: usize,

    // ── Timer ────────────────────────────────────────────────────────
    /// Ticks per second of the `rdtime` counter.
    pub timebase_frequency: u64,

    // ── PLIC ─────────────────────────────────────────────────────────
    pub plic_base: usize,
    pub plic_size: usize,
    /// S-mode context number for the boot hart.
    pub plic_context: u32,

    // ── Serial console (NS16550) ─────────────────────────────────────
    pub uart_base: usize,
    pub uart_irq: u32,

    // ── CLINT ────────────────────────────────────────────────────────
    pub clint_base: usize,
    pub clint_size: usize,

    // ── VirtIO MMIO ──────────────────────────────────────────────────
    pub virtio_mmio: [VirtioMmioSlot; MAX_VIRTIO_SLOTS],
    pub virtio_mmio_count: usize,

    // ── Bootargs ─────────────────────────────────────────────────────
    /// Pointer to the bootargs string in the FDT blob (persists in SBI memory).
    bootargs_ptr: usize,
    bootargs_len: usize,
}

// ── QEMU virt defaults (compile-time fallback) ───────────────────────

impl PlatformInfo {
    /// QEMU `virt` machine defaults — used if FDT is absent or unparseable.
    const QEMU_VIRT: Self = PlatformInfo {
        ram: MemRegion { base: 0x8000_0000, size: 128 * 1024 * 1024 },
        boot_hart_id: 0,
        timebase_frequency: 10_000_000, // 10 MHz
        plic_base: 0x0C00_0000,
        plic_size: 0x0400_0000,
        plic_context: 1, // S-mode, hart 0
        uart_base: 0x1000_0000,
        uart_irq: 10,
        clint_base: 0x0200_0000,
        clint_size: 0x0001_0000,
        virtio_mmio: [VirtioMmioSlot { base: 0, irq: 0 }; MAX_VIRTIO_SLOTS],
        virtio_mmio_count: 0,
        bootargs_ptr: 0,
        bootargs_len: 0,
    };

    pub fn ram_end(&self) -> usize {
        self.ram.base + self.ram.size
    }
}

// ── Global ───────────────────────────────────────────────────────────

static PLATFORM: SpinLock<PlatformInfo> = SpinLock::new(PlatformInfo::QEMU_VIRT);

/// Initialise platform info from a Flattened Device Tree blob.
///
/// Called once, early in `kmain`, before interrupts and before any driver
/// init.  If `dtb_ptr` is 0 or parsing fails, the QEMU virt defaults are
/// kept and a warning is printed.
pub fn init_from_fdt(hart_id: usize, dtb_ptr: usize) {
    if dtb_ptr == 0 {
        crate::println!("[platform] No DTB pointer — using QEMU virt defaults");
        PLATFORM.lock().boot_hart_id = hart_id;
        return;
    }

    // The DTB sits in the SBI region which is identity-mapped at boot.
    // Build a slice from the raw pointer — we trust firmware to give us
    // a valid address.
    let header_slice = unsafe { core::slice::from_raw_parts(dtb_ptr as *const u8, 8) };

    // Quick sanity: check FDT magic before reading totalsize.
    let magic = u32::from_be_bytes([header_slice[0], header_slice[1], header_slice[2], header_slice[3]]);
    if magic != fdt::FDT_MAGIC {
        crate::println!("[platform] Bad FDT magic {:#010x} at {:#x} — using defaults", magic, dtb_ptr);
        PLATFORM.lock().boot_hart_id = hart_id;
        return;
    }

    let total_size = u32::from_be_bytes([header_slice[4], header_slice[5], header_slice[6], header_slice[7]]) as usize;
    if total_size > 64 * 1024 {
        crate::println!("[platform] FDT too large ({} bytes) — using defaults", total_size);
        PLATFORM.lock().boot_hart_id = hart_id;
        return;
    }

    let dtb = unsafe { core::slice::from_raw_parts(dtb_ptr as *const u8, total_size) };

    match fdt::parse_platform_info(dtb, hart_id) {
        Some(info) => {
            crate::println!("[platform] FDT parsed: RAM {:#x}..{:#x} ({} MiB)",
                info.ram.base, info.ram_end(), info.ram.size / 1024 / 1024);
            crate::println!("[platform]   UART {:#x} IRQ {}, PLIC {:#x}, CLINT {:#x}",
                info.uart_base, info.uart_irq, info.plic_base, info.clint_base);
            crate::println!("[platform]   timebase {} Hz, {} VirtIO MMIO device(s)",
                info.timebase_frequency, info.virtio_mmio_count);
            if info.ram.size > MAX_RAM_BYTES {
                crate::println!("[platform]   WARNING: RAM {} MiB exceeds max {} MiB — excess unused",
                    info.ram.size / 1024 / 1024, MAX_RAM_BYTES / 1024 / 1024);
            }
            *PLATFORM.lock() = info;
        }
        None => {
            crate::println!("[platform] FDT parse failed — using QEMU virt defaults");
            PLATFORM.lock().boot_hart_id = hart_id;
        }
    }
}

// ── Accessors ────────────────────────────────────────────────────────

/// Return a copy of the full platform info.
pub fn info() -> PlatformInfo {
    *PLATFORM.lock()
}

pub fn ram_base() -> usize {
    PLATFORM.lock().ram.base
}

pub fn ram_end() -> usize {
    let p = PLATFORM.lock();
    let end = p.ram.base + p.ram.size;
    // Clamp to MAX_RAM_BYTES
    let max_end = p.ram.base + MAX_RAM_BYTES;
    if end > max_end { max_end } else { end }
}

// Part of the platform HAL public API — not yet used by kernel code, but
// available for future drivers or board-support packages.
#[allow(dead_code)]
pub fn ram_size() -> usize {
    ram_end() - ram_base()
}

pub fn uart_base() -> usize {
    PLATFORM.lock().uart_base
}

pub fn uart_irq() -> u32 {
    PLATFORM.lock().uart_irq
}

pub fn plic_base() -> usize {
    PLATFORM.lock().plic_base
}

// Part of the platform HAL public API — not yet used by kernel code, but
// available for future drivers or board-support packages.
#[allow(dead_code)]
pub fn plic_size() -> usize {
    PLATFORM.lock().plic_size
}

pub fn plic_context() -> u32 {
    PLATFORM.lock().plic_context
}

// Part of the platform HAL public API — not yet used by kernel code, but
// available for future drivers (e.g. SMP IPI via CLINT).
#[allow(dead_code)]
pub fn clint_base() -> usize {
    PLATFORM.lock().clint_base
}

// Part of the platform HAL public API — not yet used by kernel code, but
// available for future drivers (e.g. SMP IPI via CLINT).
#[allow(dead_code)]
pub fn clint_size() -> usize {
    PLATFORM.lock().clint_size
}

pub fn timebase_frequency() -> u64 {
    PLATFORM.lock().timebase_frequency
}

/// Return the list of VirtIO MMIO slots discovered from FDT.
/// Each entry is (base_address, irq_number).
pub fn virtio_mmio_slots() -> ([VirtioMmioSlot; MAX_VIRTIO_SLOTS], usize) {
    let p = PLATFORM.lock();
    (p.virtio_mmio, p.virtio_mmio_count)
}

/// Return the bootargs string from the FDT `/chosen` node.
/// Returns an empty slice if no bootargs were provided.
pub fn bootargs() -> &'static [u8] {
    let p = PLATFORM.lock();
    if p.bootargs_ptr == 0 || p.bootargs_len == 0 {
        return b"";
    }
    // SAFETY: The FDT blob persists in SBI memory for the kernel's lifetime.
    // The pointer and length were validated during FDT parsing.
    unsafe { core::slice::from_raw_parts(p.bootargs_ptr as *const u8, p.bootargs_len) }
}
