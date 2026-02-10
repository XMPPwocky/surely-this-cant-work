//! VirtIO MMIO transport layer for QEMU virt machine.
//!
//! 8 VirtIO MMIO slots at 0x1000_1000 .. 0x1000_8000, each 0x1000 apart.
//! QEMU virt machine exposes legacy (v1) devices, so we support both v1 and v2.

const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
const VIRTIO_MMIO_STRIDE: usize = 0x1000;
const VIRTIO_MMIO_SLOTS: usize = 8;

// Register offsets (common to both v1 and v2)
pub const REG_MAGIC: usize = 0x000;
pub const REG_VERSION: usize = 0x004;
pub const REG_DEVICE_ID: usize = 0x008;
#[allow(dead_code)]
pub const REG_VENDOR_ID: usize = 0x00C;
pub const REG_DEVICE_FEATURES: usize = 0x010;
pub const REG_DEVICE_FEATURES_SEL: usize = 0x014;
pub const REG_DRIVER_FEATURES: usize = 0x020;
pub const REG_DRIVER_FEATURES_SEL: usize = 0x024;
pub const REG_QUEUE_SEL: usize = 0x030;
pub const REG_QUEUE_NUM_MAX: usize = 0x034;
pub const REG_QUEUE_NUM: usize = 0x038;
pub const REG_QUEUE_NOTIFY: usize = 0x050;
pub const REG_INTERRUPT_STATUS: usize = 0x060;
pub const REG_INTERRUPT_ACK: usize = 0x064;
pub const REG_STATUS: usize = 0x070;

// Legacy (v1) only registers
pub const REG_GUEST_PAGE_SIZE: usize = 0x028;
pub const REG_QUEUE_ALIGN: usize = 0x03C;
pub const REG_QUEUE_PFN: usize = 0x040;

// Modern (v2) only registers
pub const REG_QUEUE_READY: usize = 0x044;
pub const REG_QUEUE_DESC_LOW: usize = 0x080;
pub const REG_QUEUE_DESC_HIGH: usize = 0x084;
pub const REG_QUEUE_AVAIL_LOW: usize = 0x090;
pub const REG_QUEUE_AVAIL_HIGH: usize = 0x094;
pub const REG_QUEUE_USED_LOW: usize = 0x0A0;
pub const REG_QUEUE_USED_HIGH: usize = 0x0A4;

const VIRTIO_MAGIC: u32 = 0x74726976;

// Device status bits
pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;

// Device IDs
pub const DEVICE_ID_GPU: u32 = 16;
pub const DEVICE_ID_INPUT: u32 = 18;

#[inline]
pub fn read_reg(base: usize, offset: usize) -> u32 {
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

#[inline]
pub fn write_reg(base: usize, offset: usize, val: u32) {
    unsafe { ((base + offset) as *mut u32).write_volatile(val) }
}

/// Return the MMIO version for a device at `base`.
pub fn device_version(base: usize) -> u32 {
    read_reg(base, REG_VERSION)
}

/// Probe all 8 VirtIO MMIO slots and return the base address
/// of the first device matching `device_id`, or None.
pub fn probe(device_id: u32) -> Option<usize> {
    for i in 0..VIRTIO_MMIO_SLOTS {
        let base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        let magic = read_reg(base, REG_MAGIC);
        if magic != VIRTIO_MAGIC {
            continue;
        }
        let version = read_reg(base, REG_VERSION);
        let id = read_reg(base, REG_DEVICE_ID);
        if id == 0 {
            continue; // empty slot
        }
        crate::println!("[virtio] slot {} @ {:#x}: version={} device_id={}", i, base, version, id);
        if id == device_id && (version == 1 || version == 2) {
            return Some(base);
        }
    }
    None
}

/// Initialise a VirtIO MMIO device through the standard handshake.
/// Detects v1 (legacy) vs v2 (modern) and uses the appropriate sequence.
pub fn init_device(base: usize) -> bool {
    let version = read_reg(base, REG_VERSION);

    // 1. Reset
    write_reg(base, REG_STATUS, 0);

    // 2. ACKNOWLEDGE
    write_reg(base, REG_STATUS, STATUS_ACKNOWLEDGE);

    // 3. DRIVER
    write_reg(base, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    if version == 1 {
        // Legacy: set GuestPageSize before doing anything with queues
        write_reg(base, REG_GUEST_PAGE_SIZE, 4096);

        // Negotiate features: accept none for legacy (write features word 0 only)
        write_reg(base, REG_DEVICE_FEATURES_SEL, 0);
        let _features = read_reg(base, REG_DEVICE_FEATURES);
        write_reg(base, REG_DRIVER_FEATURES_SEL, 0);
        write_reg(base, REG_DRIVER_FEATURES, 0);

        // Legacy has NO FEATURES_OK step, go straight to DRIVER_OK later
        true
    } else {
        // Modern (v2) handshake
        write_reg(base, REG_DEVICE_FEATURES_SEL, 0);
        let _features_lo = read_reg(base, REG_DEVICE_FEATURES);
        write_reg(base, REG_DRIVER_FEATURES_SEL, 0);
        write_reg(base, REG_DRIVER_FEATURES, 0);
        write_reg(base, REG_DEVICE_FEATURES_SEL, 1);
        let _features_hi = read_reg(base, REG_DEVICE_FEATURES);
        write_reg(base, REG_DRIVER_FEATURES_SEL, 1);
        write_reg(base, REG_DRIVER_FEATURES, 0);

        // FEATURES_OK
        write_reg(
            base,
            REG_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );

        let status = read_reg(base, REG_STATUS);
        if status & STATUS_FEATURES_OK == 0 {
            return false;
        }

        true
    }
}

/// After queue setup, set DRIVER_OK.
pub fn driver_ok(base: usize) {
    let status = read_reg(base, REG_STATUS);
    write_reg(base, REG_STATUS, status | STATUS_DRIVER_OK);
}

// ── Config space access (offset 0x100 from device base) ──────────

const REG_CONFIG: usize = 0x100;

pub fn write_config_u8(base: usize, offset: usize, val: u8) {
    unsafe { ((base + REG_CONFIG + offset) as *mut u8).write_volatile(val) }
}

pub fn read_config_u8(base: usize, offset: usize) -> u8 {
    unsafe { ((base + REG_CONFIG + offset) as *const u8).read_volatile() }
}

pub fn read_config_u16_le(base: usize, offset: usize) -> u16 {
    let lo = read_config_u8(base, offset) as u16;
    let hi = read_config_u8(base, offset + 1) as u16;
    lo | (hi << 8)
}

#[allow(dead_code)]
pub fn read_config_u32_le(base: usize, offset: usize) -> u32 {
    let lo = read_config_u16_le(base, offset) as u32;
    let hi = read_config_u16_le(base, offset + 2) as u32;
    lo | (hi << 16)
}

// ── Multi-device probe ───────────────────────────────────────────

/// Result of probe_all: an array of (base, slot) pairs and a count.
pub struct ProbeResult {
    pub entries: [(usize, usize); VIRTIO_MMIO_SLOTS],
    pub count: usize,
}

/// Probe all 8 VirtIO MMIO slots and return ALL devices matching `device_id`.
pub fn probe_all(device_id: u32) -> ProbeResult {
    let mut result = ProbeResult {
        entries: [(0, 0); VIRTIO_MMIO_SLOTS],
        count: 0,
    };
    for i in 0..VIRTIO_MMIO_SLOTS {
        let base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
        let magic = read_reg(base, REG_MAGIC);
        if magic != VIRTIO_MAGIC {
            continue;
        }
        let version = read_reg(base, REG_VERSION);
        let id = read_reg(base, REG_DEVICE_ID);
        if id == 0 {
            continue;
        }
        if id == device_id && (version == 1 || version == 2) {
            result.entries[result.count] = (base, i);
            result.count += 1;
        }
    }
    result
}
