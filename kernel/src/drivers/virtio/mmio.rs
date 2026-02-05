/// VirtIO MMIO transport layer for QEMU virt machine.
///
/// 8 VirtIO MMIO slots at 0x1000_1000 .. 0x1000_8000, each 0x1000 apart.

const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
const VIRTIO_MMIO_STRIDE: usize = 0x1000;
const VIRTIO_MMIO_SLOTS: usize = 8;

// Register offsets
pub const REG_MAGIC: usize = 0x000;
pub const REG_VERSION: usize = 0x004;
pub const REG_DEVICE_ID: usize = 0x008;
pub const REG_VENDOR_ID: usize = 0x00C;
pub const REG_DEVICE_FEATURES: usize = 0x010;
pub const REG_DEVICE_FEATURES_SEL: usize = 0x014;
pub const REG_DRIVER_FEATURES: usize = 0x020;
pub const REG_DRIVER_FEATURES_SEL: usize = 0x024;
pub const REG_QUEUE_SEL: usize = 0x030;
pub const REG_QUEUE_NUM_MAX: usize = 0x034;
pub const REG_QUEUE_NUM: usize = 0x038;
pub const REG_QUEUE_READY: usize = 0x044;
pub const REG_QUEUE_NOTIFY: usize = 0x050;
pub const REG_INTERRUPT_STATUS: usize = 0x060;
pub const REG_INTERRUPT_ACK: usize = 0x064;
pub const REG_STATUS: usize = 0x070;
pub const REG_QUEUE_DESC_LOW: usize = 0x080;
pub const REG_QUEUE_DESC_HIGH: usize = 0x084;
pub const REG_QUEUE_AVAIL_LOW: usize = 0x090;
pub const REG_QUEUE_AVAIL_HIGH: usize = 0x094;
pub const REG_QUEUE_USED_LOW: usize = 0x0A0;
pub const REG_QUEUE_USED_HIGH: usize = 0x0A4;

const VIRTIO_MAGIC: u32 = 0x74726976;
const VIRTIO_VERSION_2: u32 = 2;

// Device status bits
pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;

// Device IDs
pub const DEVICE_ID_GPU: u32 = 16;

#[inline]
pub fn read_reg(base: usize, offset: usize) -> u32 {
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

#[inline]
pub fn write_reg(base: usize, offset: usize, val: u32) {
    unsafe { ((base + offset) as *mut u32).write_volatile(val) }
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
        if version != VIRTIO_VERSION_2 {
            continue;
        }
        let id = read_reg(base, REG_DEVICE_ID);
        if id == device_id {
            return Some(base);
        }
    }
    None
}

/// Initialise a VirtIO MMIO device through the standard handshake.
/// Returns the base address on success.
pub fn init_device(base: usize) -> bool {
    // 1. Reset
    write_reg(base, REG_STATUS, 0);

    // 2. ACKNOWLEDGE
    write_reg(base, REG_STATUS, STATUS_ACKNOWLEDGE);

    // 3. DRIVER
    write_reg(
        base,
        REG_STATUS,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER,
    );

    // 4. Negotiate features: accept none (we don't need any special features)
    write_reg(base, REG_DEVICE_FEATURES_SEL, 0);
    let _features_lo = read_reg(base, REG_DEVICE_FEATURES);
    write_reg(base, REG_DRIVER_FEATURES_SEL, 0);
    write_reg(base, REG_DRIVER_FEATURES, 0);
    write_reg(base, REG_DEVICE_FEATURES_SEL, 1);
    let _features_hi = read_reg(base, REG_DEVICE_FEATURES);
    write_reg(base, REG_DRIVER_FEATURES_SEL, 1);
    write_reg(base, REG_DRIVER_FEATURES, 0);

    // 5. FEATURES_OK
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

/// After queue setup, set DRIVER_OK.
pub fn driver_ok(base: usize) {
    let status = read_reg(base, REG_STATUS);
    write_reg(base, REG_STATUS, status | STATUS_DRIVER_OK);
}
