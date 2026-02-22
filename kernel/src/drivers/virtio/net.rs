//! VirtIO Network driver.
//!
//! Implements a VirtIO net device driver for virtio-net-device.
//! Uses receiveq (queue 0) for incoming frames and transmitq (queue 1) for outgoing.

use core::sync::atomic::{AtomicUsize, Ordering};
use super::mmio;
use super::queue::{Virtqueue, VIRTQ_DESC_F_WRITE, alloc_dma_buffer};

/// VirtIO net header prepended to every frame by the device.
#[repr(C)]
#[allow(dead_code)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

const VIRTIO_NET_HDR_SIZE: usize = 10;

/// Size of each receive buffer slot (header + max ethernet frame).
const RX_BUF_SIZE: usize = 2048;

/// Size of the transmit staging buffer.
const TX_BUF_SIZE: usize = 2048;

/// Number of pre-filled RX descriptor slots.
const RX_SLOT_COUNT: usize = 16;

/// VIRTIO_NET_F_MAC feature bit.
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

struct Net {
    base: usize,
    irq: u32,
    receiveq: Virtqueue,
    transmitq: Virtqueue,
    rx_bufs: usize,
    tx_buf: usize,
    mac: [u8; 6],
}

static mut NET: Option<Net> = None;

/// PID to wake when a network IRQ fires.
static NET_WAKE_PID: AtomicUsize = AtomicUsize::new(0);

/// Initialize the VirtIO network driver.
/// Probes for a VirtIO net device (device ID 1), performs the handshake
/// accepting VIRTIO_NET_F_MAC, reads the MAC address, sets up receiveq
/// and transmitq, pre-fills RX buffers, and enables the PLIC IRQ.
/// Returns true on success.
pub fn init() -> bool {
    let (base, irq) = match mmio::probe(mmio::DEVICE_ID_NET) {
        Some(v) => v,
        None => {
            crate::println!("[net] No VirtIO net device found");
            return false;
        }
    };

    crate::println!("[net] Found VirtIO net at {:#x} (IRQ {})", base, irq);

    // Custom handshake: we need to accept VIRTIO_NET_F_MAC (bit 5),
    // so we cannot use mmio::init_device which accepts no features.
    if !net_init_device(base) {
        crate::println!("[net] Device init failed (features negotiation)");
        return false;
    }

    // Set up receiveq (queue 0)
    let mut receiveq = Virtqueue::new(base, 0);

    // Set up transmitq (queue 1)
    let transmitq = Virtqueue::new(base, 1);

    // Set DRIVER_OK
    mmio::driver_ok(base);

    // Read MAC address from config space (offsets 0..5)
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = mmio::read_config_u8(base, i);
    }
    crate::println!(
        "[net] MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // Allocate RX buffers: 16 slots * 2048 bytes = 32KB = 8 pages
    let rx_pages = RX_SLOT_COUNT * RX_BUF_SIZE / 4096;
    let rx_bufs = alloc_dma_buffer(rx_pages);

    // Zero the RX buffer region
    unsafe {
        core::ptr::write_bytes(rx_bufs as *mut u8, 0, RX_SLOT_COUNT * RX_BUF_SIZE);
    }

    // Allocate TX buffer: one slot of TX_BUF_SIZE (fits in 1 page)
    let tx_buf = alloc_dma_buffer(1);
    unsafe {
        core::ptr::write_bytes(tx_buf as *mut u8, 0, TX_BUF_SIZE);
    }

    // Pre-fill receiveq with device-writable descriptors
    for i in 0..RX_SLOT_COUNT {
        let desc_idx = receiveq.alloc_desc().expect("net: no free desc for rx");
        let buf_addr = rx_bufs + i * RX_BUF_SIZE;
        receiveq.write_desc(
            desc_idx,
            buf_addr as u64,
            RX_BUF_SIZE as u32,
            VIRTQ_DESC_F_WRITE,
            0,
        );
        receiveq.push_avail(desc_idx);
    }

    // Notify device that RX buffers are available
    receiveq.notify(base, 0);

    // Enable IRQ in PLIC
    crate::drivers::plic::enable_irq(irq);

    crate::println!("[net] IRQ {} enabled, rx_bufs={:#x}, tx_buf={:#x}", irq, rx_bufs, tx_buf);

    unsafe {
        core::ptr::addr_of_mut!(NET).write(Some(Net {
            base,
            irq,
            receiveq,
            transmitq,
            rx_bufs,
            tx_buf,
            mac,
        }));
    }

    crate::println!("[net] Initialized");

    true
}

/// Perform the VirtIO device handshake accepting VIRTIO_NET_F_MAC.
/// This is a custom handshake because `mmio::init_device` accepts no features.
fn net_init_device(base: usize) -> bool {
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

        // Accept MAC feature if available
        let accepted = dev_features & VIRTIO_NET_F_MAC;
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES_SEL, 0);
        mmio::write_reg(base, mmio::REG_DRIVER_FEATURES, accepted);

        // No FEATURES_OK step for legacy
        true
    } else {
        // Modern v2 handshake
        mmio::write_reg(base, mmio::REG_DEVICE_FEATURES_SEL, 0);
        let dev_features = mmio::read_reg(base, mmio::REG_DEVICE_FEATURES);
        let accepted = dev_features & VIRTIO_NET_F_MAC;
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
            return false;
        }

        true
    }
}

/// Return the MAC address if the net device is initialized.
pub fn mac_address() -> Option<[u8; 6]> {
    unsafe { (*core::ptr::addr_of!(NET)).as_ref().map(|n| n.mac) }
}

/// Return the IRQ number if the net device is initialized.
pub fn irq_number() -> Option<u32> {
    unsafe { (*core::ptr::addr_of!(NET)).as_ref().map(|n| n.irq) }
}

/// Set the PID to wake when a network IRQ fires.
pub fn set_wake_pid(pid: usize) {
    NET_WAKE_PID.store(pid, Ordering::Relaxed);
}

/// Poll the receiveq for a completed RX buffer.
///
/// Returns `Some((frame_ptr, frame_len, desc_idx))` where:
/// - `frame_ptr` points past the VirtIO net header to the start of the ethernet frame
/// - `frame_len` is the ethernet frame length (excluding VirtIO header)
/// - `desc_idx` must be passed back to `requeue_rx()` when the caller is done
///
/// Returns `None` if no completed buffers are available.
pub fn poll_rx() -> Option<(usize, usize, u16)> {
    let net = unsafe { (*core::ptr::addr_of_mut!(NET)).as_mut()? };

    let (desc_idx, total_len) = net.receiveq.pop_used()?;
    let frame_len = match (total_len as usize).checked_sub(VIRTIO_NET_HDR_SIZE) {
        Some(len) if len > 0 => len,
        _ => {
            crate::println!("[net] dropping short RX frame ({} bytes, need > {})",
                total_len, VIRTIO_NET_HDR_SIZE);
            requeue_rx(desc_idx);
            return None;
        }
    };
    let frame_ptr = net.rx_bufs + (desc_idx as usize) * RX_BUF_SIZE + VIRTIO_NET_HDR_SIZE;
    Some((frame_ptr, frame_len, desc_idx))
}

/// Re-queue an RX descriptor after the caller has finished processing the frame.
/// `desc_idx` is the value returned by `poll_rx()`.
pub fn requeue_rx(desc_idx: u16) {
    let net = unsafe {
        match (*core::ptr::addr_of_mut!(NET)).as_mut() {
            Some(n) => n,
            None => return,
        }
    };

    let buf_addr = net.rx_bufs + (desc_idx as usize) * RX_BUF_SIZE;
    net.receiveq.write_desc(
        desc_idx,
        buf_addr as u64,
        RX_BUF_SIZE as u32,
        VIRTQ_DESC_F_WRITE,
        0,
    );
    net.receiveq.push_avail(desc_idx);
    net.receiveq.notify(net.base, 0);
}

/// Transmit an ethernet frame.
///
/// Prepends a zeroed VirtIO net header and copies the frame data into
/// the TX staging buffer. Blocks (via WFI polling) until the device
/// has consumed the buffer.
///
/// Returns true on success, false if the frame is too large or the
/// device is not initialized.
pub fn transmit(frame: &[u8]) -> bool {
    let net = unsafe {
        match (*core::ptr::addr_of_mut!(NET)).as_mut() {
            Some(n) => n,
            None => return false,
        }
    };

    let total_len = VIRTIO_NET_HDR_SIZE + frame.len();
    if total_len > TX_BUF_SIZE {
        return false;
    }

    // Write zeroed VirtIO net header
    unsafe {
        core::ptr::write_bytes(net.tx_buf as *mut u8, 0, VIRTIO_NET_HDR_SIZE);
    }

    // Copy frame data after the header
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            (net.tx_buf + VIRTIO_NET_HDR_SIZE) as *mut u8,
            frame.len(),
        );
    }

    // Allocate a descriptor, set it up as device-readable
    let desc_idx = match net.transmitq.alloc_desc() {
        Some(idx) => idx,
        None => return false,
    };

    net.transmitq.write_desc(
        desc_idx,
        net.tx_buf as u64,
        total_len as u32,
        0, // flags=0: device-readable
        0,
    );
    net.transmitq.push_avail(desc_idx);
    net.transmitq.notify(net.base, 1);

    // Poll for completion via WFI
    loop {
        if let Some((head, _len)) = net.transmitq.pop_used() {
            net.transmitq.free_chain(head);
            return true;
        }
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Handle a network device IRQ. Called from the trap handler.
///
/// Acknowledges the interrupt and wakes the registered PID (if any)
/// so the network service can poll for received frames.
pub fn handle_irq() {
    let net = unsafe {
        match (*core::ptr::addr_of_mut!(NET)).as_mut() {
            Some(n) => n,
            None => return,
        }
    };

    // Acknowledge interrupt
    let intr_status = mmio::read_reg(net.base, mmio::REG_INTERRUPT_STATUS);
    mmio::write_reg(net.base, mmio::REG_INTERRUPT_ACK, intr_status);

    // Wake the registered network service process
    let pid = NET_WAKE_PID.load(Ordering::Relaxed);
    if pid != 0 {
        crate::task::wake_process(pid);
    }
}
