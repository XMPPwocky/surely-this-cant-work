//! VirtIO GPU driver.
//!
//! Implements a minimal VirtIO GPU driver that sets up a 2D framebuffer
//! and provides `flush()` to update the display.

use crate::mm::address::PAGE_SIZE;
use super::mmio;
use super::queue::{Virtqueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, alloc_dma_buffer};

// GPU command types
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

// GPU response types
const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

// Pixel format
const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;

const RESOURCE_ID: u32 = 1;
const SCANOUT_ID: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuCtrlHdr {
    type_: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}

impl VirtioGpuCtrlHdr {
    fn new(type_: u32) -> Self {
        VirtioGpuCtrlHdr {
            type_,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            padding: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuDisplayOne {
    r: VirtioGpuRect,
    enabled: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuRespDisplayInfo {
    hdr: VirtioGpuCtrlHdr,
    pmodes: [VirtioGpuDisplayOne; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuResourceCreate2d {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuResourceAttachBacking {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    nr_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuMemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuSetScanout {
    hdr: VirtioGpuCtrlHdr,
    r: VirtioGpuRect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuTransferToHost2d {
    hdr: VirtioGpuCtrlHdr,
    r: VirtioGpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuResourceFlush {
    hdr: VirtioGpuCtrlHdr,
    r: VirtioGpuRect,
    resource_id: u32,
    padding: u32,
}

/// Global GPU state.
pub struct Gpu {
    base: usize,
    irq: u32,
    controlq: Virtqueue,
    /// DMA buffer for sending commands/receiving responses (one page)
    cmd_buf: usize,
    pub fb_addr: usize,
    pub width: u32,
    pub height: u32,
}

static mut GPU: Option<Gpu> = None;

/// Send a command on the control virtqueue and poll for completion.
/// `cmd_phys` is the physical address of the command buffer (device-readable).
/// `cmd_len` is the command size.
/// `resp_phys` is the physical address of the response buffer (device-writable).
/// `resp_len` is the response buffer size.
fn send_command(gpu: &mut Gpu, cmd_phys: usize, cmd_len: u32, resp_phys: usize, resp_len: u32) {
    let q = &mut gpu.controlq;

    let d0 = q.alloc_desc().expect("gpu: no free desc for cmd");
    let d1 = q.alloc_desc().expect("gpu: no free desc for resp");

    // d0: command (device reads)
    q.write_desc(d0, cmd_phys as u64, cmd_len, VIRTQ_DESC_F_NEXT, d1);
    // d1: response (device writes)
    q.write_desc(d1, resp_phys as u64, resp_len, VIRTQ_DESC_F_WRITE, 0);

    q.push_avail(d0);
    q.notify(gpu.base, 0);

    // Wait for completion.  The VirtIO GPU device in QEMU processes commands
    // via a bottom-half (BH), not synchronously during the MMIO notify write.
    // A tight spin loop prevents QEMU's event loop from running the BH.
    // We use WFI to yield the CPU, allowing the BH to run.  The GPU's PLIC
    // interrupt (enabled during init) wakes us when the command completes.
    let mut attempts: u32 = 0;
    loop {
        if let Some((head, _len)) = q.pop_used() {
            q.free_chain(head);
            return;
        }
        attempts += 1;
        if attempts > 1000 {
            let cmd_type = unsafe { core::ptr::read_volatile(cmd_phys as *const u32) };
            let avail_idx = unsafe {
                core::ptr::addr_of!((*q.avail).idx).read_volatile()
            };
            let used_idx = unsafe {
                core::ptr::addr_of!((*q.used).idx).read_volatile()
            };
            let resp_type = unsafe { core::ptr::read_volatile(resp_phys as *const u32) };
            let dev_status = mmio::read_reg(gpu.base, mmio::REG_STATUS);
            let intr_status = mmio::read_reg(gpu.base, mmio::REG_INTERRUPT_STATUS);
            crate::println!(
                "[gpu] STUCK: cmd_type={:#x} d0={} d1={} avail_idx={} last_used={} used_idx={} resp_type={:#x} dev_status={:#x} intr_status={:#x}",
                cmd_type, d0, d1, avail_idx, q.last_used_idx, used_idx, resp_type, dev_status, intr_status
            );
            panic!("gpu: send_command stuck — device did not respond after {} WFI cycles", attempts);
        }
        // Yield CPU so QEMU can run its event loop and process the VirtIO BH
        unsafe { core::arch::asm!("wfi"); }
    }
}

/// Send a command that is already laid out in the cmd_buf page.
/// Returns a pointer to the response header in cmd_buf.
fn send_cmd_in_buf(gpu: &mut Gpu, cmd_offset: usize, cmd_len: usize, resp_offset: usize, resp_len: usize) {
    let cmd_phys = gpu.cmd_buf + cmd_offset;
    let resp_phys = gpu.cmd_buf + resp_offset;
    send_command(gpu, cmd_phys, cmd_len as u32, resp_phys, resp_len as u32);
}

/// Initialise the VirtIO GPU.
/// Returns true on success.
pub fn init() -> bool {
    let base = match mmio::probe(mmio::DEVICE_ID_GPU) {
        Some(b) => b,
        None => {
            crate::println!("[gpu] No VirtIO GPU found");
            return false;
        }
    };

    crate::println!("[gpu] Found VirtIO GPU at {:#x}", base);

    if !mmio::init_device(base) {
        crate::println!("[gpu] Device init failed (features negotiation)");
        return false;
    }

    // Set up control virtqueue (queue 0)
    let controlq = Virtqueue::new(base, 0);

    // Set DRIVER_OK
    mmio::driver_ok(base);

    // Allocate a page for command/response DMA buffers
    let cmd_buf = alloc_dma_buffer(1);

    // Compute IRQ: QEMU virt machine uses IRQ = 1 + slot
    let irq = 1 + ((base - 0x1000_1000) / 0x1000) as u32;

    let mut gpu = Gpu {
        base,
        irq,
        controlq,
        cmd_buf,
        fb_addr: 0,
        width: 0,
        height: 0,
    };

    // Enable GPU interrupt in PLIC so WFI wakes on command completion
    crate::drivers::plic::enable_irq(irq);
    // Ensure SEIE (supervisor external interrupt enable) is set so WFI can
    // wake on the GPU interrupt.  During early boot this bit hasn't been set
    // yet by enable_timer().
    crate::set_csr!("sie", 1 << 9);
    crate::println!("[gpu] IRQ {} enabled", irq);

    // 1. GET_DISPLAY_INFO
    let (width, height) = get_display_info(&mut gpu);
    gpu.width = width;
    gpu.height = height;
    crate::println!("[gpu] Display: {}x{}", width, height);

    // 2. Allocate framebuffer
    let fb_bytes = (width as usize) * (height as usize) * 4;
    let fb_pages = fb_bytes.div_ceil(PAGE_SIZE);
    let fb_addr = alloc_dma_buffer(fb_pages);
    gpu.fb_addr = fb_addr;
    crate::println!("[gpu] FB alloc: {:#x}..{:#x} ({} pages)", fb_addr, fb_addr + fb_pages * PAGE_SIZE, fb_pages);

    // Clear framebuffer to black
    unsafe {
        core::ptr::write_bytes(fb_addr as *mut u8, 0, fb_bytes);
    }

    // 3. RESOURCE_CREATE_2D
    resource_create_2d(&mut gpu, width, height);

    // 4. RESOURCE_ATTACH_BACKING
    resource_attach_backing(&mut gpu, fb_addr, fb_bytes);

    // 5. SET_SCANOUT
    set_scanout(&mut gpu, width, height);

    // 6. Initial flush
    transfer_to_host_2d(&mut gpu, width, height);
    resource_flush(&mut gpu, width, height);

    crate::println!("[gpu] Framebuffer at {:#x} ({} pages)", fb_addr, fb_pages);

    unsafe {
        core::ptr::addr_of_mut!(GPU).write(Some(gpu));
    }

    true
}

fn get_display_info(gpu: &mut Gpu) -> (u32, u32) {
    let buf = gpu.cmd_buf as *mut u8;

    // Write command header at offset 0
    let hdr = VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    unsafe {
        core::ptr::write(buf as *mut VirtioGpuCtrlHdr, hdr);
    }

    let cmd_len = core::mem::size_of::<VirtioGpuCtrlHdr>();
    let resp_offset = 256; // put response at offset 256
    let resp_len = core::mem::size_of::<VirtioGpuRespDisplayInfo>();

    send_cmd_in_buf(gpu, 0, cmd_len, resp_offset, resp_len);

    let resp = unsafe {
        &*(buf.add(resp_offset) as *const VirtioGpuRespDisplayInfo)
    };

    if resp.hdr.type_ == VIRTIO_GPU_RESP_OK_DISPLAY_INFO && resp.pmodes[0].enabled != 0 {
        (resp.pmodes[0].r.width, resp.pmodes[0].r.height)
    } else {
        // Default
        (1024, 768)
    }
}

fn resource_create_2d(gpu: &mut Gpu, width: u32, height: u32) {
    let buf = gpu.cmd_buf as *mut u8;

    let cmd = VirtioGpuResourceCreate2d {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D),
        resource_id: RESOURCE_ID,
        format: VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
        width,
        height,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuResourceCreate2d, cmd); }

    let cmd_len = core::mem::size_of::<VirtioGpuResourceCreate2d>();
    let resp_offset = 256;
    let resp_len = core::mem::size_of::<VirtioGpuCtrlHdr>();

    send_cmd_in_buf(gpu, 0, cmd_len, resp_offset, resp_len);

    let resp = unsafe { &*(buf.add(resp_offset) as *const VirtioGpuCtrlHdr) };
    assert!(resp.type_ == VIRTIO_GPU_RESP_OK_NODATA, "resource_create_2d failed: {:#x}", resp.type_);
}

fn resource_attach_backing(gpu: &mut Gpu, fb_addr: usize, fb_bytes: usize) {
    let buf = gpu.cmd_buf as *mut u8;

    // Layout: AttachBacking struct followed by one MemEntry
    let cmd = VirtioGpuResourceAttachBacking {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING),
        resource_id: RESOURCE_ID,
        nr_entries: 1,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuResourceAttachBacking, cmd); }

    let entry_offset = core::mem::size_of::<VirtioGpuResourceAttachBacking>();
    let entry = VirtioGpuMemEntry {
        addr: fb_addr as u64,
        length: fb_bytes as u32,
        padding: 0,
    };
    unsafe { core::ptr::write(buf.add(entry_offset) as *mut VirtioGpuMemEntry, entry); }

    let cmd_len = entry_offset + core::mem::size_of::<VirtioGpuMemEntry>();
    let resp_offset = 256;
    let resp_len = core::mem::size_of::<VirtioGpuCtrlHdr>();

    send_cmd_in_buf(gpu, 0, cmd_len, resp_offset, resp_len);

    let resp = unsafe { &*(buf.add(resp_offset) as *const VirtioGpuCtrlHdr) };
    assert!(resp.type_ == VIRTIO_GPU_RESP_OK_NODATA, "attach_backing failed: {:#x}", resp.type_);
}

fn set_scanout(gpu: &mut Gpu, width: u32, height: u32) {
    let buf = gpu.cmd_buf as *mut u8;

    let cmd = VirtioGpuSetScanout {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_SET_SCANOUT),
        r: VirtioGpuRect { x: 0, y: 0, width, height },
        scanout_id: SCANOUT_ID,
        resource_id: RESOURCE_ID,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuSetScanout, cmd); }

    let cmd_len = core::mem::size_of::<VirtioGpuSetScanout>();
    let resp_offset = 256;
    let resp_len = core::mem::size_of::<VirtioGpuCtrlHdr>();

    send_cmd_in_buf(gpu, 0, cmd_len, resp_offset, resp_len);

    let resp = unsafe { &*(buf.add(resp_offset) as *const VirtioGpuCtrlHdr) };
    assert!(resp.type_ == VIRTIO_GPU_RESP_OK_NODATA, "set_scanout failed: {:#x}", resp.type_);
}

fn transfer_to_host_2d(gpu: &mut Gpu, width: u32, height: u32) {
    let buf = gpu.cmd_buf as *mut u8;

    let cmd = VirtioGpuTransferToHost2d {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D),
        r: VirtioGpuRect { x: 0, y: 0, width, height },
        offset: 0,
        resource_id: RESOURCE_ID,
        padding: 0,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuTransferToHost2d, cmd); }

    let cmd_len = core::mem::size_of::<VirtioGpuTransferToHost2d>();
    let resp_offset = 256;
    let resp_len = core::mem::size_of::<VirtioGpuCtrlHdr>();

    send_cmd_in_buf(gpu, 0, cmd_len, resp_offset, resp_len);

    let resp = unsafe { &*(buf.add(resp_offset) as *const VirtioGpuCtrlHdr) };
    assert!(resp.type_ == VIRTIO_GPU_RESP_OK_NODATA, "transfer_to_host_2d failed: {:#x}", resp.type_);
}

fn resource_flush(gpu: &mut Gpu, width: u32, height: u32) {
    let buf = gpu.cmd_buf as *mut u8;

    let cmd = VirtioGpuResourceFlush {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_FLUSH),
        r: VirtioGpuRect { x: 0, y: 0, width, height },
        resource_id: RESOURCE_ID,
        padding: 0,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuResourceFlush, cmd); }

    let cmd_len = core::mem::size_of::<VirtioGpuResourceFlush>();
    let resp_offset = 256;
    let resp_len = core::mem::size_of::<VirtioGpuCtrlHdr>();

    send_cmd_in_buf(gpu, 0, cmd_len, resp_offset, resp_len);

    let resp = unsafe { &*(buf.add(resp_offset) as *const VirtioGpuCtrlHdr) };
    assert!(resp.type_ == VIRTIO_GPU_RESP_OK_NODATA, "resource_flush failed: {:#x}", resp.type_);
}

/// Get framebuffer info: (pointer, width, height).
/// Returns None if GPU is not initialised.
pub fn framebuffer() -> Option<(*mut u32, u32, u32)> {
    unsafe {
        let ptr = core::ptr::addr_of!(GPU);
        (*ptr).as_ref().map(|gpu| {
            (gpu.fb_addr as *mut u32, gpu.width, gpu.height)
        })
    }
}

/// Get framebuffer physical page info: (base_ppn, page_count).
/// Returns None if GPU is not initialised.
pub fn framebuffer_phys() -> Option<(crate::mm::address::PhysPageNum, usize)> {
    unsafe {
        let ptr = core::ptr::addr_of!(GPU);
        (*ptr).as_ref().map(|gpu| {
            let fb_bytes = (gpu.width as usize) * (gpu.height as usize) * 4;
            let pages = fb_bytes.div_ceil(PAGE_SIZE);
            (crate::mm::address::PhysPageNum(gpu.fb_addr / PAGE_SIZE), pages)
        })
    }
}

/// Flush a rectangular region of the framebuffer to the display.
pub fn flush_rect(x: u32, y: u32, w: u32, h: u32) {
    unsafe {
        let ptr = core::ptr::addr_of_mut!(GPU);
        if let Some(ref mut gpu) = *ptr {
            transfer_to_host_2d_rect(gpu, x, y, w, h);
            resource_flush_rect(gpu, x, y, w, h);
        }
    }
}

fn transfer_to_host_2d_rect(gpu: &mut Gpu, x: u32, y: u32, w: u32, h: u32) {
    let buf = gpu.cmd_buf as *mut u8;
    let cmd = VirtioGpuTransferToHost2d {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D),
        r: VirtioGpuRect { x, y, width: w, height: h },
        offset: 0,
        resource_id: RESOURCE_ID,
        padding: 0,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuTransferToHost2d, cmd); }
    let cmd_len = core::mem::size_of::<VirtioGpuTransferToHost2d>();
    send_cmd_in_buf(gpu, 0, cmd_len, 256, core::mem::size_of::<VirtioGpuCtrlHdr>());
}

/// Handle a GPU IRQ. Called from the trap handler.
pub fn handle_irq() {
    let gpu = unsafe {
        match (*core::ptr::addr_of_mut!(GPU)).as_mut() {
            Some(g) => g,
            None => return,
        }
    };

    // Acknowledge interrupt
    let intr_status = mmio::read_reg(gpu.base, mmio::REG_INTERRUPT_STATUS);
    mmio::write_reg(gpu.base, mmio::REG_INTERRUPT_ACK, intr_status);
}

/// Return the GPU's IRQ number, if initialised.
pub fn irq_number() -> Option<u32> {
    unsafe { (*core::ptr::addr_of!(GPU)).as_ref().map(|g| g.irq) }
}

fn resource_flush_rect(gpu: &mut Gpu, x: u32, y: u32, w: u32, h: u32) {
    let buf = gpu.cmd_buf as *mut u8;
    let cmd = VirtioGpuResourceFlush {
        hdr: VirtioGpuCtrlHdr::new(VIRTIO_GPU_CMD_RESOURCE_FLUSH),
        r: VirtioGpuRect { x, y, width: w, height: h },
        resource_id: RESOURCE_ID,
        padding: 0,
    };
    unsafe { core::ptr::write(buf as *mut VirtioGpuResourceFlush, cmd); }
    let cmd_len = core::mem::size_of::<VirtioGpuResourceFlush>();
    send_cmd_in_buf(gpu, 0, cmd_len, 256, core::mem::size_of::<VirtioGpuCtrlHdr>());
}
