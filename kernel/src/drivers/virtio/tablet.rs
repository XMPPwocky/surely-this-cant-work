/// VirtIO Tablet (absolute pointer) driver.
///
/// Implements a VirtIO input device driver for virtio-tablet-device.
/// Uses eventq (queue 0) to receive input events from QEMU.
/// Tablet provides absolute coordinates (0..32767) instead of relative deltas.

use super::mmio;
use super::queue::{Virtqueue, VIRTQ_DESC_F_WRITE, QUEUE_SIZE, alloc_dma_buffer};
use crate::drivers::tty;

// VirtIO input event types (Linux input event codes)
const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_ABS: u16 = 3;

// Sync event codes
const SYN_REPORT: u16 = 0;

// Absolute axis codes
const ABS_X: u16 = 0;
const ABS_Y: u16 = 1;

// Button codes
const BTN_LEFT: u16 = 0x110;
const BTN_RIGHT: u16 = 0x111;
const BTN_MIDDLE: u16 = 0x112;

// Event buffer count - one per descriptor in the queue
const EVENT_BUF_COUNT: usize = QUEUE_SIZE;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioInputEvent {
    type_: u16,
    code: u16,
    value: u32,
}

struct Tablet {
    base: usize,
    irq: u32,
    eventq: Virtqueue,
    event_bufs: usize,     // physical addr of event buffer array
    pending_x: u16,        // accumulated X position
    pending_y: u16,        // accumulated Y position
    prev_buttons: u8,      // bitmask: bit0=Left, bit1=Right, bit2=Middle
}

static mut TABLET: Option<Tablet> = None;

/// Probe for tablet device (via input.rs) and initialize if found.
pub fn init_from_probe() -> bool {
    let (base, slot) = match super::input::tablet_base_and_slot() {
        Some(v) => v,
        None => return false,
    };
    init(base, slot)
}

/// Initialize the VirtIO tablet driver at a specific MMIO base/slot.
fn init(base: usize, slot: usize) -> bool {
    let irq = 1 + slot as u32;
    crate::println!("[tablet] Found VirtIO tablet at {:#x} (slot {}, IRQ {})", base, slot, irq);

    if !mmio::init_device(base) {
        crate::println!("[tablet] Device init failed");
        return false;
    }

    // Set up eventq (queue 0)
    let mut eventq = Virtqueue::new(base, 0);

    // Set DRIVER_OK
    mmio::driver_ok(base);

    // Allocate event buffers: one VirtioInputEvent (8 bytes) per descriptor
    let buf_size = EVENT_BUF_COUNT * core::mem::size_of::<VirtioInputEvent>();
    let event_bufs = alloc_dma_buffer(1); // one page is plenty

    // Zero the buffer
    unsafe {
        core::ptr::write_bytes(event_bufs as *mut u8, 0, buf_size);
    }

    // Pre-fill eventq with device-writable descriptors
    for i in 0..EVENT_BUF_COUNT {
        let desc_idx = eventq.alloc_desc().expect("tablet: no free desc");
        let buf_addr = event_bufs + i * core::mem::size_of::<VirtioInputEvent>();
        eventq.write_desc(
            desc_idx,
            buf_addr as u64,
            core::mem::size_of::<VirtioInputEvent>() as u32,
            VIRTQ_DESC_F_WRITE,
            0,
        );
        eventq.push_avail(desc_idx);
    }

    // Notify device that buffers are available
    eventq.notify(base, 0);

    // Enable IRQ in PLIC
    crate::drivers::plic::enable_irq(irq);

    unsafe {
        core::ptr::addr_of_mut!(TABLET).write(Some(Tablet {
            base,
            irq,
            eventq,
            event_bufs,
            pending_x: 0,
            pending_y: 0,
            prev_buttons: 0,
        }));
    }

    crate::println!("[tablet] Initialized, event_bufs={:#x}", event_bufs);

    true
}

/// Handle a tablet IRQ. Called from the trap handler.
pub fn handle_irq() {
    let tab = unsafe {
        match (*core::ptr::addr_of_mut!(TABLET)).as_mut() {
            Some(t) => t,
            None => return,
        }
    };

    // Acknowledge interrupt
    let intr_status = mmio::read_reg(tab.base, mmio::REG_INTERRUPT_STATUS);
    mmio::write_reg(tab.base, mmio::REG_INTERRUPT_ACK, intr_status);

    // Track current button state for this batch of events
    let mut cur_buttons = tab.prev_buttons;

    // Process all used descriptors
    while let Some((desc_idx, _len)) = tab.eventq.pop_used() {
        let buf_addr = tab.event_bufs + (desc_idx as usize) * core::mem::size_of::<VirtioInputEvent>();
        let event = unsafe { &*(buf_addr as *const VirtioInputEvent) };

        match event.type_ {
            EV_ABS => {
                match event.code {
                    ABS_X => tab.pending_x = event.value as u16,
                    ABS_Y => tab.pending_y = event.value as u16,
                    _ => {}
                }
            }
            EV_KEY => {
                let bit = match event.code {
                    BTN_LEFT => Some(0u8),
                    BTN_RIGHT => Some(1u8),
                    BTN_MIDDLE => Some(2u8),
                    _ => None,
                };
                if let Some(bit_idx) = bit {
                    if event.value != 0 {
                        cur_buttons |= 1 << bit_idx;
                    } else {
                        cur_buttons &= !(1 << bit_idx);
                    }
                }
            }
            EV_SYN if event.code == SYN_REPORT => {
                // Flush: emit events for this sync batch

                // Emit move event
                tty::push_raw_mouse_event(tty::RawMouseEvent::Move {
                    abs_x: tab.pending_x,
                    abs_y: tab.pending_y,
                });

                // Emit button edge events
                let changed = cur_buttons ^ tab.prev_buttons;
                for bit_idx in 0..3u8 {
                    if changed & (1 << bit_idx) != 0 {
                        if cur_buttons & (1 << bit_idx) != 0 {
                            tty::push_raw_mouse_event(tty::RawMouseEvent::ButtonDown { button: bit_idx });
                        } else {
                            tty::push_raw_mouse_event(tty::RawMouseEvent::ButtonUp { button: bit_idx });
                        }
                    }
                }
                tab.prev_buttons = cur_buttons;
            }
            _ => {}
        }

        // Re-queue the descriptor
        let buf_addr = tab.event_bufs + (desc_idx as usize) * core::mem::size_of::<VirtioInputEvent>();
        tab.eventq.write_desc(
            desc_idx,
            buf_addr as u64,
            core::mem::size_of::<VirtioInputEvent>() as u32,
            VIRTQ_DESC_F_WRITE,
            0,
        );
        tab.eventq.push_avail(desc_idx);
    }

    // Notify device that buffers have been re-queued
    tab.eventq.notify(tab.base, 0);
}

/// Return the IRQ number if the tablet is initialized.
pub fn irq_number() -> Option<u32> {
    unsafe { (*core::ptr::addr_of!(TABLET)).as_ref().map(|t| t.irq) }
}
