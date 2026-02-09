/// VirtIO Input (keyboard) driver.
///
/// Implements a VirtIO input device driver for virtio-keyboard-device.
/// Uses eventq (queue 0) to receive input events from QEMU.

use super::mmio;
use super::queue::{Virtqueue, VIRTQ_DESC_F_WRITE, QUEUE_SIZE, alloc_dma_buffer};
use crate::drivers::tty;

// VirtIO input event types (Linux input event codes)
const EV_KEY: u16 = 1;

// Event buffer count - one per descriptor in the queue
const EVENT_BUF_COUNT: usize = QUEUE_SIZE;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioInputEvent {
    type_: u16,
    code: u16,
    value: u32,
}

struct Keyboard {
    base: usize,
    irq: u32,
    eventq: Virtqueue,
    event_bufs: usize, // physical addr of event buffer array
    shift_pressed: bool,
}

static mut KEYBOARD: Option<Keyboard> = None;

// Linux keycodes to ASCII (unshifted)
static KEYMAP: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'1';
    map[3] = b'2';
    map[4] = b'3';
    map[5] = b'4';
    map[6] = b'5';
    map[7] = b'6';
    map[8] = b'7';
    map[9] = b'8';
    map[10] = b'9';
    map[11] = b'0';
    map[12] = b'-';
    map[13] = b'=';
    map[14] = 0x7F; // Backspace -> DEL
    map[15] = b'\t';
    map[16] = b'q';
    map[17] = b'w';
    map[18] = b'e';
    map[19] = b'r';
    map[20] = b't';
    map[21] = b'y';
    map[22] = b'u';
    map[23] = b'i';
    map[24] = b'o';
    map[25] = b'p';
    map[26] = b'[';
    map[27] = b']';
    map[28] = b'\r'; // Enter
    // 29 = LeftCtrl (skip)
    map[30] = b'a';
    map[31] = b's';
    map[32] = b'd';
    map[33] = b'f';
    map[34] = b'g';
    map[35] = b'h';
    map[36] = b'j';
    map[37] = b'k';
    map[38] = b'l';
    map[39] = b';';
    map[40] = b'\'';
    map[41] = b'`';
    // 42 = LeftShift (handled separately)
    map[43] = b'\\';
    map[44] = b'z';
    map[45] = b'x';
    map[46] = b'c';
    map[47] = b'v';
    map[48] = b'b';
    map[49] = b'n';
    map[50] = b'm';
    map[51] = b',';
    map[52] = b'.';
    map[53] = b'/';
    // 54 = RightShift (handled separately)
    map[55] = b'*'; // Keypad *
    // 56 = LeftAlt (skip)
    map[57] = b' '; // Space
    map
};

// Linux keycodes to ASCII (shifted)
static KEYMAP_SHIFT: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'!';
    map[3] = b'@';
    map[4] = b'#';
    map[5] = b'$';
    map[6] = b'%';
    map[7] = b'^';
    map[8] = b'&';
    map[9] = b'*';
    map[10] = b'(';
    map[11] = b')';
    map[12] = b'_';
    map[13] = b'+';
    map[14] = 0x7F; // Backspace -> DEL
    map[15] = b'\t';
    map[16] = b'Q';
    map[17] = b'W';
    map[18] = b'E';
    map[19] = b'R';
    map[20] = b'T';
    map[21] = b'Y';
    map[22] = b'U';
    map[23] = b'I';
    map[24] = b'O';
    map[25] = b'P';
    map[26] = b'{';
    map[27] = b'}';
    map[28] = b'\r'; // Enter
    map[30] = b'A';
    map[31] = b'S';
    map[32] = b'D';
    map[33] = b'F';
    map[34] = b'G';
    map[35] = b'H';
    map[36] = b'J';
    map[37] = b'K';
    map[38] = b'L';
    map[39] = b':';
    map[40] = b'"';
    map[41] = b'~';
    map[43] = b'|';
    map[44] = b'Z';
    map[45] = b'X';
    map[46] = b'C';
    map[47] = b'V';
    map[48] = b'B';
    map[49] = b'N';
    map[50] = b'M';
    map[51] = b'<';
    map[52] = b'>';
    map[53] = b'?';
    map[57] = b' '; // Space
    map
};

/// Initialize the VirtIO keyboard driver.
/// Returns true if a keyboard device was found and initialized.
pub fn init() -> bool {
    let (base, slot) = match mmio::probe_with_slot(mmio::DEVICE_ID_INPUT) {
        Some(v) => v,
        None => {
            crate::println!("[keyboard] No VirtIO input device found");
            return false;
        }
    };

    let irq = 1 + slot as u32;
    crate::println!("[keyboard] Found VirtIO input at {:#x} (slot {}, IRQ {})", base, slot, irq);
    crate::println!("[keyboard] NOTE: next allocs are kbd virtq + event_bufs");

    if !mmio::init_device(base) {
        crate::println!("[keyboard] Device init failed");
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
        let desc_idx = eventq.alloc_desc().expect("keyboard: no free desc");
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
        core::ptr::addr_of_mut!(KEYBOARD).write(Some(Keyboard {
            base,
            irq,
            eventq,
            event_bufs,
            shift_pressed: false,
        }));
    }

    crate::println!("[keyboard] Initialized, event_bufs={:#x} (page {:#x})", event_bufs, event_bufs >> 12);
    true
}

/// Handle a keyboard IRQ. Called from the trap handler.
pub fn handle_irq() {
    let kbd = unsafe {
        match (*core::ptr::addr_of_mut!(KEYBOARD)).as_mut() {
            Some(k) => k,
            None => return,
        }
    };

    // Acknowledge interrupt
    let status = mmio::read_reg(kbd.base, mmio::REG_INTERRUPT_STATUS);
    mmio::write_reg(kbd.base, mmio::REG_INTERRUPT_ACK, status);

    // Process all used descriptors
    while let Some((desc_idx, _len)) = kbd.eventq.pop_used() {
        // Read the event from the buffer
        let buf_addr = kbd.event_bufs + (desc_idx as usize) * core::mem::size_of::<VirtioInputEvent>();

        // Corruption check: read the descriptor's addr field and compare with expected
        let expected_addr = buf_addr as u64;
        let desc = unsafe { &*(kbd.eventq.desc.add(desc_idx as usize)) };
        if desc.addr != expected_addr {
            crate::println!("[irq] CORRUPTION: desc[{}].addr={:#x} expected={:#x}",
                desc_idx, desc.addr, expected_addr);
        }

        let event = unsafe { &*(buf_addr as *const VirtioInputEvent) };

        crate::println!("[irq] desc={} addr={:#x} type={:#x} code={:#x} val={:#x}",
            desc_idx, buf_addr, event.type_, event.code, event.value);

        if event.type_ == EV_KEY {
            let code = event.code as usize;
            let pressed = event.value != 0;
            if pressed {
                crate::println!("[irq] EV_KEY D{}", event.code);
            } else {
                crate::println!("[irq] EV_KEY U{}", event.code);
            }

            // Push raw event for ALL key presses and releases (for kbd-server)
            tty::push_raw_kbd_event(event.code, pressed);

            if code == 42 || code == 54 {
                // Shift key
                kbd.shift_pressed = event.value != 0; // 1=press, 0=release
            } else if event.value == 1 && code < 128 {
                // Key press (not release/repeat)
                let ascii = if kbd.shift_pressed {
                    KEYMAP_SHIFT[code]
                } else {
                    KEYMAP[code]
                };

                if ascii != 0 {
                    tty::push_kbd_char(ascii);
                }
            }
        }

        // Re-queue the descriptor: set it up as device-writable again
        let buf_addr = kbd.event_bufs + (desc_idx as usize) * core::mem::size_of::<VirtioInputEvent>();
        kbd.eventq.write_desc(
            desc_idx,
            buf_addr as u64,
            core::mem::size_of::<VirtioInputEvent>() as u32,
            VIRTQ_DESC_F_WRITE,
            0,
        );
        kbd.eventq.push_avail(desc_idx);
    }

    // Notify device that buffers have been re-queued
    kbd.eventq.notify(kbd.base, 0);
}

/// Return the IRQ number if the keyboard is initialized.
pub fn irq_number() -> Option<u32> {
    unsafe { (*core::ptr::addr_of!(KEYBOARD)).as_ref().map(|k| k.irq) }
}
