use crate::sync::SpinLock;

const RING_BUF_SIZE: usize = 256;

/// Simple ring buffer for input characters from IRQ handlers.
pub struct RingBuffer {
    buf: [u8; RING_BUF_SIZE],
    head: usize, // next write position
    tail: usize, // next read position
}

impl RingBuffer {
    pub const fn new() -> Self {
        RingBuffer {
            buf: [0; RING_BUF_SIZE],
            head: 0,
            tail: 0,
        }
    }

    pub fn push(&mut self, ch: u8) {
        let next = (self.head + 1) % RING_BUF_SIZE;
        if next != self.tail {
            self.buf[self.head] = ch;
            self.head = next;
        }
        // else: buffer full, drop character
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            None
        } else {
            let ch = self.buf[self.tail];
            self.tail = (self.tail + 1) % RING_BUF_SIZE;
            Some(ch)
        }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}

/// Serial (UART) input ring buffer — filled by UART IRQ handler
pub static SERIAL_INPUT: SpinLock<RingBuffer> = SpinLock::new(RingBuffer::new());

/// Keyboard input ring buffer — filled by VirtIO keyboard IRQ handler
pub static KBD_INPUT: SpinLock<RingBuffer> = SpinLock::new(RingBuffer::new());

/// PID of the serial console server to wake when serial input arrives (0 = none)
static SERIAL_WAKE_PID: SpinLock<usize> = SpinLock::new(0);

/// PID of the FB console server to wake when keyboard input arrives (0 = none)
static KBD_WAKE_PID: SpinLock<usize> = SpinLock::new(0);

// ============================================================
// Raw keyboard events (press + release, with Linux keycode)
// ============================================================

const RAW_KBD_BUF_SIZE: usize = 64;

/// A raw keyboard event: keycode + press/release.
#[derive(Clone, Copy)]
pub struct RawKeyEvent {
    pub code: u16,
    pub pressed: bool,
}

/// Ring buffer for raw keyboard events.
pub struct RawKeyRingBuffer {
    buf: [RawKeyEvent; RAW_KBD_BUF_SIZE],
    head: usize,
    tail: usize,
}

impl RawKeyRingBuffer {
    pub const fn new() -> Self {
        RawKeyRingBuffer {
            buf: [RawKeyEvent { code: 0, pressed: false }; RAW_KBD_BUF_SIZE],
            head: 0,
            tail: 0,
        }
    }

    pub fn push(&mut self, event: RawKeyEvent) -> bool {
        let next = (self.head + 1) % RAW_KBD_BUF_SIZE;
        if next != self.tail {
            self.buf[self.head] = event;
            self.head = next;
            true
        } else {
            false
        }
    }

    pub fn pop(&mut self) -> Option<RawKeyEvent> {
        if self.head == self.tail {
            None
        } else {
            let ev = self.buf[self.tail];
            self.tail = (self.tail + 1) % RAW_KBD_BUF_SIZE;
            Some(ev)
        }
    }
}

/// Raw keyboard events ring buffer — filled by VirtIO keyboard IRQ handler
pub static RAW_KBD_EVENTS: SpinLock<RawKeyRingBuffer> = SpinLock::new(RawKeyRingBuffer::new());

/// PID of the kbd server to wake when raw keyboard events arrive (0 = none)
static RAW_KBD_WAKE_PID: SpinLock<usize> = SpinLock::new(0);

/// Push a raw keyboard event from the IRQ handler.
pub fn push_raw_kbd_event(code: u16, pressed: bool) {
    let ok = RAW_KBD_EVENTS.lock().push(RawKeyEvent { code, pressed });
    if !ok {
        crate::println!("[tty] DROPPED kbd event code={} pressed={}", code, pressed);
    }
    let pid = *RAW_KBD_WAKE_PID.lock();
    if pid != 0 {
        crate::task::wake_process(pid);
    }
}

/// Set the PID to wake when raw keyboard events arrive.
pub fn set_raw_kbd_wake_pid(pid: usize) {
    *RAW_KBD_WAKE_PID.lock() = pid;
}

/// Push a character from UART IRQ handler.
pub fn push_serial_char(ch: u8) {
    SERIAL_INPUT.lock().push(ch);
    let pid = *SERIAL_WAKE_PID.lock();
    if pid != 0 {
        crate::task::wake_process(pid);
    }
}

/// Push a character from keyboard IRQ handler.
pub fn push_kbd_char(ch: u8) {
    KBD_INPUT.lock().push(ch);
    let pid = *KBD_WAKE_PID.lock();
    if pid != 0 {
        crate::task::wake_process(pid);
    }
}

/// Set the PID to wake when serial input arrives.
pub fn set_serial_wake_pid(pid: usize) {
    *SERIAL_WAKE_PID.lock() = pid;
}

/// Set the PID to wake when keyboard input arrives.
pub fn set_kbd_wake_pid(pid: usize) {
    *KBD_WAKE_PID.lock() = pid;
}

// ============================================================
// Raw mouse events (from VirtIO tablet/mouse IRQ handler)
// ============================================================

const RAW_MOUSE_BUF_SIZE: usize = 64;

/// A raw mouse event from the tablet/mouse device.
#[derive(Clone, Copy)]
pub enum RawMouseEvent {
    Move { abs_x: u16, abs_y: u16 },
    ButtonDown { button: u8 },  // 0=Left, 1=Right, 2=Middle
    ButtonUp { button: u8 },
}

/// Ring buffer for raw mouse events.
pub struct RawMouseRingBuffer {
    buf: [RawMouseEvent; RAW_MOUSE_BUF_SIZE],
    head: usize,
    tail: usize,
}

impl RawMouseRingBuffer {
    pub const fn new() -> Self {
        RawMouseRingBuffer {
            buf: [RawMouseEvent::Move { abs_x: 0, abs_y: 0 }; RAW_MOUSE_BUF_SIZE],
            head: 0,
            tail: 0,
        }
    }

    pub fn push(&mut self, event: RawMouseEvent) -> bool {
        let next = (self.head + 1) % RAW_MOUSE_BUF_SIZE;
        if next != self.tail {
            self.buf[self.head] = event;
            self.head = next;
            true
        } else {
            false
        }
    }

    pub fn pop(&mut self) -> Option<RawMouseEvent> {
        if self.head == self.tail {
            None
        } else {
            let ev = self.buf[self.tail];
            self.tail = (self.tail + 1) % RAW_MOUSE_BUF_SIZE;
            Some(ev)
        }
    }
}

/// Raw mouse events ring buffer — filled by VirtIO tablet IRQ handler
pub static RAW_MOUSE_EVENTS: SpinLock<RawMouseRingBuffer> = SpinLock::new(RawMouseRingBuffer::new());

/// PID of the mouse server to wake when raw mouse events arrive (0 = none)
static RAW_MOUSE_WAKE_PID: SpinLock<usize> = SpinLock::new(0);

/// Push a raw mouse event from the IRQ handler.
pub fn push_raw_mouse_event(event: RawMouseEvent) {
    let ok = RAW_MOUSE_EVENTS.lock().push(event);
    if !ok {
        // Buffer full — drop silently (mouse events are high-frequency)
    }
    let pid = *RAW_MOUSE_WAKE_PID.lock();
    if pid != 0 {
        crate::task::wake_process(pid);
    }
}

/// Set the PID to wake when raw mouse events arrive.
pub fn set_raw_mouse_wake_pid(pid: usize) {
    *RAW_MOUSE_WAKE_PID.lock() = pid;
}

/// Raw UART putchar that bypasses the UART SpinLock.
/// Safe to call from interrupt context where interrupts are already disabled
/// and we are single-threaded on a single-hart system.
pub fn raw_uart_putchar(ch: u8) {
    let uart_base: *mut u8 = 0x1000_0000 as *mut u8;
    unsafe {
        // Wait for THR empty (LSR bit 5)
        while (uart_base.add(5).read_volatile() & (1 << 5)) == 0 {
            core::hint::spin_loop();
        }
        uart_base.write_volatile(ch);
    }
}

/// Initialize TTY subsystem.
pub fn init() {
    crate::println!("TTY initialized (ring buffers)");
}
