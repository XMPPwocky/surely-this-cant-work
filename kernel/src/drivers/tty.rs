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
