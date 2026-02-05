use core::fmt;
use crate::sync::SpinLock;

const UART_BASE: usize = 0x1000_0000;

// UART 16550 register offsets
const RBR: usize = 0; // Receive Buffer Register (read)
const THR: usize = 0; // Transmitter Holding Register (write)
const IER: usize = 1; // Interrupt Enable Register
const FCR: usize = 2; // FIFO Control Register (write)
const LCR: usize = 3; // Line Control Register
const LSR: usize = 5; // Line Status Register

// LSR bits
const LSR_DATA_READY: u8 = 1 << 0;
const LSR_THR_EMPTY: u8 = 1 << 5;

// LCR bits
const LCR_DLAB: u8 = 1 << 7;
const LCR_8BIT: u8 = 0b11;

pub struct Uart {
    base: usize,
}

impl Uart {
    pub const fn new(base: usize) -> Self {
        Uart { base }
    }

    fn read_reg(&self, offset: usize) -> u8 {
        let ptr = (self.base + offset) as *const u8;
        unsafe { ptr.read_volatile() }
    }

    fn write_reg(&self, offset: usize, val: u8) {
        let ptr = (self.base + offset) as *mut u8;
        unsafe { ptr.write_volatile(val) }
    }

    pub fn init(&self) {
        // Disable interrupts
        self.write_reg(IER, 0x00);

        // Enable DLAB to set baud rate divisor
        self.write_reg(LCR, LCR_DLAB);

        // Set divisor to 3 (38400 baud with 1.8432 MHz clock)
        self.write_reg(0, 0x03); // DLL
        self.write_reg(1, 0x00); // DLM

        // 8 bits, no parity, 1 stop bit, disable DLAB
        self.write_reg(LCR, LCR_8BIT);

        // Enable FIFO, clear TX/RX, 14-byte threshold
        self.write_reg(FCR, 0xC7);

        // Enable receive interrupts
        self.write_reg(IER, 0x01);
    }

    pub fn putchar(&self, ch: u8) {
        // Wait for THR to be empty
        while self.read_reg(LSR) & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        self.write_reg(THR, ch);
    }

    pub fn getchar(&self) -> Option<u8> {
        if self.read_reg(LSR) & LSR_DATA_READY != 0 {
            Some(self.read_reg(RBR))
        } else {
            None
        }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.putchar(byte);
        }
        Ok(())
    }
}

pub static UART: SpinLock<Uart> = SpinLock::new(Uart::new(UART_BASE));

pub fn init() {
    UART.lock().init();
}
