// PLIC (Platform-Level Interrupt Controller) for QEMU virt machine
// Base address: 0x0C000000

const PLIC_BASE: usize = 0x0C00_0000;

// Register offsets
// Priority: base + 4 * source_id
const PLIC_PRIORITY_BASE: usize = PLIC_BASE;
// Enable bits for context 1 (S-mode, hart 0)
const PLIC_ENABLE_BASE: usize = PLIC_BASE + 0x2080;
// Threshold for context 1
const PLIC_THRESHOLD: usize = PLIC_BASE + 0x20_1000;
// Claim/complete for context 1
const PLIC_CLAIM: usize = PLIC_BASE + 0x20_1004;

const UART_IRQ: u32 = 10;

fn write_reg(addr: usize, val: u32) {
    unsafe { (addr as *mut u32).write_volatile(val); }
}

fn read_reg(addr: usize) -> u32 {
    unsafe { (addr as *const u32).read_volatile() }
}

pub fn init() {
    // Set UART IRQ priority to 1
    write_reg(PLIC_PRIORITY_BASE + 4 * UART_IRQ as usize, 1);

    // Enable UART IRQ for context 1 (S-mode, hart 0)
    // IRQ 10 is in the first 32-bit word (bit 10)
    let enable_word = read_reg(PLIC_ENABLE_BASE);
    write_reg(PLIC_ENABLE_BASE, enable_word | (1 << UART_IRQ));

    // Set threshold to 0 (accept all priorities > 0)
    write_reg(PLIC_THRESHOLD, 0);

    crate::println!("PLIC initialized (UART IRQ {} enabled)", UART_IRQ);
}

/// Enable an additional IRQ (set priority and enable bit).
pub fn enable_irq(irq: u32) {
    // Set priority to 1
    write_reg(PLIC_PRIORITY_BASE + 4 * irq as usize, 1);
    // Enable the IRQ bit
    let word_idx = irq / 32;
    let bit_idx = irq % 32;
    let addr = PLIC_ENABLE_BASE + (word_idx as usize) * 4;
    let current = read_reg(addr);
    write_reg(addr, current | (1 << bit_idx));
}

pub fn plic_claim() -> u32 {
    read_reg(PLIC_CLAIM)
}

pub fn plic_complete(irq: u32) {
    write_reg(PLIC_CLAIM, irq);
}
