// PLIC (Platform-Level Interrupt Controller)
// Base address and context read from FDT via platform module.

use crate::platform;

fn plic_base() -> usize { platform::plic_base() }
fn plic_context() -> u32 { platform::plic_context() }

fn priority_addr(source: u32) -> usize {
    plic_base() + 4 * source as usize
}

fn enable_addr() -> usize {
    // Enable register base for this context: base + 0x2000 + context*0x80
    plic_base() + 0x2000 + plic_context() as usize * 0x80
}

fn threshold_addr() -> usize {
    // Threshold register: base + 0x20_0000 + context*0x1000
    plic_base() + 0x20_0000 + plic_context() as usize * 0x1000
}

fn claim_addr() -> usize {
    threshold_addr() + 4
}

fn write_reg(addr: usize, val: u32) {
    unsafe { (addr as *mut u32).write_volatile(val); }
}

fn read_reg(addr: usize) -> u32 {
    unsafe { (addr as *const u32).read_volatile() }
}

pub fn init() {
    let uart_irq = platform::uart_irq();

    // Set UART IRQ priority to 1
    write_reg(priority_addr(uart_irq), 1);

    // Enable UART IRQ for this context
    let word_idx = uart_irq / 32;
    let bit_idx = uart_irq % 32;
    let addr = enable_addr() + (word_idx as usize) * 4;
    let current = read_reg(addr);
    write_reg(addr, current | (1 << bit_idx));

    // Set threshold to 0 (accept all priorities > 0)
    write_reg(threshold_addr(), 0);

    crate::println!("PLIC initialized (UART IRQ {} enabled, context {})",
        uart_irq, plic_context());
}

/// Enable an additional IRQ (set priority and enable bit).
pub fn enable_irq(irq: u32) {
    // Set priority to 1
    write_reg(priority_addr(irq), 1);
    // Enable the IRQ bit
    let word_idx = irq / 32;
    let bit_idx = irq % 32;
    let addr = enable_addr() + (word_idx as usize) * 4;
    let current = read_reg(addr);
    write_reg(addr, current | (1 << bit_idx));
}

pub fn plic_claim() -> u32 {
    read_reg(claim_addr())
}

pub fn plic_complete(irq: u32) {
    write_reg(claim_addr(), irq);
}
