#[macro_export]
macro_rules! read_csr {
    ($reg:literal) => {{
        let val: usize;
        unsafe {
            core::arch::asm!(
                concat!("csrr {0}, ", $reg),
                out(reg) val,
                options(nomem, nostack),
            );
        }
        val
    }};
}

#[macro_export]
macro_rules! write_csr {
    ($reg:literal, $val:expr) => {{
        let v: usize = $val;
        unsafe {
            core::arch::asm!(
                concat!("csrw ", $reg, ", {0}"),
                in(reg) v,
                options(nomem, nostack),
            );
        }
    }};
}

#[macro_export]
macro_rules! set_csr {
    ($reg:literal, $val:expr) => {{
        let v: usize = $val;
        unsafe {
            core::arch::asm!(
                concat!("csrs ", $reg, ", {0}"),
                in(reg) v,
                options(nomem, nostack),
            );
        }
    }};
}

#[macro_export]
macro_rules! clear_csr {
    ($reg:literal, $val:expr) => {{
        let v: usize = $val;
        unsafe {
            core::arch::asm!(
                concat!("csrc ", $reg, ", {0}"),
                in(reg) v,
                options(nomem, nostack),
            );
        }
    }};
}

// SSTATUS bits
pub const SSTATUS_SIE: usize = 1 << 1;
pub const SSTATUS_SPIE: usize = 1 << 5;
pub const SSTATUS_SPP: usize = 1 << 8;
pub const SSTATUS_SUM: usize = 1 << 18;

#[inline(always)]
pub fn read_sstatus() -> usize {
    read_csr!("sstatus")
}

#[inline(always)]
pub fn read_scause() -> usize {
    read_csr!("scause")
}

#[inline(always)]
pub fn read_stval() -> usize {
    read_csr!("stval")
}

#[inline(always)]
pub fn read_sepc() -> usize {
    read_csr!("sepc")
}

#[inline(always)]
pub fn read_tp() -> usize {
    read_csr!("tp")
}

#[inline(always)]
pub fn write_stvec(val: usize) {
    write_csr!("stvec", val);
}

#[inline(always)]
pub fn write_satp(val: usize) {
    write_csr!("satp", val);
}

#[inline(always)]
pub fn write_sscratch(val: usize) {
    write_csr!("sscratch", val);
}

#[inline(always)]
pub fn write_sepc(val: usize) {
    write_csr!("sepc", val);
}

#[inline(always)]
pub fn disable_interrupts() {
    clear_csr!("sstatus", SSTATUS_SIE);
}

#[inline(always)]
pub fn enable_interrupts() {
    set_csr!("sstatus", SSTATUS_SIE);
}

#[inline(always)]
pub fn interrupts_enabled() -> bool {
    read_sstatus() & SSTATUS_SIE != 0
}
