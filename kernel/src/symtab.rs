//! Embedded symbol table for runtime backtrace symbolization.
//!
//! A two-pass build embeds the table:
//!   1. First cargo build (ksymtab.bin = 4 zero bytes → count=0)
//!   2. `gen_symtab.py` extracts symbols from the ELF → `kernel/ksymtab.bin`
//!   3. Second cargo build picks up the real data via `include_bytes!`
//!
//! Binary format (little-endian):
//!   count: u32
//!   entries[count]: { addr: u64, name_off: u32, name_len: u16, _pad: u16 }
//!   string table: concatenated UTF-8 names

static SYMTAB_DATA: &[u8] = include_bytes!("../ksymtab.bin");

/// Size of one entry: u64 + u32 + u16 + u16 = 16 bytes.
const ENTRY_SIZE: usize = 16;

/// Header size: u32 count = 4 bytes.
const HEADER_SIZE: usize = 4;

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off], data[off + 1], data[off + 2], data[off + 3],
        data[off + 4], data[off + 5], data[off + 6], data[off + 7],
    ])
}

/// Resolve an address to the nearest symbol name and offset.
///
/// Returns `Some((name, offset))` where `name` is the mangled symbol name
/// and `offset` is the byte distance from the symbol start.
pub fn resolve(addr: usize) -> Option<(&'static str, usize)> {
    let data = SYMTAB_DATA;
    if data.len() < HEADER_SIZE {
        return None;
    }

    let count = read_u32(data, 0) as usize;
    if count == 0 {
        return None;
    }

    let entries_start = HEADER_SIZE;
    let strtab_start = entries_start + count * ENTRY_SIZE;
    if strtab_start > data.len() {
        return None;
    }

    // Binary search: find the last entry whose addr <= target
    let target = addr as u64;
    let mut lo: usize = 0;
    let mut hi: usize = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_off = entries_start + mid * ENTRY_SIZE;
        let sym_addr = read_u64(data, entry_off);
        if sym_addr <= target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if lo == 0 {
        return None;
    }

    let idx = lo - 1;
    let entry_off = entries_start + idx * ENTRY_SIZE;
    let sym_addr = read_u64(data, entry_off) as usize;
    let name_off = read_u32(data, entry_off + 8) as usize;
    let name_len = read_u16(data, entry_off + 12) as usize;

    let str_start = strtab_start + name_off;
    let str_end = str_start + name_len;
    if str_end > data.len() {
        return None;
    }

    let name = core::str::from_utf8(&data[str_start..str_end]).ok()?;
    let offset = addr - sym_addr;

    // Reject matches unreasonably far from the symbol start
    if offset > 0x10000 {
        return None;
    }

    Some((name, offset))
}
