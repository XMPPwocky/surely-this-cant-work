use crate::mm::address::{PhysPageNum, PAGE_SIZE};
use crate::mm::frame;

// ELF64 constants
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_RISCV: u16 = 0xF3;
const PT_LOAD: u32 = 1;

/// ELF64 file header (64 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 program header (56 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

pub struct LoadedElf {
    pub code_ppn: PhysPageNum,  // first physical page of loaded program
    pub total_pages: usize,      // number of pages allocated
    #[allow(dead_code)]
    pub entry_pa: usize,         // physical address of entry point
    pub entry_va: usize,         // original virtual address of entry point
    pub base_va: usize,          // base virtual address of first PT_LOAD segment
}

/// Load an ELF64 binary. Allocates contiguous physical pages, copies
/// PT_LOAD segments, zeros .bss, and returns physical entry point.
/// Uses identity mapping (VA = PA for user pages).
pub fn load_elf(elf_data: &[u8]) -> Result<LoadedElf, &'static str> {
    if elf_data.len() < 64 {
        return Err("ELF too small");
    }

    // Parse header (manually to avoid alignment issues)
    let ehdr = parse_ehdr(elf_data)?;

    // Validate
    if ehdr.e_ident[0..4] != ELF_MAGIC {
        return Err("Bad ELF magic");
    }
    if ehdr.e_ident[4] != ELFCLASS64 {
        return Err("Not 64-bit ELF");
    }
    if ehdr.e_ident[5] != ELFDATA2LSB {
        return Err("Not little-endian");
    }
    if ehdr.e_machine != EM_RISCV {
        return Err("Not RISC-V");
    }

    // Find extent of all PT_LOAD segments
    let mut min_vaddr: u64 = u64::MAX;
    let mut max_vaddr: u64 = 0;

    let phdr_offset = ehdr.e_phoff as usize;
    let phdr_size = ehdr.e_phentsize as usize;
    let phdr_count = ehdr.e_phnum as usize;

    for i in 0..phdr_count {
        let off = phdr_offset + i * phdr_size;
        let phdr = parse_phdr(elf_data, off)?;
        if phdr.p_type == PT_LOAD {
            if phdr.p_vaddr < min_vaddr {
                min_vaddr = phdr.p_vaddr;
            }
            let end = phdr.p_vaddr + phdr.p_memsz;
            if end > max_vaddr {
                max_vaddr = end;
            }
        }
    }

    if min_vaddr == u64::MAX {
        return Err("No PT_LOAD segments");
    }

    let base_va = min_vaddr as usize;
    let total_size = (max_vaddr as usize) - base_va;
    let total_pages = (total_size + PAGE_SIZE - 1) / PAGE_SIZE;
    let total_pages = if total_pages == 0 { 1 } else { total_pages };

    // Allocate contiguous physical pages
    let code_ppn = frame::frame_alloc_contiguous(total_pages)
        .ok_or("Failed to allocate pages for ELF")?;
    let base_pa = code_ppn.0 * PAGE_SIZE;

    // Zero all allocated pages first (ensures clean .bss and padding)
    unsafe {
        core::ptr::write_bytes(base_pa as *mut u8, 0, total_pages * PAGE_SIZE);
    }

    // Copy each PT_LOAD segment
    for i in 0..phdr_count {
        let off = phdr_offset + i * phdr_size;
        let phdr = parse_phdr(elf_data, off)?;
        if phdr.p_type == PT_LOAD {
            let seg_offset = (phdr.p_vaddr as usize) - base_va;
            let dst = base_pa + seg_offset;
            let src_off = phdr.p_offset as usize;
            let filesz = phdr.p_filesz as usize;

            // Copy file data
            if filesz > 0 {
                if src_off + filesz > elf_data.len() {
                    return Err("ELF segment extends past file");
                }
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        elf_data[src_off..].as_ptr(),
                        dst as *mut u8,
                        filesz,
                    );
                }
            }
        }
    }

    // Compute entry point PA
    let entry_pa = base_pa + ((ehdr.e_entry as usize) - base_va);

    Ok(LoadedElf {
        code_ppn,
        total_pages,
        entry_pa,
        entry_va: ehdr.e_entry as usize,
        base_va,
    })
}

fn parse_ehdr(data: &[u8]) -> Result<Elf64Ehdr, &'static str> {
    if data.len() < 64 {
        return Err("Too small for ELF header");
    }
    let mut e_ident = [0u8; 16];
    e_ident.copy_from_slice(&data[0..16]);

    Ok(Elf64Ehdr {
        e_ident,
        e_type: u16::from_le_bytes([data[16], data[17]]),
        e_machine: u16::from_le_bytes([data[18], data[19]]),
        e_version: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
        e_entry: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        e_phoff: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        e_shoff: u64::from_le_bytes(data[40..48].try_into().unwrap()),
        e_flags: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
        e_ehsize: u16::from_le_bytes([data[52], data[53]]),
        e_phentsize: u16::from_le_bytes([data[54], data[55]]),
        e_phnum: u16::from_le_bytes([data[56], data[57]]),
        e_shentsize: u16::from_le_bytes([data[58], data[59]]),
        e_shnum: u16::from_le_bytes([data[60], data[61]]),
        e_shstrndx: u16::from_le_bytes([data[62], data[63]]),
    })
}

fn parse_phdr(data: &[u8], offset: usize) -> Result<Elf64Phdr, &'static str> {
    if offset + 56 > data.len() {
        return Err("Phdr extends past ELF data");
    }
    let d = &data[offset..];
    Ok(Elf64Phdr {
        p_type: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
        p_flags: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
        p_offset: u64::from_le_bytes(d[8..16].try_into().unwrap()),
        p_vaddr: u64::from_le_bytes(d[16..24].try_into().unwrap()),
        p_paddr: u64::from_le_bytes(d[24..32].try_into().unwrap()),
        p_filesz: u64::from_le_bytes(d[32..40].try_into().unwrap()),
        p_memsz: u64::from_le_bytes(d[40..48].try_into().unwrap()),
        p_align: u64::from_le_bytes(d[48..56].try_into().unwrap()),
    })
}
