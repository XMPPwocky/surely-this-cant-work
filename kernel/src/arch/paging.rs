use crate::mm::address::{PhysPageNum, PAGE_SIZE};
use crate::mm::page_table::{PageTable, PTE_R, PTE_W, PTE_X};
use crate::println;

/// Set up the kernel page table with identity mappings.
/// Returns the root page table's PhysPageNum.
pub fn init_kernel_page_table() -> PhysPageNum {
    extern "C" {
        static _text_start: u8;
        static _text_end: u8;
        static _rodata_start: u8;
        static _rodata_end: u8;
        static _data_start: u8;
        fn _stack_top();
    }

    let text_start = unsafe { &_text_start as *const u8 as usize };
    let text_end = unsafe { &_text_end as *const u8 as usize };
    let rodata_start = unsafe { &_rodata_start as *const u8 as usize };
    let rodata_end = unsafe { &_rodata_end as *const u8 as usize };
    let data_start = unsafe { &_data_start as *const u8 as usize };
    let stack_top = _stack_top as *const () as usize;

    let mut pt = PageTable::new();

    // Identity-map SBI region: 0x8000_0000..0x8020_0000 as R+X
    println!("  Mapping SBI:    {:#x}..{:#x} (R+X)", 0x8000_0000usize, text_start);
    pt.map_range(0x8000_0000, 0x8000_0000, text_start - 0x8000_0000, PTE_R | PTE_X);

    // Identity-map kernel text as R+X
    let text_size = text_end - text_start;
    println!("  Mapping text:   {:#x}..{:#x} (R+X)", text_start, text_end);
    pt.map_range(text_start, text_start, text_size, PTE_R | PTE_X);

    // Identity-map rodata as R
    let rodata_size = rodata_end - rodata_start;
    println!("  Mapping rodata: {:#x}..{:#x} (R)", rodata_start, rodata_end);
    pt.map_range(rodata_start, rodata_start, rodata_size, PTE_R);

    // Identity-map data + bss + stack as R+W
    let data_size = stack_top - data_start;
    println!("  Mapping data:   {:#x}..{:#x} (R+W)", data_start, stack_top);
    pt.map_range(data_start, data_start, data_size, PTE_R | PTE_W);

    // Identity-map free memory from stack_top to 0x88000000
    let free_start = (stack_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let free_size = 0x8800_0000 - free_start;
    println!("  Mapping free:   {:#x}..{:#x} (R+W)", free_start, 0x8800_0000usize);
    pt.map_range(free_start, free_start, free_size, PTE_R | PTE_W);

    // Identity-map UART: 0x1000_0000 (one page)
    println!("  Mapping UART:   {:#x} (R+W)", 0x1000_0000usize);
    pt.map_range(0x1000_0000, 0x1000_0000, PAGE_SIZE, PTE_R | PTE_W);

    // Identity-map PLIC: 0x0C00_0000..0x1000_0000
    println!("  Mapping PLIC:   {:#x}..{:#x} (R+W)", 0x0C00_0000usize, 0x1000_0000usize);
    pt.map_range(0x0C00_0000, 0x0C00_0000, 0x0400_0000, PTE_R | PTE_W);

    // Identity-map CLINT: 0x0200_0000..0x0201_0000
    println!("  Mapping CLINT:  {:#x}..{:#x} (R+W)", 0x0200_0000usize, 0x0201_0000usize);
    pt.map_range(0x0200_0000, 0x0200_0000, 0x0001_0000, PTE_R | PTE_W);

    // Identity-map VirtIO: 0x1000_1000..0x1000_9000
    println!("  Mapping VirtIO: {:#x}..{:#x} (R+W)", 0x1000_1000usize, 0x1000_9000usize);
    pt.map_range(0x1000_1000, 0x1000_1000, 0x0000_8000, PTE_R | PTE_W);

    pt.root_ppn()
}

/// Enable Sv39 paging by writing to satp and flushing the TLB.
pub fn enable_paging(root_ppn: PhysPageNum) {
    let satp_val = (8usize << 60) | root_ppn.0;
    unsafe {
        core::arch::asm!("sfence.vma");
        crate::arch::csr::write_satp(satp_val);
        core::arch::asm!("sfence.vma");
    }
}
