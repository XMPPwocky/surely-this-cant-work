use crate::mm::address::{PhysPageNum, PAGE_SIZE};
use crate::mm::page_table::{PageTable, PTE_R, PTE_W, PTE_X};
use crate::platform;
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

    let ram_base = platform::ram_base();
    let ram_end = platform::ram_end();
    let plat = platform::info();

    let mut pt = PageTable::new().expect("boot: page table root");

    // Identity-map SBI region: ram_base..text_start as R+X
    println!("  Mapping SBI:    {:#x}..{:#x} (R+X)", ram_base, text_start);
    pt.map_range(ram_base, ram_base, text_start - ram_base, PTE_R | PTE_X).expect("boot: map SBI");

    // Identity-map kernel text as R+X
    let text_size = text_end - text_start;
    println!("  Mapping text:   {:#x}..{:#x} (R+X)", text_start, text_end);
    pt.map_range(text_start, text_start, text_size, PTE_R | PTE_X).expect("boot: map text");

    // Identity-map rodata as R
    let rodata_size = rodata_end - rodata_start;
    println!("  Mapping rodata: {:#x}..{:#x} (R)", rodata_start, rodata_end);
    pt.map_range(rodata_start, rodata_start, rodata_size, PTE_R).expect("boot: map rodata");

    // Identity-map data + bss + stack as R+W
    let data_size = stack_top - data_start;
    println!("  Mapping data:   {:#x}..{:#x} (R+W)", data_start, stack_top);
    pt.map_range(data_start, data_start, data_size, PTE_R | PTE_W).expect("boot: map data");

    // Identity-map free memory from stack_top to ram_end
    let free_start = (stack_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let free_size = ram_end - free_start;
    println!("  Mapping free:   {:#x}..{:#x} (R+W)", free_start, ram_end);
    pt.map_range(free_start, free_start, free_size, PTE_R | PTE_W).expect("boot: map free");

    // Identity-map UART (one page)
    println!("  Mapping UART:   {:#x} (R+W)", plat.uart_base);
    pt.map_range(plat.uart_base, plat.uart_base, PAGE_SIZE, PTE_R | PTE_W).expect("boot: map UART");

    // Identity-map PLIC
    println!("  Mapping PLIC:   {:#x}..{:#x} (R+W)", plat.plic_base, plat.plic_base + plat.plic_size);
    pt.map_range(plat.plic_base, plat.plic_base, plat.plic_size, PTE_R | PTE_W).expect("boot: map PLIC");

    // Identity-map CLINT
    println!("  Mapping CLINT:  {:#x}..{:#x} (R+W)", plat.clint_base, plat.clint_base + plat.clint_size);
    pt.map_range(plat.clint_base, plat.clint_base, plat.clint_size, PTE_R | PTE_W).expect("boot: map CLINT");

    // Identity-map VirtIO MMIO devices (one page each)
    if plat.virtio_mmio_count > 0 {
        for i in 0..plat.virtio_mmio_count {
            let base = plat.virtio_mmio[i].base;
            pt.map_range(base, base, PAGE_SIZE, PTE_R | PTE_W).expect("boot: map VirtIO");
        }
        let mut lo = plat.virtio_mmio[0].base;
        let mut hi = lo;
        for i in 1..plat.virtio_mmio_count {
            let b = plat.virtio_mmio[i].base;
            if b < lo { lo = b; }
            if b > hi { hi = b; }
        }
        println!("  Mapping VirtIO: {:#x}..{:#x} (R+W, {} slot(s))",
            lo, hi + PAGE_SIZE, plat.virtio_mmio_count);
    }

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
