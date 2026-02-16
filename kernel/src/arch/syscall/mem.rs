//! Memory mapping syscalls: mmap, munmap, shm_create, shm_dup_ro, meminfo.

use crate::task::{HandleObject, HandleInfo};
use super::validate_user_buffer;

/// SYS_SHM_CREATE: create a shared memory region and return a RW handle.
pub fn sys_shm_create(size: usize) -> usize {
    if size == 0 {
        return usize::MAX;
    }

    let page_count = size.div_ceil(crate::mm::address::PAGE_SIZE);

    let ppn = match crate::mm::frame::frame_alloc_contiguous(page_count) {
        Some(ppn) => ppn,
        None => return usize::MAX,
    };

    let base_pa = ppn.0 * crate::mm::address::PAGE_SIZE;
    crate::println!("[shm_create] PID {} pages={} range={:#x}..{:#x} (ppn {:#x}..{:#x})",
        crate::task::current_pid(), page_count, base_pa, base_pa + page_count * crate::mm::address::PAGE_SIZE,
        ppn.0, ppn.0 + page_count);

    unsafe {
        core::ptr::write_bytes(base_pa as *mut u8, 0, page_count * crate::mm::address::PAGE_SIZE);
    }

    let shm = match crate::ipc::shm_create(ppn, page_count) {
        Some(owned) => owned,
        None => {
            for i in 0..page_count {
                crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + i));
            }
            return usize::MAX;
        }
    };

    // alloc_handle takes ownership. On None, shm drops → auto dec_ref.
    match crate::task::current_process_alloc_handle(HandleObject::Shm { owned: shm, rw: true }) {
        Some(local_handle) => local_handle,
        None => usize::MAX,
    }
}

/// SYS_SHM_DUP_RO: duplicate a SHM handle as read-only.
pub fn sys_shm_dup_ro(handle: usize) -> usize {
    let shm_id = match crate::task::current_process_handle(handle) {
        Some(HandleInfo::Shm { id, .. }) => id,
        _ => return usize::MAX,
    };

    // Create new owned reference (inc_ref via clone_from_raw)
    let owned = crate::ipc::OwnedShm::clone_from_raw(shm_id);

    // alloc_handle takes ownership. On None, owned drops → auto dec_ref.
    match crate::task::current_process_alloc_handle(HandleObject::Shm { owned, rw: false }) {
        Some(local_handle) => local_handle,
        None => usize::MAX,
    }
}

/// SYS_MMAP: map pages into process address space.
/// a0 == 0: anonymous mapping (allocate fresh pages)
/// a0 != 0: SHM handle mapping (map shared region)
pub fn sys_mmap(shm_handle: usize, length: usize) -> usize {
    if length == 0 {
        return usize::MAX;
    }

    if shm_handle == 0 {
        sys_mmap_anonymous(length)
    } else {
        sys_mmap_shm(shm_handle, length)
    }
}

fn sys_mmap_anonymous(length: usize) -> usize {
    let pages = length.div_ceil(crate::mm::address::PAGE_SIZE);

    let ppn = match crate::mm::frame::frame_alloc_contiguous(pages) {
        Some(ppn) => ppn,
        None => return usize::MAX,
    };

    let base_pa = ppn.0 * crate::mm::address::PAGE_SIZE;

    unsafe {
        core::ptr::write_bytes(base_pa as *mut u8, 0, pages * crate::mm::address::PAGE_SIZE);
    }

    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        for i in 0..pages {
            crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + i));
        }
        return usize::MAX;
    }

    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);

    for i in 0..pages {
        let vpn = crate::mm::address::VirtPageNum(ppn.0 + i);
        let page_ppn = crate::mm::address::PhysPageNum(ppn.0 + i);
        if pt.map(vpn, page_ppn,
            crate::mm::page_table::PTE_R |
            crate::mm::page_table::PTE_W |
            crate::mm::page_table::PTE_U).is_err()
        {
            let mut pt2 = crate::mm::page_table::PageTable::from_root(root_ppn);
            for j in 0..i {
                pt2.unmap(crate::mm::address::VirtPageNum(ppn.0 + j));
            }
            for k in 0..pages {
                crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + k));
            }
            unsafe { core::arch::asm!("sfence.vma"); }
            return usize::MAX;
        }
    }

    if !crate::task::current_process_add_mmap(ppn.0, pages, None) {
        let mut pt2 = crate::mm::page_table::PageTable::from_root(root_ppn);
        for i in 0..pages {
            pt2.unmap(crate::mm::address::VirtPageNum(ppn.0 + i));
            crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(ppn.0 + i));
        }
        unsafe { core::arch::asm!("sfence.vma"); }
        return usize::MAX;
    }

    unsafe { core::arch::asm!("sfence.vma"); }

    crate::task::current_process_adjust_mem_pages(pages as i32);

    base_pa
}

fn sys_mmap_shm(shm_handle: usize, length: usize) -> usize {
    let (shm_id, rw) = match crate::task::current_process_handle(shm_handle) {
        Some(HandleInfo::Shm { id, rw }) => (id, rw),
        _ => return usize::MAX,
    };

    let (base_ppn, region_page_count) = match crate::ipc::shm_get_info(shm_id) {
        Some(info) => info,
        None => return usize::MAX,
    };

    let map_pages = length.div_ceil(crate::mm::address::PAGE_SIZE);

    if map_pages > region_page_count {
        return usize::MAX;
    }

    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        return usize::MAX;
    }

    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);

    let flags = if rw {
        crate::mm::page_table::PTE_R | crate::mm::page_table::PTE_W | crate::mm::page_table::PTE_U
    } else {
        crate::mm::page_table::PTE_R | crate::mm::page_table::PTE_U
    };

    crate::println!("[mmap_shm] PID {} shm={} pages={} range={:#x}..{:#x}",
        crate::task::current_pid(), shm_id, map_pages,
        base_ppn.0 * crate::mm::address::PAGE_SIZE,
        (base_ppn.0 + map_pages) * crate::mm::address::PAGE_SIZE);

    for i in 0..map_pages {
        let vpn = crate::mm::address::VirtPageNum(base_ppn.0 + i);
        let page_ppn = crate::mm::address::PhysPageNum(base_ppn.0 + i);
        if pt.map(vpn, page_ppn, flags).is_err() {
            let mut pt2 = crate::mm::page_table::PageTable::from_root(root_ppn);
            for j in 0..i {
                pt2.unmap(crate::mm::address::VirtPageNum(base_ppn.0 + j));
            }
            unsafe { core::arch::asm!("sfence.vma"); }
            return usize::MAX;
        }
    }

    if !crate::task::current_process_add_mmap(base_ppn.0, map_pages, Some(shm_id)) {
        let mut pt2 = crate::mm::page_table::PageTable::from_root(root_ppn);
        for i in 0..map_pages {
            pt2.unmap(crate::mm::address::VirtPageNum(base_ppn.0 + i));
        }
        unsafe { core::arch::asm!("sfence.vma"); }
        return usize::MAX;
    }

    unsafe { core::arch::asm!("sfence.vma"); }

    crate::task::current_process_adjust_mem_pages(map_pages as i32);

    base_ppn.0 * crate::mm::address::PAGE_SIZE
}

pub fn sys_munmap(addr: usize, length: usize) -> usize {
    if length == 0 || !addr.is_multiple_of(crate::mm::address::PAGE_SIZE) {
        return usize::MAX;
    }

    let pages = length.div_ceil(crate::mm::address::PAGE_SIZE);
    let base_ppn = addr / crate::mm::address::PAGE_SIZE;

    let shm_id = match crate::task::current_process_remove_mmap(base_ppn, pages) {
        Some(shm_id) => shm_id,
        None => return usize::MAX,
    };

    let user_satp = crate::task::current_process_user_satp();
    if user_satp == 0 {
        return usize::MAX;
    }

    let root_ppn = crate::mm::address::PhysPageNum(user_satp & ((1usize << 44) - 1));
    let mut pt = crate::mm::page_table::PageTable::from_root(root_ppn);

    for i in 0..pages {
        let vpn = crate::mm::address::VirtPageNum(base_ppn + i);
        pt.unmap(vpn);
        if shm_id.is_none() {
            crate::mm::frame::frame_dealloc(crate::mm::address::PhysPageNum(base_ppn + i));
        }
    }

    crate::task::current_process_adjust_mem_pages(-(pages as i32));

    unsafe { core::arch::asm!("sfence.vma"); }

    0
}

/// SYS_MEMINFO: fill a user-space MemInfo struct with kernel memory statistics.
pub fn sys_meminfo(buf_ptr: usize) -> usize {
    let pa = match validate_user_buffer(buf_ptr, 5 * core::mem::size_of::<usize>()) {
        Some(pa) => pa,
        None => return usize::MAX,
    };
    let (_tags, _count, heap_used) = crate::mm::heap::heap_stats();
    let heap_total = crate::mm::heap::heap_total_size();
    let frames_used = crate::mm::frame::frames_allocated();
    let frames_total = crate::mm::frame::frames_total();
    let proc_mem_pages = crate::task::current_process_mem_pages() as usize;
    let out = pa as *mut usize;
    unsafe {
        out.write(heap_used);
        out.add(1).write(heap_total);
        out.add(2).write(frames_used);
        out.add(3).write(frames_total);
        out.add(4).write(proc_mem_pages);
    }
    0
}
