# 0015: fbcon crashes at startup — SHM identity-map collides with user stack

**Reported:** 2026-02-20
**Status:** Open
**Severity:** HIGH
**Subsystem:** mm (kernel memory management, `sys_mmap_shm`)

## Symptoms

Running `make run-vnc` produces a page fault that kills fbcon (PID 16):

```
Page fault (store/AMO): sepc=0x1fd6e, stval=0x819e45b8, SPP=0 (U-mode)
  sstatus=0x200040020 ra=0x1a6ae sp=0x819e4550
  s0=0x24700 s1=0x3 s2=0x12165
  current_pid=16
  Killing user process due to page fault
```

Key observations:
- `stval=0x819e45b8` (faulting write address) is only **0x68 bytes above**
  `sp=0x819e4550` (stack pointer) — the fault is at a valid stack address,
  meaning the stack's page table entries have been corrupted or overwritten.
- The fault is a **store/AMO** in U-mode — a write to a page that is either
  unmapped or mapped read-only.

## Reproduction Steps

1. `make run-vnc`
2. Observe the page fault in serial output — fbcon crashes at startup.

## Root Cause

`sys_mmap_shm()` in `kernel/src/arch/syscall/mem.rs:131-192` maps SHM
pages using **identity mapping** (VA = PA):

```rust
// mem.rs:165-167
for i in 0..map_pages {
    let vpn = VirtPageNum(base_ppn.0 + i);   // VA = PA
    let page_ppn = PhysPageNum(base_ppn.0 + i);
    pt.map(vpn, page_ppn, flags)?;
}
```

The SHM for the double-buffered framebuffer is **6 MB** (1024 × 768 × 4 × 2
= 6,291,456 bytes = 1536 pages). When the frame allocator returns physical
pages whose addresses happen to overlap with fbcon's user stack virtual address
range (`~0x819e0000..0x819e8000`, 32 KiB = 8 pages), the identity mapping
**overwrites the stack's page table entries** with SHM entries.

After `sys_mmap_shm` returns, the stack's VA range now points to SHM physical
pages (or is unmapped if `pt.map()` replaces entries). When fbcon's
`FbConsole::new()` (`user/fbcon/src/main.rs:92-112`) attempts to clear the
back buffer in a loop:

```rust
let total = (stride * height) as usize;
for i in 0..total {
    unsafe { *fb.add(i) = 0xFF000000; }  // loop uses stack for locals/spills
}
```

…any stack access (loop counter spill, function call frame) hits the corrupted
PTEs and faults.

**Bug class:** Memory corruption — virtual address space collision due to
identity mapping without collision checking.

**Fundamental cause:** The kernel has no virtual address space allocator for
user processes. All mappings (code, stack, SHM, future mmap) are identity-
mapped, meaning any two physical allocations whose addresses overlap in the
64-bit virtual space will collide. With a 6 MB SHM allocation, the probability
of hitting the 32 KiB stack is significant.

## Fix

(To be determined — likely needs a user-space VA allocator or at minimum a
collision check in `sys_mmap_shm`.)

Potential approaches:
1. **Minimal fix:** In `sys_mmap_shm`, check each VPN against existing mappings
   before writing. If collision detected, return error (user-space retries are
   not possible with identity mapping, so this is just a safety net).
2. **Proper fix:** Allocate SHM at a dedicated VA region (e.g., above the stack)
   rather than identity-mapping. This requires a per-process VA allocator or at
   least a bump pointer for mmap regions.
3. **Alternative:** Reserve a fixed VA range for mmap/SHM (e.g.,
   `0x40000000..0x80000000`) and map SHM pages there instead of at PA=VA.

## Verification

(To be filled after fix)

## Lessons Learned

(To be filled after fix)
