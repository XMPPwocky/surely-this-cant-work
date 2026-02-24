# 0015: fbcon crashes at startup — SHM identity-map + stack overflow

**Reported:** 2026-02-20
**Status:** Closed (2026-02-20)
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

## Reproduction Steps

1. `make run-vnc`
2. Observe the page fault in serial output — fbcon crashes at startup.

## Investigation

The initial analysis (from a subagent that read the crash dump and kernel source)
concluded that the fault at `stval=0x819e45b8` — only 0x68 bytes above
`sp=0x819e4550` — was caused by SHM identity-mapping collision: `sys_mmap_shm()`
allocated physical frames whose addresses (used directly as VAs) overlapped the
user stack's virtual range, and `pt.map()` silently overwrote the stack PTEs.
That analysis was plausible and the identity-mapping design flaw was real
(confirmed in `kernel/src/arch/syscall/mem.rs:166`).

A fix was implemented and committed (`a989d50`): a per-process bump-pointer VA
allocator starting at `MMAP_VA_BASE = 0x4000_0000` so mmap/SHM regions would no
longer identity-map and could not overlap with the stack at `0x8000_0000+`.

After that fix, `make run-vnc` was run with an expect script to verify. fbcon
still crashed with a nearly identical fault:

```
Page fault (store/AMO): sepc=0x1fd6e, stval=0x819ea5b8, SPP=0 (U-mode)
  sstatus=0x200040020 ra=0x1a6ae sp=0x819ea550
  current_pid=16
```

The SHM for net-stack now appeared at `0x40005000` (confirming the VA allocator
was working), but fbcon still died. Investigating why the stack-area fault
persisted led to examining the page table more carefully — `pt.map()` overwrites
silently, so a collision from a different source was considered.

To narrow it down, PTE inspection and stack-range display were added to the
page fault handler (`kernel/src/arch/trap.rs`):

```rust
match pt.translate(faulting_vpn) {
    Some(ppn) => crate::println!("  PTE exists: vpn={:#x} -> ppn={:#x}", ...),
    None      => crate::println!("  PTE missing for vpn={:#x}", faulting_vpn.0),
}
crate::println!("  user_stack_top={:#x}", stack_top_va);
```

The instrumented kernel produced:

```
PTE missing for vpn=0x819ea
user_stack_top=0x819f4000
```

This was the turning point. The stack range was `0x819ec000..0x819f4000`
(32 KiB, 8 pages), but `sp=0x819ea550` was 5 KB *below* the stack base —
the stack had overflowed its allocation. The page at `0x819ea000` was not
mapped with the U bit (it was part of the kernel identity-map without U),
causing the U-mode store fault.

Notably, the crash happened before `[fbcon] starting` was ever printed,
meaning the overflow occurred in the Rust std runtime initialization
(argument parsing, stdio setup, `connect_to_service` × 2) before `main()`
was even reached. Analysis of the call chain showed that each IPC round-trip
(`connect_to_service`, `Channel::send/recv`, `WindowClient` RPCs) places one
or two 1080-byte `Message` structs on the stack — quickly accumulating past
the 32 KiB limit for deeply nested initialization.

The original SHM identity-mapping bug was a separate design flaw that did
exist and has been fixed, but it was not the immediate crash trigger in this
run — the stack overflow was.

## Root Cause

**Two issues combined:**

### Issue 1: SHM identity mapping (design flaw)

`sys_mmap_shm()` and `sys_mmap_anonymous()` mapped pages using identity
mapping (VA = PA). With large allocations like the 6 MB framebuffer SHM,
the physical addresses could collide with existing user-space mappings
(code, stack). The `pt.map()` function silently overwrites existing PTEs.

### Issue 2: User stack overflow (the actual crash trigger)

After adding debug instrumentation to the page fault handler, the real
crash was identified as a **stack overflow**:

```
  PTE missing for vpn=0x819ea
  user_stack_top=0x819f4000
```

The stack range was `0x819ec000..0x819f4000` (32 KiB), but `sp=0x819ea550`
had gone 5 KB below the stack base. The page at `0x819ea000` was not mapped
with the U bit (it was part of the kernel identity-map), causing the
U-mode store fault.

fbcon's initialization uses a deep call chain with multiple 1080-byte
`Message` IPC structs on the stack (std init → `connect_to_service` ×2 →
`connect_to_service("window")` → `Channel::send/recv` → `WindowClient`
calls), exceeding the 32 KiB limit before `main()` even prints its first
message.

**Bug class:** Memory corruption (Issue 1) + stack overflow (Issue 2).

## Fix

### Fix 1: Per-process mmap VA allocator

Added a per-process bump-pointer VA allocator for mmap regions:

- New constants `MMAP_VA_BASE = 0x4000_0000` and `MMAP_VA_LIMIT = 0x8000_0000`
  in `kernel/src/task/process.rs` — dedicates VA range 1–2 GiB for mmap.
- Added `mmap_next_va` field to `Process`, initialized to `MMAP_VA_BASE`.
- `MmapRegion` now has separate `base_vpn` (for PTE unmap) and `base_ppn`
  (for frame dealloc), allowing VA ≠ PA.
- `sys_mmap_shm` and `sys_mmap_anonymous` now allocate VA from the bump
  pointer instead of identity-mapping.
- `sys_munmap` and exit cleanup use `base_vpn` for unmap, `base_ppn` for
  dealloc.

### Fix 2: Increase user stack to 64 KiB

Changed `USER_STACK_PAGES` from 8 (32 KiB) to 16 (64 KiB). This provides
adequate headroom for programs with deep IPC call chains during
initialization. Filed bug 0016 for the underlying stack usage issue.

## Verification

1. `make build` — clean build, no warnings.
2. `make clippy` — clean on all crates.
3. `make run-vnc` — fbcon starts successfully, shell spawned. No page fault.
   SHM mapped at `0x40001000` (in new VA region, not identity-mapped).
4. `make run` (serial) — boots to shell prompt, no errors.
5. `make bench` — all benchmarks pass, no regressions.

## Lessons Learned

1. **Debug page faults thoroughly.** The initial analysis attributed the
   crash to SHM identity-map collision. While that was a real design flaw
   (and is fixed), the actual trigger was a stack overflow. Adding PTE
   inspection and stack range checking to the page fault handler quickly
   revealed the real cause.

2. **Identity mapping is fragile for user mmap.** Any identity-mapped
   allocation in user space risks colliding with other identity-mapped
   regions. The proper fix is a VA allocator, even a simple bump pointer.

3. **`Message` struct (1080 bytes) is a stack hazard.** Multiple IPC
   round-trips in a call chain can easily exhaust a small stack. This is
   tracked as bug 0016.
