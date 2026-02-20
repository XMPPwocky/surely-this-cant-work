# 0012: User Virtual Address Space (No More Identity Mapping)

**Date:** 2026-02-20
**Status:** Partially Implemented
**Subsystem:** kernel/mm, kernel/task, kernel/arch/syscall

## Motivation

User process memory (stack, mmap, SHM) was identity-mapped (VA=PA).
Physical pages were allocated from the frame allocator, then mapped at
VPN=PPN in the user page table. The address returned to user-space WAS the
physical address.

This caused **Bug 0015**: fbcon's 6 MB SHM framebuffer landed on physical
pages whose addresses overlapped the user stack's virtual range, corrupting
the stack PTEs. More broadly, any two identity-mapped regions whose physical
addresses collide will corrupt each other's page table entries.

The fix is to give mmap/SHM regions dedicated virtual addresses — independent
of where their backing physical pages happen to be.

## Design

### Overview

Replace identity mapping for mmap/SHM with a per-process bump allocator
that assigns virtual addresses from a dedicated region. The user stack
remains identity-mapped for now (see Deferred section).

### Virtual Address Layout

```
0x0000_0000 .. code_end              ELF code+rodata+data+bss  (from linker)
  [unmapped gap]
0x4000_0000 .. (grows up)            mmap / SHM region          (bump allocator)
  [large unmapped gap]
0x80xx_xxxx                          User stack (32 KiB)        (identity-mapped, VA=PA)
0x8000_0000 .. 0x8800_0000           Kernel RAM                 (identity-mapped, no U bit)
```

The mmap region starts at `MMAP_VA_BASE = 0x4000_0000` (1 GiB), well below
physical RAM at `0x8000_0000`. Since the user stack's physical address is in
the `0x8000_0000+` range, mmap VAs at `0x4000_0000+` can never collide with
the stack — fixing Bug 0015.

The kernel's identity mapping of all RAM (without U bit) remains unchanged
in user page tables — the kernel still accesses physical memory at VA=PA
during syscall handling.

A per-process bump pointer (`mmap_next_va`) allocates virtual addresses for
mmap/SHM. The `MmapRegion` struct stores both the VA (for page table ops)
and the PPN (for frame deallocation).

### Constants

```rust
// kernel/src/task/process.rs
pub const MMAP_VA_BASE: usize = 0x4000_0000;  // 1 GiB mark
```

### Interface Changes

**No user-facing ABI changes.** The mmap/munmap syscall signatures and
semantics are identical — the only difference is that the returned address
is a user VA instead of a PA. User code already treats it as an opaque
pointer. The std sysroot allocator (`sys/alloc/rvos.rs`) requires zero
changes.

### Internal Changes

#### 1. `MmapRegion` struct (process.rs) — DONE

Added `base_vpn` field alongside existing `base_ppn`:

```rust
pub struct MmapRegion {
    pub base_vpn: usize,       // virtual page number (for PTE unmap)
    pub base_ppn: usize,       // physical page number (for frame dealloc)
    pub page_count: usize,
    pub shm_id: Option<usize>,
}
```

#### 2. `Process` struct (process.rs) — DONE

Added `mmap_next_va: usize` bump pointer, initialized to `MMAP_VA_BASE`
in all four constructors (new_kernel, new_user, new_user_elf, new_idle).

#### 3. `sys_mmap_anonymous()` (syscall/mem.rs) — DONE

Allocates VA from bump pointer, maps VA→PA, returns VA (not PA).

#### 4. `sys_mmap_shm()` (syscall/mem.rs) — DONE

Same pattern — allocates VA from bump pointer, maps VA→PA, returns VA.

#### 5. `sys_munmap()` (syscall/mem.rs) — DONE

Looks up region by VPN (from user VA), gets stored PPN for frame dealloc.

#### 6. `terminate_current_process()` / `terminate_process()` (scheduler.rs) — DONE

Mmap cleanup uses `base_vpn` for unmap, `base_ppn` for frame dealloc.

#### 7. `current_process_alloc_mmap_va()` (scheduler.rs) — DONE

New helper that bumps `mmap_next_va` and returns the allocated VA.

#### 8. `current_process_add_mmap` / `current_process_remove_mmap` (scheduler.rs) — DONE

Updated signatures: add takes both VPN and PPN; remove matches on VPN and
returns `(base_ppn, shm_id)`.

### Resource Limits

The mmap VA region starts at `0x4000_0000` and grows upward. The bump
pointer doesn't reclaim freed VA ranges (munmap frees pages but doesn't
reset the pointer). This is adequate for current workloads (largest is the
6 MB framebuffer). If VA exhaustion becomes an issue later, upgrade to a
free-list allocator.

Note: `current_process_alloc_mmap_va()` does not currently check an upper
bound. An upper-bound check should be added if the stack is later moved
to a fixed VA below the RAM range.

## Blast Radius

| Change | Files Affected | Status |
|--------|---------------|--------|
| `MmapRegion` gains `base_vpn` field | `process.rs`, `scheduler.rs`, `mem.rs` | DONE |
| `Process` gains `mmap_next_va` | `process.rs` (4 constructors) | DONE |
| `sys_mmap_anonymous` returns VA not PA | `mem.rs` | DONE |
| `sys_mmap_shm` returns VA not PA | `mem.rs` | DONE |
| `sys_munmap` matches on VPN | `mem.rs`, `scheduler.rs` | DONE |
| `terminate_*` uses `base_vpn` for unmap | `scheduler.rs` | DONE |
| `current_process_alloc_mmap_va` added | `scheduler.rs`, `mod.rs` (re-export) | DONE |
| Debug prints removed | `mem.rs` (shm_create, mmap_shm) | DONE |

### Files touched

1. `kernel/src/task/process.rs` — MmapRegion, Process struct, constructors
2. `kernel/src/arch/syscall/mem.rs` — sys_mmap_anonymous, sys_mmap_shm, sys_munmap
3. `kernel/src/task/scheduler.rs` — cleanup fns, mmap helpers, VA allocator
4. `kernel/src/task/mod.rs` — re-export new function

### What does NOT change

- **User-space code**: No changes. The allocator, fbcon, window-server, all
  user programs treat mmap return values as opaque pointers already.
- **std sysroot**: No changes. No `make build-std-lib` needed.
- **Kernel page table**: Still identity-mapped for all RAM. No change to
  `paging.rs` or boot setup.
- **trap.S**: TrapContext lives in kernel memory (identity-mapped, no U bit).
  No change needed.
- **Syscall buffer validation**: `validate_user_buffer()` already walks the
  user page table to translate VA→PA. No assumption of VA=PA.
- **Debug service**: `translate_va_for_pid()` already does proper page table
  translation. No change.
- **Wire protocols, IPC, channel system**: Unaffected.
- **User stack mapping**: Still identity-mapped (VA=PA). No collision with
  mmap because mmap VAs are at `0x4000_0000+`, far below stack PAs at
  `0x8000_0000+`.

## Acceptance Criteria

- [ ] `make clippy` passes with no new warnings
- [ ] `make build` succeeds
- [ ] System boots and reaches shell (`make run` with expect script)
- [ ] `make run-vnc` works — fbcon displays correctly (Bug 0015 fixed)
- [ ] Shell commands work: `ps`, `mem`, `ls`, `cat`, `echo`
- [ ] User-space heap allocation works (Vec, String, Box in shell/user programs)
- [ ] SHM works end-to-end (window-server ↔ fbcon framebuffer)
- [ ] `make bench` runs without regression (>20% on any benchmark)
- [ ] Multiple processes can coexist with mmap regions (no VA collision)
- [ ] munmap correctly frees physical pages (check `mem` output)
- [ ] Process exit correctly cleans up all mmap regions and stack pages

## Deferred

| Item | Rationale |
|------|-----------|
| Move user stack to fixed VA | Stack at PA=VA still works; no collision now that mmap is at separate VAs. Revisit if stack needs to be larger than 32 KiB or if we want guard pages. |
| Simplify `create_user_page_table_elf()` | Could remove the exclude-user-pages-from-kernel-map logic since user mmap VAs no longer overlap kernel RAM range. Low priority — current code works correctly. |
| Delete `create_user_page_table_identity()` | Dead code (`#[allow(dead_code)]`). Cleanup, not correctness. |
| Add `user_stack_ppn` to Process | Only needed if stack moves to fixed VA; currently `user_stack_top / PAGE_SIZE` still works since stack is identity-mapped. |
| VA free-list allocator | Bump pointer is sufficient; add when VA fragmentation matters |
| Per-process VA randomization (ASLR) | Security feature, not needed for correctness |
| Growable user stack | Current 32 KiB fixed stack is adequate; demand-paging is separate work |
| Upper-bound check in `alloc_mmap_va` | Currently no limit; add if stack moves to fixed VA below mmap region |
| Update `docs/kernel-abi.md` | Document that mmap returns VA not PA (semantically invisible to users but worth noting) |

## Implementation Notes

Phase 1 (mmap/SHM VA allocation) was implemented as uncommitted changes on
main. This fixes Bug 0015 by ensuring mmap VAs are at `0x4000_0000+`,
which cannot collide with user stacks at `0x8000_0000+` PAs.

The stack and code mappings are untouched — they remain identity-mapped.
This is safe because:
- Code is at low ELF VAs (near 0), which don't overlap kernel RAM or mmap.
- Stack is at PA=VA in the `0x8000_0000+` range, which doesn't overlap
  mmap VAs at `0x4000_0000+`.

The bump pointer has no upper-bound check. In the current layout this is
harmless — the bump pointer would need to reach `0x8000_0000` before it
could collide with anything, which requires 1 GiB of cumulative mmap
allocations (including freed ones, since the bump pointer doesn't reclaim).

## Verification

(Updated during verification)
