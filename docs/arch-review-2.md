# rvOS Architecture Review #2

**Date**: 2026-02-08
**Methodology**: 5 parallel reviewers (kernel core, IPC system, bug history, code duplication, std port)

---

## What's Good

The overall architecture is sound for a microkernel at this stage:

- **SpinLock** (`sync/spinlock.rs`): Saves/restores interrupt state, proper acquire/release ordering, guard pattern prevents forgetting to unlock. Best-designed abstraction in the kernel.
- **Tagged heap allocator** (`mm/heap.rs`): Per-subsystem tracking (IPC_, SCHD, PGTB, etc.) is an excellent debugging feature.
- **Clean arch separation**: `arch/` isolates RISC-V specifics. `mm/` cleanly separates frame allocation, page tables, heap, address types.
- **rvos-wire** (`lib/rvos-wire/`): Solid, correct, zero-copy reads, proper error handling, 20 tests.
- **Capability-based IPC**: Fuchsia-style per-endpoint ref counting is well-chosen.

---

## Structural Problems

### The SCHEDULER God Lock

Every kernel operation acquires the single `SCHEDULER` lock (~20 public functions). The `Process` struct is a 34-field flat struct mixing scheduling, memory, IPC, and lifecycle concerns. This means the IPC hot path locks the *entire scheduler* just to look up a handle.

**Impact**: 3 deadlock bugs. The `exit_current_from_syscall` "snapshot and release" pattern is 115 lines of careful choreography.

**Recommendation**: Extract handles into a separate per-process lock. Decompose Process into sub-structs.

### Single Blocked PID Per Endpoint

`ipc/mod.rs:129-132`: `blocked_a` / `send_blocked_a` are single `usize` values. If two processes block on the same endpoint, the second silently overwrites the first. The first process hangs forever. Works today because endpoints are point-to-point, but it's a time bomb.

### channel_create_pair Panics on Exhaustion

`ipc/mod.rs:195`: `panic!("No free channels")` — a user process can exhaust all 64 slots and crash the kernel. Must return an error.

### Page Table Frame Leak in sys_mmap

`PageTable::from_root()` creates a wrapper with empty `frames` vec. `map()` allocates intermediate PT nodes into this vec. On drop, `frame_dealloc` is never called — frames leak permanently.

---

## Security Issues

| Severity | Location | Issue |
|----------|----------|-------|
| HIGH | `trap.rs:847-878` | `validate_user_buffer` checks mapping but not U-bit page permission |
| HIGH | `trap.rs:291` | `msg.len` from userspace not clamped; kernel slices like `msg.data[..msg.len]` can panic OOB |
| MEDIUM | Design | No capability revocation mechanism (by design, but limits security model) |
| MEDIUM | `ipc/mod.rs:195` | DoS via channel exhaustion → kernel panic |

---

## Performance Cliffs

### Stale Chunk Sizes (order-of-magnitude penalty)

MAX_MSG_SIZE was increased from 64 to 1024, but chunk sizes in the std port were never updated:

| Location | Current | Should Be | Penalty |
|----------|---------|-----------|---------|
| `stdio/rvos.rs:31` — `chunks(64)` | 64 B | ~1024 B | ~16x more IPC |
| `fs/rvos.rs:47` — `MAX_WRITE_CHUNK=53` | 53 B | ~1013 B | ~19x more IPC |
| `fs/rvos.rs:109` — path limit 60 B | 60 B | ~1020 B | artificial limit |

### 1KB Message Copies

`Message` is 1048 bytes, copied by value on every send. Most payloads are < 64 bytes. Fully-loaded channels (64 channels × 64 depth × 1048 bytes × 2 queues) could theoretically exceed heap.

### O(n) Frame Allocator

`frame.rs:54-65`: Linear scan through 32,768 frames. `first_free` never decreases. Fine for 12 processes, won't scale.

---

## API Footguns

### Channel RAII Missing Blocking Send

`Channel::send()` is non-blocking (returns QueueFull). `Channel::recv_blocking()` is blocking. No `Channel::send_blocking()`. Users must drop to raw syscalls.

### append Mode Silently Ignored (DATA LOSS)

`fs/rvos.rs:545-572`: `OpenOptions.append` stored but never sent to fs server. `.append(true).open(path)` overwrites from position 0.

### Inconsistent file.metadata() vs fs::metadata()

`File::file_attr()` returns unsupported, but module-level `stat()` works. Same operation, different result.

### send_and_wake Silently Drops on QueueFull

`init.rs:579-585`: Critical control messages sent non-blocking. If queue full, response silently dropped, user process hangs forever.

### Raw Integer Returns Instead of Result

Many kernel IPC functions and syscall handlers return raw `usize` error codes instead of `Result`. Since `Result` is already `#[must_use]` in Rust, switching to `Result` return types would give compile-time warnings when callers ignore errors. The silent-failure bugs (QueueFull drops, ignored capacity limits) stem from this pattern.

### Duplicate Syscall Number Definitions

`trap.rs:15-31` and `lib/rvos/src/raw.rs:2-19` define the same constants independently. No compile-time enforcement of agreement.

---

## Code Duplication (~345 Lines Recoverable)

| Pattern | Instances | Lines | Fix |
|---------|-----------|-------|-----|
| Blocking recv loop in services | 7 | ~100 | Use existing `channel_recv_blocking()` (dead code!) |
| Send-with-backpressure | 3 | ~50 | Kernel-side `channel_send_blocking()` |
| Control EP static+setter | 5 | ~30 | Macro or `register_service()` |
| Shell sysinfo commands | 3 | ~45 | `sysinfo_query(cmd)` helper |
| Serial vs FB console server | 2 | ~100 | `ConsoleIO` trait |
| Window protocol constants | 2 | ~20 | Shared crate/module |

Also: `create_user_page_table_elf` and `create_user_page_table_identity` in `process.rs` are ~180 lines of near-identical kernel memory mapping.

---

## Bug Classes (from 22 historical bugs)

| Class | Bugs | Best Structural Fix | Effort |
|-------|------|---------------------|--------|
| Lock-ordering deadlocks | 3 | Return wake-lists from IPC functions | Medium |
| Check-then-act races | 3 | Atomic `recv_or_block()` primitive | Medium |
| Resource leaks (handles) | 2 | RAII `OwnedEndpoint` wrapper | Small |
| Silent failures | 4 | Use `Result` returns; log on capacity limits | Small |
| Protocol mismatches | 4 | Shared `rvos-abi` crate; typed protocols | Med-Large |
| Interrupt/preemption | 3 | Debug-mode CSR assertions | Large |
| Server lifecycle bugs | 3 | `KernelService` trait with generic loop | Medium |

**Top 3 by ROI:**
1. **RAII OwnedEndpoint** — tiny effort, eliminates handle leak class
2. **`Result` returns + capacity logging** — small effort, catches silent failures
3. **KernelService trait** — medium effort, prevents lifecycle bugs + duplication

---

## Prioritized Action Items

### Tier 1 — Fix Now (ALL DONE)
1. ~~Clamp `msg.len` to MAX_MSG_SIZE in syscall send path~~ — DONE
2. ~~Return error instead of panicking in `channel_create_pair()`~~ — DONE (returns `Option`)
3. ~~Update stale chunk sizes (stdio 64→1024, fs write 53→1013, path 60→1020)~~ — DONE
4. ~~Fix `append` mode silent ignore in fs PAL~~ — DONE (FLAG_APPEND in PAL + fs server)
5. ~~Make `send_and_wake` in init.rs handle QueueFull (use blocking send)~~ — DONE

### Tier 2 — Fix Soon (PARTIALLY DONE)
6. ~~RAII `OwnedEndpoint` for kernel services~~ — DONE (`ipc::OwnedEndpoint`, used in math + sysinfo)
7. ~~`accept_client` + `channel_recv_blocking` helpers~~ — DONE (replaced duplicated loops in math, sysinfo, gpu_server)
8. ~~Kernel-side `channel_send_blocking`~~ — DONE (used by all kernel services + init)
9. Fix PageTable frame leak in `from_root()` / sys_mmap
10. Add `Channel::send_blocking()` to userland RAII wrapper
11. Unify page table creation functions

### Tier 3 — Fix When Scaling
12. Decompose Process struct; per-process handle lock
13. Enforce single-blocker or use wake lists
14. Shared `rvos-abi` crate for constants
15. U-bit check in `validate_user_buffer`
16. Variable-size messages
