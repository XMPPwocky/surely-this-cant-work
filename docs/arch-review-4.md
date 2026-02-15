# Architecture Review 4 — 2026-02-15

Scope: 15 commits since arch-review-3 (478b834..0d61c7f). Major features: per-task trap frames with sscratch-based context management, schedule() race fix + kernel task return handler, ChannelCap typed capability serialization, test infrastructure (ktest harness + bench regression), SYS_MEMINFO syscall, GPU display hang fix (WFI + volatile DMA + IRQ), FS protocol ChannelCap port.

Codebase: ~21,660 lines of Rust + assembly across kernel/, user/, and lib/.

Methodology: 9 parallel reviewers (kernel core, IPC & channels, kernel services, user apps & std PAL, docs vs implementation, build system & toolchain, bug history & patterns, coupling & blast radius, failure & exhaustion analysis).

---

## 1. Correctness Bugs (Fix Now)

### HIGH: Missing ref count increments in kernel-internal capability sends

**Location**: `kernel/src/services/init.rs` (multiple sites), `kernel/src/ipc/transport.rs:28-43`

**Problem**: The function `send_ok_with_cap()` (init.rs:820-827) encodes a capability endpoint and sends it via `channel_send_blocking()`, but does not call `channel_inc_ref()`. This violates the documented invariant: any code path placing a capability in a message's `caps[]` array MUST call `channel_inc_ref()`. Affected call sites:

- init.rs:570 — `handle_service_request()` sends `client_ep` (NO inc_ref)
- init.rs:609 — `handle_stdio_request()` sends `client_ep` (NO inc_ref)
- init.rs:1235 — `finish_fs_launch()` sends process handle (NO inc_ref)
- init.rs:560 — `handle_service_request()` sends `server_ep` to service control channel (NO inc_ref)
- init.rs:599 — `handle_stdio_request()` sends `server_ep` to console control channel (NO inc_ref)
- init.rs:727 — `handle_spawn_request()` sends `server_ep` to fs control channel (NO inc_ref)
- init.rs:904 — `init_fs_launches()` sends `server_ep` to fs control channel (NO inc_ref)

Additionally, `KernelTransport::send()` (transport.rs:28-43) encodes capabilities without calling `channel_inc_ref()`, affecting any RPC server using the transport layer.

One call site IS correct: init.rs:393 (`handle_request()` for ConnectService) manually calls `channel_inc_ref` before `send_ok_with_cap()`.

**Impact**: Premature channel deactivation. When the receiving process closes a capability whose ref count was never incremented for the transfer, the count drops to 0, breaking other processes' connections. This is the same class of bug as Bug 0002 (GUI shell dies after child exit).

**Fix**: Either (a) add `channel_inc_ref(cap_ep)` inside `send_ok_with_cap()` before encoding, making the function self-contained, or (b) create a `cap_send_blocking()` wrapper in `ipc/mod.rs` that auto-increments refs for kernel-internal sends. Option (a) is simpler; option (b) is more structural.

---

### HIGH: Resource leak in SYS_CHAN_CREATE on partial handle allocation failure

**Location**: `kernel/src/arch/trap.rs:364-388`

**Problem**: When `channel_create_pair()` succeeds but `alloc_handle()` fails for either endpoint, the code returns `usize::MAX` without closing the leaked endpoints:

```rust
let (ep_a, ep_b) = channel_create_pair()?; // succeeds
let handle_a = alloc_handle(Channel(ep_a))?; // if this fails: ep_a AND ep_b leaked
let handle_b = alloc_handle(Channel(ep_b))?; // if this fails: handle_a leaked (installed but unreturned)
```

If handle_a allocation succeeds but handle_b fails, handle_a is installed in the process handle table but never returned to user code (a0/a1 are set to `usize::MAX`). The process can never close it, and ep_b is leaked entirely.

**Fix**: Add rollback logic — close both endpoints on first failure; close ep_b and free handle_a on second failure.

---

### HIGH: 6 panic-on-frame-exhaustion sites in process creation

**Location**: `kernel/src/task/process.rs:136,181,191,205,252,264`

**Problem**: Process creation uses `.expect("Failed to allocate...")` for kernel stack, user code pages, user stack, and page table frames. If the frame allocator is exhausted, the kernel panics instead of returning an error to the syscall caller. A user-space process can trigger this by spawning many processes or allocating large amounts of memory via mmap.

Additional panic sites:
- `kernel/src/task/scheduler.rs:158` — `panic!("No free process slots")` when MAX_PROCS (64) exceeded
- `kernel/src/mm/page_table.rs:56,94` — `.expect("frame_alloc failed")` during page table creation
- `kernel/src/services/init.rs:88` — `assert!(idx < MAX_NAMED_SERVICES)` on service registration overflow

**Impact**: Any of these panics crashes the entire kernel. This is a DoS vector from user-space.

**Fix**: Change `Process::new_kernel()` and `Process::new_user_elf()` to return `Result`, propagate errors through spawn functions to syscall handlers, and return appropriate error codes to user-space.

---

### MEDIUM: Integer underflow in user stack PPN calculation during process exit

**Location**: `kernel/src/task/scheduler.rs:649-651`

**Problem**:
```rust
ustack_ppn = (proc.user_stack_top / PAGE_SIZE) - ustack_pages;
```
If `proc.user_stack_top / PAGE_SIZE < 8` (ustack_pages), this wraps to a very large number due to unsigned subtraction, potentially corrupting the frame allocator bitmap during cleanup.

**Fix**: Use checked subtraction: `ppn_top.checked_sub(ustack_pages).unwrap_or(0)` with a guard to skip cleanup if invalid.

---

## 2. Structural Problems

### trap.rs is a 1,139-line god module

**Location**: `kernel/src/arch/trap.rs`

trap.rs serves as the syscall dispatch hub with 25+ outgoing calls to `task/scheduler`, 20+ to `ipc/mod`, and 10+ to `mm/`. It handles all syscall argument validation, capability translation, and response marshalling in a single file.

**Why it matters**: Every new syscall adds ~30 lines to this file. Code review difficulty scales with file size. Bugs in argument validation (like the validate_user_buffer overflow) are hard to spot in a 1,139-line function.

**Refactoring path**: Extract syscall handlers into `arch/syscall/` submodule with one file per syscall group (chan.rs, mmap.rs, process.rs, misc.rs). Keep trap.rs as the dispatch table only.

---

### Inconsistent RAII adoption for endpoint ownership

**Location**: `kernel/src/services/gpu_server.rs`, `kbd_server.rs`, `mouse_server.rs` (raw endpoint IDs); `sysinfo.rs`, `math.rs` (OwnedEndpoint)

`sysinfo` and `math` correctly use `OwnedEndpoint` for automatic `channel_close` on drop. `gpu_server`, `kbd_server`, and `mouse_server` store raw endpoint IDs and never explicitly close them. While kernel task endpoints are cleaned up on process exit, this inconsistency makes code review harder and increases risk of the 0002-class bug (ref count leak).

**Fix**: Convert all services to use `OwnedEndpoint`. This also serves as documentation of ownership semantics.

---

### service.rs spawn function duplication (from review #3, still open)

**Location**: `lib/rvos/src/service.rs:63-191`

`spawn_process()`, `spawn_process_with_cap()`, and `spawn_process_with_args()` are 85+ lines of nearly identical boot-channel code. 6 similar `spawn_*` functions exist.

**Fix**: Extract a common `spawn_impl()` helper parameterized by optional caps/args/overrides.

---

## 3. Security & Isolation

| Severity | Location | Issue | Impact |
|----------|----------|-------|--------|
| HIGH | `process.rs:136,181,191,205` | Frame exhaustion → kernel panic | User-space DoS: spawn many processes to exhaust frames |
| HIGH | `scheduler.rs:158` | Process table full → panic | User-space DoS: spawn 64 processes |
| MEDIUM | `trap.rs:364-388` | Channel endpoint leak on handle alloc failure | Slow channel exhaustion (64 max) |
| MEDIUM | `init.rs` (7 sites) | Missing cap ref increments | Premature channel deactivation across processes |
| LOW | `page_table.rs:56,94` | Page table alloc failure → panic | Triggered by heavy mmap usage |
| LOW | `drivers/virtio/*.rs` | `unsafe mut` statics without locks | Safe only if IRQ nesting stays disabled |

---

## 4. Performance Cliffs

| Location | Current | Should Be | Penalty |
|----------|---------|-----------|---------|
| `scheduler.rs` find_free_slot | O(MAX_PROCS=64) linear scan | O(1) with free list | 64x overhead at capacity; negligible at current scale |
| `process.rs` alloc_handle | O(MAX_HANDLES=32) linear scan | O(1) with free list | 32x overhead; negligible |
| `ipc/mod.rs` channel_create_pair | O(MAX_CHANNELS=64) linear scan | O(1) with free list | 64x overhead at capacity |
| `frame.rs` frame_alloc | O(TOTAL_FRAMES=32768) bitmap scan | O(1) with free list or buddy | Up to 32768 iterations; mitigated by cursor |
| SCHEDULER SpinLock | Global lock for all task ops | Per-CPU run queues | Contention at >4 CPUs (currently single-CPU) |

None of these are performance issues at current scale (64 processes, single CPU). They would become bottlenecks if scaling to 256+ processes or SMP.

---

## 5. Resource Exhaustion Audit

| Resource | Limit | Limit Location | On Exhaustion | Caller Notified? | DoS Vector? |
|----------|-------|---------------|---------------|-----------------|-------------|
| Channels | 64 | `ipc/mod.rs:12` | Logs warning, returns None | YES | YES |
| Processes | 64 | `process.rs:15` | **PANIC** | NO | YES |
| Handles (per-proc) | 32 | `process.rs:16` | Returns None | YES | YES (per-proc) |
| Mmap regions | 256 | `process.rs:17` | Returns false → syscall error | YES | Unlikely |
| Message queue | 64 | `ipc/mod.rs:16` | Returns QueueFull | YES | YES (backpressure) |
| Physical frames | 32768 | `frame.rs:6` | Returns None (but **panics** in 6 callers) | Partial | YES |
| Console clients | 8 | `console.rs:132` | Logs warning, closes endpoint | YES | YES (limited) |
| Boot registrations | 16 | `init.rs:46` | Logs warning, skips | YES | NO (boot-time) |
| Named services | 8 | `init.rs:50` | **PANIC** (assert) | NO | NO (boot-time) |
| GPU clients | 1 | `gpu_server.rs:37` | Rejects connection | YES | By design |
| KBD/Mouse clients | 1 | `kbd_server.rs:28` | Rejects connection | YES | By design |
| SHM regions | 32 | `ipc/mod.rs:14` | Returns None | YES | YES |
| Page table pages | Unbounded | `page_table.rs:94` | **PANIC** | NO | YES |
| Kernel stacks | 17 pages/proc | `process.rs:6,10` | **PANIC** | NO | YES |

**Key finding**: 8 panic sites on resource exhaustion that should return errors. Process table full and frame allocation failure are the most critical — both are user-triggerable.

---

## 6. API Consistency & Footguns

### Blocking vs non-blocking sends — policy partially applied

Review #3 identified this. Since then, FS server responses and shell sysinfo have been fixed to use blocking sends. Current policy:
- Kernel tasks: `channel_send_blocking()` — correctly used
- User-space critical responses: `sys_chan_send_blocking()` — correctly used
- Fire-and-forget (mouse events): `sys_chan_send()` — correct by design

**Remaining**: Policy not formally documented. Recommend adding to CLAUDE.md.

### `send_ok_with_cap()` does NOT increment ref counts

This function looks like it handles capability transfer completely, but callers must manually call `channel_inc_ref()` before using it. Only 1 of 7+ call sites does this correctly. This is the most dangerous footgun in the codebase.

**Fix**: Make `send_ok_with_cap()` self-contained by adding `channel_inc_ref()` internally, or rename to `send_ok_with_cap_raw()` and create a safe wrapper.

### `usize::MAX` as error sentinel

Syscalls return `usize::MAX` for errors. This violates the stated design principle of no sentinel values. Newer paths return structured error codes (0-5), but older paths still use `usize::MAX`.

### Console `pending_read_len` field — still unused

**Location**: `kernel/src/services/console.rs:139`

Set on Read requests (line 336) but never read to limit response size. Dead code since review #3.

---

## 7. Code Duplication

| Pattern | Instances | Lines | Fix |
|---------|-----------|-------|-----|
| `spawn_process*` variants in `lib/rvos/src/service.rs` | 6 | ~130 | Extract `spawn_impl()` with optional params |
| Service endpoint registration in `main.rs` | 8 services | ~40 | Trait-based `KernelService::init()` |
| Handle lookup + match in syscall handlers (`trap.rs`) | 15+ | ~75 | Extract `with_handle::<T>(handle, \|ep\| ...)` helper |
| `send_ok_with_cap()` callers doing manual inc_ref | 7 | ~35 | Move inc_ref inside the function |

---

## 8. Documentation Drift

| Doc | Claim | Actual Code | Severity |
|-----|-------|-------------|----------|
| **architecture.md:139-153** | Trap frames saved "on the current kernel stack" | `process.rs:51` — `TrapContext` stored in Process struct (per-task, not stack-based) | **HIGH** |
| **architecture.md:139-140** | "reads sscratch: if zero → S-mode; if nonzero → U-mode" | sscratch always points to TrapContext; trap origin determined by `sstatus.SPP` | **HIGH** |
| **architecture.md:25** | "Heap — a 1 MiB linked-list allocator" | `heap.rs:5` — HEAP_SIZE = 4 MiB | **MEDIUM** |
| **architecture.md:332** | "Each process has a 16-slot handle table" | `process.rs:16` — MAX_HANDLES = 32 | **MEDIUM** |
| **architecture.md:328** | "Kernel stack — 4 pages (16 KiB)" | `process.rs:6` — KERNEL_STACK_PAGES = 16 (64 KiB) | **MEDIUM** |
| **architecture.md:201-207** | Kernel task trampoline: enables interrupts, jumps to entry | Per-task trap frames; entry via `sret` from TrapContext, not direct `jr` | **MEDIUM** |
| **README.md** | Syscall table missing SYS_MEMINFO (233) | `trap.rs:38` — implemented | **MEDIUM** |
| **README.md** | No mention of `make bench`, `make test`, `make bench-check` | Makefile has these targets (added f06d5ef) | **MEDIUM** |
| **architecture.md** | No mention of sscratch invariant (always → current TrapContext) | Critical new invariant from 4fbec34 | **HIGH** |
| **architecture.md** | No mention of `preempt()` function | Fundamentally changes timer preemption path | **HIGH** |
| **All docs** | No mention of ktest harness | `user/ktest/src/main.rs` — 1,132 lines, fully implemented | **MEDIUM** |
| **All docs** | No mention of ChannelCap typed serialization | `lib/rvos-wire/src/lib.rs:693+` — complete | **LOW** |

**Key issue**: `architecture.md` is significantly out of date. The trap handling and context switching sections describe the pre-4fbec34 architecture. The design doc `docs/designs/0007-per-task-trap-frames.md` exists and is thorough, but the main architecture doc hasn't been updated.

---

## 9. Bug Pattern Analysis

Analysis of 115 commits found 33 bug fixes (29% fix density, up from 26% in review #3).

| Pattern | Count | Trend vs Review #3 | Structural Prevention |
|---------|-------|--------------------|-----------------------|
| Resource leak | 8 | STABLE | Partial RAII adoption (OwnedEndpoint in 2/7 services) |
| Race condition | 7 | **UP** (+3) | `suppress_irq_restore()` pattern; no automated enforcement |
| Silent drop / lost message | 7 | DOWN | Blocking send policy adopted; `#[must_use]` recommended |
| Ref counting error | 5 | STABLE | Manual discipline; no compile-time enforcement |
| Memory corruption | 5 | STABLE | Guard pages + per-task trap frames; architectural fix |
| Missing validation | 5 | DOWN | `checked_add` adoption; compile-time assertions |
| Deadlock / blocking | 4 | STABLE | Lock ordering improving; no formal doc |
| Integer overflow | 3 | DOWN | `checked_add` habit established |
| Busy-wait / starvation | 3 | NEW CATEGORY | WFI pattern + EOF handling; documented |

**Most-fixed subsystems** (updated rankings):
1. IPC channels: 11 bugs (was 9) — STABLE
2. Scheduler & preemption: 10 bugs (was 7) — **TRENDING UP**
3. Memory management: 7 bugs (was 5) — STABLE
4. GPU & device drivers: 5 bugs — **NEW CATEGORY**
5. Shell / user-space: 6 bugs — DOWN (mostly cosmetic/UX)

**Key insight**: Scheduler/preemption races are the hardest bug class to prevent architecturally. The `suppress_irq_restore()` pattern helps but requires developer discipline at every `drop(lock)` site. GPU/device drivers emerged as a new risk area in the last 15 commits.

**Structural fixes from review #3 — effectiveness**:

| Fix | Effectiveness | Evidence |
|-----|---------------|----------|
| Compile-time assertions (Message size) | HIGH | No recurrence |
| Bounds checks (frame allocator) | HIGH | No recurrence |
| SHM underflow assertion | HIGH | Catches double-free immediately |
| Guard pages + per-task trap frames | HIGH | Stack overflow contained; 0d61c7f was race, not corruption |
| `checked_add` adoption | HIGH | No new integer overflows |
| Blocking send policy | HIGH | No new silent drops in services |
| Log+skip vs panic on exhaustion | MEDIUM | Applied to init; 6 other panic sites remain |

---

## 10. Dependency & Coupling Map

### File coupling heat map

```
kernel/src/arch/trap.rs               HOTTEST   [scheduler:15  ipc:20  mm:10  drivers:5]
kernel/src/task/scheduler.rs          HOT       [process:50+  ipc:10  mm:8  sync:5]
kernel/src/ipc/mod.rs                 WARM      [59 call sites across 11 files]
kernel/src/services/init.rs           WARM      [spawns processes, manages boot caps]
```

### Blast radius of changing core structs

| Struct | Files Affected | Key Constraint |
|--------|---------------|----------------|
| **Message** | **14+ files** | Kernel ↔ user ABI; layout frozen; 90+ operations |
| **TrapContext** | **6 files + asm** | Hardcoded assembly offsets in trap.S |
| **Channel API** | **11 files** | 59 call sites; every service depends on semantics |
| **Process** | **8 files** | State machine; handle table; trap_ctx embedding |
| **HandleObject** | **5 files** | 50+ pattern matches across trap.rs and scheduler.rs |
| **SpinLock** | **9+ files** | 87 `.lock()` call sites; sync primitive |

### Global statics (32 total)

**Critical bottlenecks**:
- `SCHEDULER` (SpinLock) — 120+ reads, 87 writes; every task operation
- `CHANNELS` (SpinLock) — 59 call sites; all IPC
- `FRAME_ALLOCATOR` (SpinLock) — 40+ operations; all memory allocation
- `HEAP` (LockedHeap) — 50+ operations; all heap allocation

**Driver statics** (unsafe mut, no locks):
- `GPU`, `KEYBOARD`, `TABLET` — relies on IRQ disabling for safety; not portable to SMP

### Circular dependencies: **NONE**

All dependencies flow downward: services → ipc → task → mm → sync → arch. This is excellent.

---

## 11. What's Good

### Per-task trap frames (4fbec34) — excellent architecture

The move from stack-based to per-task TrapContext eliminates an entire class of corruption bugs (shared kernel trap stack). The sscratch invariant is maintained at all 4 update sites (init, schedule, preempt, trampolines) with interrupts disabled. The `#[repr(C)]` layout with fixed assembly offsets is clean and maintainable.

### schedule() race fix (0d61c7f) — elegant pattern

The `SpinLockGuard::suppress_irq_restore()` pattern is minimal and composable. It correctly prevents the interrupt window between `sched.current = next_pid` and `switch_context()` without requiring a fundamentally different lock design. The `kernel_task_return_handler` cleanly handles kernel task exit.

### ChannelCap typed capabilities (356f631, a2d8ade) — sound type design

`ChannelCap<S, R>` with move-only semantics enforces capability ownership at compile time. The GAT-based `MessageType` provides zero-copy deserialization. The migration is ~95% complete with idiomatic wire serialization via `RawChannelCap`.

### Capability transfer rollback (trap.rs:414-431)

The `translate_cap_for_send()` + `rollback_encoded_cap()` pattern ensures atomicity of multi-capability transfers. If any cap in a message fails to translate, all previously-translated caps are rolled back. This prevents ref count leaks on partial failures.

### Process exit cleanup ordering (scheduler.rs:585-704)

The exit sequence correctly: (1) snapshots data under lock, (2) releases lock before calling channel_close (avoiding deadlock), (3) closes all handles, (4) frees physical frames, (5) explicitly drops heap-allocated Vec before schedule() (preventing leak since schedule() never returns for Dead processes). Well-documented with inline comments explaining each ordering decision.

### Test infrastructure (f06d5ef)

The ktest harness (1,132 lines) with memory leak detection, expect-based serial testing, and benchmark regression checking (20% threshold) provides meaningful CI capability. The bench-save/bench-check workflow is well-designed.

### Zero circular dependencies

The module dependency graph flows cleanly downward with no cycles. This is rare for a kernel and should be preserved.

### Compile-time assertions for ABI stability

Message size and layout assertions across 4 definition sites (kernel, lib/rvos, lib/rvos-wire, vendor/rust PAL) catch ABI drift at compile time.

---

## 12. Priority Action Items

### Immediate (fix this week)

1. **Add `channel_inc_ref()` to `send_ok_with_cap()` or all 7 caller sites in init.rs** — same bug class as 0002; premature channel deactivation (HIGH)
2. **Add rollback to SYS_CHAN_CREATE handle allocation failure** — endpoint/handle leak on partial failure (HIGH)
3. **Replace panics with Result in Process::new_kernel/new_user_elf** — user-triggerable kernel crash via resource exhaustion (HIGH)
4. **Replace panic in find_free_slot with Option return** — user-triggerable via 64 process spawns (HIGH)
5. **Fix integer underflow in ustack_ppn calculation** — `scheduler.rs:651` (MEDIUM)

### Soon (next sprint)

6. Update `architecture.md` trap handling and context switching sections for per-task trap frames + sscratch invariant (HIGH doc drift)
7. Add SYS_MEMINFO to README.md syscall table; add `make test`/`make bench` to README (MEDIUM doc drift)
8. Convert gpu_server/kbd_server/mouse_server to use `OwnedEndpoint` (MEDIUM consistency)
9. Make `send_ok_with_cap()` self-contained (inc_ref internally) to eliminate footgun (MEDIUM)
10. Add `channel_inc_ref()` to `KernelTransport::send()` for capability-bearing messages (MEDIUM)
11. Replace page_table.rs `.expect()` with error propagation (MEDIUM)
12. ~~Fix allocator comment line 39-40 in vendor/rust~~ Document three-field header layout (LOW)
13. Remove stale TODO/deprecation comment from `lib/rvos/src/lib.rs:12-14` (LOW)
14. Fix hardcoded `x86_64-unknown-linux-gnu` in `Makefile:3` for cross-platform builds (MEDIUM)

### Backlog (when convenient)

15. Extract trap.rs syscall handlers into `arch/syscall/` submodule (~1,139 LOC → ~4 files)
16. Extract `lib/rvos/src/service.rs` spawn function duplication into common helper
17. Document lock ordering in `kernel/LOCK_ORDERING.md`
18. Add `#[must_use]` to all Result-returning IPC functions
19. Document blocking vs non-blocking send policy in CLAUDE.md
20. Add build prerequisites documentation (`docs/build-setup.md`)
21. Document `build-std-lib` dependency chain (Makefile comment or README)
22. Remove unused `pending_read_len` field from `console.rs:139`
23. Standardize math/sysinfo error responses to wire format
24. Consider generating TrapContext field offsets from Rust for trap.S (eliminate hardcoded asm offsets)

### Review #3 items — status

| Item | Status |
|------|--------|
| ~~validate_user_buffer integer overflow~~ | **DONE** (eba2880) |
| ~~FS server non-blocking response sends~~ | **DONE** (7e09384) |
| ~~GPU flush bounds validation~~ | **DONE** (bdbf4fb) |
| ~~Hardcoded path in target JSON~~ | **DONE** (d6e6890) |
| ~~Stale constants in docs~~ | **DONE** (7e38029) |
| ~~MAX_MSG_SIZE compile-time assertions~~ | **DONE** (ed72746) |
| ~~Init panic on exhaustion~~ | **DONE** (c0af550) |
| ~~Empty workspace sections~~ | **DONE** (d3bc3ad) |
| ~~Allocator comment~~ | **DONE** (66a2399) |
| Standardize wire-format error responses | OPEN |
| Extract service.rs spawn duplication | OPEN |
| Document lock ordering | OPEN |
| Add `#[must_use]` to IPC functions | OPEN |
| RAII wrappers for gpu/kbd/mouse endpoints | OPEN |
| Syscall numbers not centralized | OPEN |
