# rvOS Architecture Review #3

**Date**: 2026-02-10
**Methodology**: 7 parallel reviewers (kernel core, kernel services, user apps, docs vs implementation, build system, git bug history, agent mistake patterns)

---

## 1. Correctness Bugs (Fix Now)

### HIGH: Integer overflow in `validate_user_buffer`
**`kernel/src/arch/trap.rs:974`** — `ptr + len` can wrap around on 64-bit, causing the multi-page validation to pass for an out-of-bounds buffer. Use `ptr.checked_add(len)` to detect overflow.

### HIGH: Integer overflow in `sys_mmap` size rounding
**`kernel/src/arch/trap.rs:667`** — `(size + PAGE_SIZE - 1) / PAGE_SIZE` wraps if `size` is near `usize::MAX`. Add a checked-add guard.

### HIGH: FS server sends critical responses non-blocking
**`user/fs/src/main.rs:421,427,445,452,462,468,474`** — `send_ok()`, `send_error()`, `send_write_ok()`, etc. all use `sys_chan_send()` (non-blocking). If the client's queue is full, the response is silently dropped and the client hangs forever waiting. Data chunk sends correctly use `sys_chan_send_retry()`, but metadata responses don't. Change all to blocking sends.

### HIGH: GPU server doesn't validate flush rectangle bounds
**`kernel/src/services/gpu_server.rs:74-80`** — `Flush { x, y, w, h }` is passed straight to the VirtIO driver without checking against framebuffer dimensions. Out-of-bounds coords from a buggy/malicious client could cause a device error or panic. Add `x + w <= width && y + h <= height` check.

### MEDIUM: Shell sysinfo send is non-blocking
**`user/shell/src/shell.rs:136`** — `sys_chan_send()` instead of blocking. If sysinfo's queue is full, the command is dropped and the shell waits forever.

### MEDIUM: SHM ref count has no underflow detection
**`kernel/src/ipc/mod.rs:607-609`** — The `if ref_count > 0 { ref_count -= 1; }` guard silently ignores a double-free instead of asserting. Replace with `assert!(ref_count > 0)` to catch ref-counting bugs.

### MEDIUM: `frame.rs` missing bounds check in `is_used()`/`set_used()`
**`kernel/src/mm/frame.rs:48-52`** — `dealloc()` asserts `frame_idx < TOTAL_FRAMES`, but `is_used()` and `set_used()` don't. A bad index panics on array bounds instead of a clear error.

---

## 2. Inconsistencies & Code Smells

### Blocking vs non-blocking sends — no clear policy
The codebase mixes three send strategies with no documented rule:
- `sys_chan_send()` — non-blocking, returns QueueFull (used in: fs server responses, shell, service.rs boot requests)
- `sys_chan_send_retry()` — yield+retry spin loop (used in: fs data chunks)
- `sys_chan_send_blocking()` / `channel_send_blocking()` — kernel blocking (used in: all kernel services, std stdio/fs PAL)

**Recommendation**: Document the policy: kernel tasks use `channel_send_blocking()`; user-space uses `sys_chan_send_blocking()` (syscall 207) for anything where a dropped message means a hang. Reserve non-blocking only for mouse-move-style fire-and-forget.

### Error response formats differ between services
- **sysinfo**: Sends raw text `"Unknown command\n"` (not wire format)
- **math**: Sends raw bytes `b"bad request"` (not wire format)
- **console**: Sends `FileResponse::Error { FsError::Io {} }` via rvos_wire
- **init**: Sends `BootResponse::Error { message }` via rvos_wire

**Recommendation**: Standardize all services to use wire-format responses matching their protocol definitions.

### `usize::MAX` as error sentinel vs. Result types
**`kernel/src/arch/trap.rs` (many lines)** — Syscalls return `usize::MAX` for unknown errors, specific codes (0-5) for known errors, and some newer paths return structured values. This violates the stated design principle ("no sentinel values").

### Inconsistent `OwnedEndpoint` adoption
**sysinfo, math** correctly use `OwnedEndpoint` for RAII cleanup. **gpu_server, kbd_server, mouse_server** store raw endpoint IDs and never explicitly close them.

### Copy-paste in `lib/rvos/src/service.rs`
**Lines 63-191** — `spawn_process()`, `spawn_process_with_cap()`, and `spawn_process_with_args()` are 85+ lines of nearly identical boot-channel code. Extract a common helper.

### Console `pending_read_len` field is never read
**`kernel/src/services/console.rs:139`** — Set on Read requests but never used to limit response size. Either use it or remove it.

---

## 3. Footguns & Defensive Gaps

### Init panics on resource exhaustion
**`kernel/src/services/init.rs:150,162`** — `register_boot()` and `register_console()` `panic!()` if their static arrays are full. This is during boot — a microkernel should degrade gracefully, not crash. Return `Result` or log and skip.

### Scheduler assumes PID 0 always exists
**`kernel/src/task/scheduler.rs:318-332`** — Falls back to PID 0 (idle) without verifying `processes[0].is_some()`. If someone modifies `find_free_slot()` to reuse slot 0, the system crashes.

### `as_page_table()` has no safety documentation
**`kernel/src/mm/address.rs:123-125`** — Casts a PPN to a mutable page table reference with no alignment, mapping, or validity checks. Needs at minimum a `// SAFETY:` comment explaining the identity-map invariant.

### Process::new panics on frame allocation failure
**`kernel/src/task/process.rs:142`** — `expect("Failed to allocate kernel stack")` panics the whole kernel if frame allocation fails during process spawn. Return `Result` instead.

### `KERNEL_TRAP_STACK_TOP` initialized to 0
**`kernel/src/task/scheduler.rs:89`** — If a trap fires before `init()` (shouldn't happen, but...), the trap handler loads sp=0 and corrupts address 0. Initialize statically or add a runtime guard.

### Arbitrary path length limit not shared
**`user/fs/src/main.rs:626,650,893`** — Multiple functions check `path_bytes.len() > 60` as a hardcoded limit. This constant should be defined once (in rvos-proto) and shared with all consumers.

---

## 4. Build System Issues

### CRITICAL: Hardcoded absolute path in target JSON
**`user/riscv64gc-unknown-rvos.json:23`** — Contains `-T/home/ubuntu/src/temp2/rvos/user/user.ld`. Breaks for any other developer or CI path.

### `MAX_MSG_SIZE` defined in 4 places without sync
**kernel/src/ipc/mod.rs, lib/rvos/src/message.rs, lib/rvos-wire/src/lib.rs, vendor/rust/.../ipc.rs** — All say `1024`, but there's no compile-time assertion linking them. Likewise `Message` struct is duplicated in 3 places. Add `const _: () = assert!(size_of::<Message>() == 1088);` in each.

### Syscall numbers defined in 3 places
**trap.rs, raw.rs, std ipc.rs** — No single source of truth. Move to `rvos-wire` and re-export.

### Empty `[workspace]` in user crates
**user/hello, user/shell, user/rvos-rt** — Have bare `[workspace]` sections with no members. These are cargo workspace-root markers that serve no purpose and can confuse dependency resolution. Remove them.

### Outdated allocator comment
**`vendor/rust/library/std/src/sys/alloc/rvos.rs:39`** — Comment describes two-field layout (mmap_size + padding) but implementation uses three-field layout (mmap_size + back_ptr + padding) after the overlap bug fix. Comment misleads.

---

## 5. Documentation Drift

| Doc | Issue | Actual Code |
|-----|-------|-------------|
| **kernel-abi.md** | MAX_HANDLES = 16 | **32** (process.rs:18) |
| **kernel-abi.md** | MAX_MMAP_REGIONS = 32 | **256** (process.rs:19) |
| **kernel-abi.md** | KERNEL_STACK_PAGES = 4 | **16** (process.rs:8) |
| **shared-memory.md** | MAX_MSG_SIZE = 64 | **1024** (ipc/mod.rs:10) |
| **shared-memory.md** | MAX_HANDLES = 16 | **32** |
| **README.md** | Syscall table missing 6 entries | SYS_CHAN_SEND_BLOCKING(207), SYS_CHAN_POLL_ADD(208), SYS_BLOCK(209), SYS_TRACE(230), SYS_SHUTDOWN(231), SYS_CLOCK(232) |
| **README.md** | Process list shows 9 | Actually 14+ at boot |
| **architecture.md** | Process states diagram | Missing SYS_BLOCK / poll-based blocking |
| **kernel-abi.md** | Handle table = `Option<usize>` | Actually `HandleObject` enum (Channel/Shm) |
| **arch-review-1.md** | Limits table stale | All constants wrong |

---

## 6. Historical Bug Patterns (from git log)

Analysis of 73 commits found 19 bug fixes (26%). The top recurring patterns:

| Pattern | Count | Example | Prevention |
|---------|-------|---------|------------|
| **Race conditions** | 6 | Check-then-block, blocked field cleared early | Atomic ops, wakeup_pending pattern |
| **Silent drops** | 5 | QueueFull unchecked, MAX_CLIENTS exceeded silently | `#[must_use]`, log on limit hit |
| **Resource leaks** | 5 | Endpoint not closed after serving, allocator header overlap | RAII wrappers everywhere |
| **Deadlocks** | 3 | Lock held across callback, fault handler re-lock | Lock ordering doc, try_lock() |
| **Memory corruption** | 3 | Stack overflow into DMA, guard page PTE not restored | Guard pages, dedicated trap stack |
| **"Update X forget Y"** | 5 | Changed return type, forgot 20 callers | `git grep` before commit |

**Most bug-prone subsystems**: IPC channels (9 bugs), scheduler (7 bugs), memory management (5 bugs).

---

## 7. Common Agent Mistakes (from session logs)

| Mistake | Frequency | Fix |
|---------|-----------|-----|
| Piping QEMU output through `tail` | 29% of sessions | Use `expect` for interactive; `timeout 30+` for batch |
| Adding `build-std` to `.cargo/config.toml` | 24% of sessions | NEVER — use Makefile flags only |
| Forgetting `cargo +rvos clean` after `build-std-lib` | 7% of sessions | ALWAYS clean all user crates after x.py |
| Missing `BOOTSTRAP_SKIP_TARGET_SANITY=1` | 17% of sessions | Copy full command from MEMORY.md |
| Lock held across channel_close/wake_process | 16% of sessions | Snapshot under lock, release, then call |

---

## 8. Priority Action Items

### Immediate (fix this week)
1. Fix `validate_user_buffer` integer overflow (correctness)
2. Fix FS server non-blocking response sends (hangs)
3. Fix GPU flush bounds validation (potential crash from user)
4. Fix hardcoded path in `riscv64gc-unknown-rvos.json` (build portability)
5. Update all stale constants in docs (MAX_HANDLES, MAX_MMAP_REGIONS, etc.)

### Soon (next sprint)
6. Centralize `MAX_MSG_SIZE` + syscall numbers in `rvos-wire` with compile-time assertions
7. Add `Message` size assertions in all 3 definition sites
8. Replace init `panic!()` on exhaustion with graceful degradation
9. Standardize all services to wire-format error responses
10. Remove empty `[workspace]` sections; fix allocator comment

### Backlog
11. Extract `lib/rvos/src/service.rs` spawn function duplication
12. Document lock ordering in `kernel/LOCK_ORDERING.md`
13. Add `#[must_use]` to all Result-returning IPC functions
14. Add RAII wrappers for gpu/kbd/mouse server endpoints
15. Create stress test: run bench 100x, measure heap growth
