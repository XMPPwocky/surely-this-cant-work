# Milestone 1 — Harden for Compositor, Networking, and Persistent FS

**Date:** 2026-02-06
**Input:** [Architecture Review 1](../arch-review-1.md)
**Goal:** Fix the subset of arch-review findings that will block or complicate the next
three planned features: a window compositor, a network stack, and a persistent
block-device filesystem.

Findings that don't block those features are explicitly deferred at the bottom of this
document.

---

## Acceptance Criteria

All six items must be complete before the milestone is closed.

### 1. Bump resource limits

- [ ] `MAX_HANDLES` ≥ 32 (was 16) — a compositor process needs handles for: GPU device,
  SHM framebuffer, per-client channels (×N), plus its own boot/control channels.
  16 is already exhausted with ~4 clients.
- [ ] `MAX_CHANNELS` ≥ 64 (was 32) — currently 7 services × ~3 channels each = 21
  consumed at boot. Compositor + networking adds at minimum 10 more.
- [ ] `MAX_SERVICES` ≥ 8 (was 4) — currently at capacity with stdio, sysinfo, math, fs.
  Compositor and networking each register as a service.

**Why now:** Every new feature hits these ceilings immediately. Trivial constant changes
but they silently fail if not bumped.

**Ref:** Arch review §3 (Fixed-size tables), §7 (Handle exhaustion is silent)

---

### 2. Add message queue depth limits

- [ ] Each channel endpoint enforces a maximum queue depth (e.g., 64 messages).
- [ ] `sys_chan_send` returns an error code (e.g., `QUEUE_FULL`) when the limit is hit.
- [ ] User-space `lib/rvos` exposes the error so callers can implement backpressure.

**Why now:** A compositor pushes frame-dirty notifications to every client. A network
stack receives packets from the NIC driver. Without backpressure, either feature can
exhaust the kernel heap with queued messages, panicking the system. This is the top
security concern from the arch review.

**Ref:** Arch review §3 (Message queue unbounded), §7 (Message queue flooding)

---

### 3. Fix fs endpoint leak

- [ ] `do_open()` in `user/fs/src/main.rs` closes `client_file_handle` after sending it
  to the client, or restructures ownership so the handle is not leaked.
- [ ] Verified: can open and close >14 files in a single session without `NO_CAP` errors.

**Why now:** A persistent filesystem will have long-lived sessions with many opens. The
current leak limits the system to ~14 file opens total before the handle table fills.

**Ref:** Arch review §7 (Endpoint leak in fs server), §9 recommendation #1

---

### 4. Deduplicate init.rs service handlers

- [ ] `handle_sysinfo_request`, `handle_math_request`, and `handle_fs_request` are
  replaced by a single generic function, e.g.,
  `handle_service_request(service_ep: &AtomicUsize, boot_ep_b: usize)`.
- [ ] Adding a new service requires only adding an entry to a table/array, not a new
  function.

**Why now:** Compositor and networking each add a new service. Without this fix, that's
two more copy-paste handler functions, increasing the maintenance surface and the odds
of a subtle copy-paste bug (e.g., forgetting to update the atomic variable).

**Ref:** Arch review §4 (Copy-paste handlers in init.rs), §9 recommendation #4

---

### 5. Port user/fs and user/shell to lib/rvos

- [ ] `user/fs/src/syscall.rs` is deleted; `user/fs` depends on `lib/rvos` for raw
  syscalls and channel operations.
- [ ] `user/shell/src/syscall.rs` is deleted; `user/shell` depends on `lib/rvos`.
- [ ] Both programs build and pass their existing functional tests.

**Why now:** Every new user-space program (compositor, network daemon, block-device
driver) will face the same "do I duplicate syscalls or use the shared library?" question.
If `user/fs` and `user/shell` still have their own copies, newcomers will cargo-cult the
duplication. Fix the existing programs so the shared library is the obvious path.

**Ref:** Arch review §4 (Duplicated syscall wrappers), §9 recommendation #3

---

### 6. Fix PageTable mem::forget pattern

- [ ] `PageTable::drop()` is a no-op (does not free page table frames).
- [ ] An explicit method (e.g., `PageTable::free()` or `PageTable::into_raw()`) is the
  only way to free page table frames.
- [ ] All 10 `mem::forget(PageTable)` call sites are removed.
- [ ] Kernel boots and runs all existing user programs without page table corruption.

**Why now:** The compositor will add `mmap` for GPU buffers, which means new code paths
that create/modify `PageTable` wrappers. Every such site must remember to call
`mem::forget` — and forgetting to do so silently corrupts page tables. Fix the
abstraction now before the number of fragile sites grows.

**Ref:** Arch review §2 (mem::forget is concerning), §9 recommendation #5

---

## Deferred

These arch-review findings are **not** in scope for this milestone.

| Finding | Rationale |
|---------|-----------|
| Hard-coded RAM constants → DTB parsing | Feature work (DTB parser), not a fix. Does not block compositor/net/fs — QEMU virt machine layout is stable. |
| `Handle(usize)` newtype | Pervasive refactor touching every syscall path. No correctness impact — just type safety. Can be done in a cleanup pass. |
| Frame allocator O(n) scan | At 32K frames (128 MiB), linear scan is fast enough. Only matters at much higher memory sizes. |
| std PAL allocator pooling | Requires changes in `vendor/rust/` and rebuilding the custom toolchain. Complex for modest gain — current one-mmap-per-alloc works. |
| 64-byte message limit → larger IPC | Deep IPC redesign (shared-memory message passing, scatter-gather). Deserves its own milestone. |
| Sequential service loops → `select()` | The fix is a new `select()`-like syscall, which is a feature. Belongs in the compositor milestone itself. |
| `.incbin` existence validation in build.rs | Quality-of-life improvement. Confusing linker errors are annoying but not blocking. |
| Target JSON absolute path | Irrelevant — single dev machine, no CI. |
| Stack traces on panic | Debuggability feature, not a correctness fix. Own milestone. |
| IPC tracing / runtime inspector | Debuggability infrastructure. Important but not blocking. |
| fs server trusts all clients | Access control is a feature that depends on a permissions model. Not blocking for the compositor or net stack prototypes. |
| No ASLR | Security hardening, not a blocker. |
| No capability revocation | Requires design work on revocation semantics. Not blocking. |

---

## Verification

The milestone is complete when:

1. `make build && make run` succeeds with all existing user programs running correctly.
2. `hello-std` can open, write, read, and close >20 files without `NO_CAP` errors.
3. `ps` (via shell) shows all current processes running (no regressions).
4. Grep for `mem::forget` in `kernel/` returns zero matches for `PageTable`.
5. Grep for `syscall.rs` in `user/fs/` and `user/shell/` returns zero matches.
6. `init.rs` has a single generic service handler function (no per-service copies).
7. A synthetic test or code inspection confirms that sending >64 messages on a channel
   returns an error rather than growing the queue unboundedly.
