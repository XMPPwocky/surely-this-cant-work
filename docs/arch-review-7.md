# Architecture Review 7 — 2026-02-24

Scope: 107 commits since arch-review-6 (6de9aa9..fafba7c). Major features: platform abstraction (FDT parser), ext2 read-write filesystem, VirtIO block device driver, multi-interface net-stack with loopback, HTTP client/server, DNS client library, DHCP client, debugging/observability tools (kstat, schedlat, ipclat, chstat, dbg), spawn-suspended, SYS_KILL syscall, Ctrl+C/foreground group, process termination, terminal server library, netcat utility, bug investigation documentation.

Codebase: ~35,500 lines of Rust + assembly across kernel/, user/, and lib/.

Methodology: 6 parallel reviewers (kernel internals, services & applications, cross-cutting analysis, code quality, test coverage, docs & build). Special focus on patterns revealed by the investigation writeups added to all 17 closed bug docs.

---

## 1. Correctness Bugs (Fix Now)

### HIGH: net-stack TCP connection buffers cause stack overflow

**Location**: `user/net-stack/src/main.rs:752-754`

**Problem**: Each `TcpConn` embeds two 4 KiB buffers (recv_buf, send_buf), totaling ~8.3 KiB per connection. With `MAX_TCP_CONNS = 16`, the `TcpConns` type consumes ~133 KiB. Combined with the socket array, interface state, and local variables in `main()`, total stack usage exceeds 145 KiB — far beyond the 64 KiB user stack.

The net-stack currently works only because `TcpConns` and `TxScratch`/`RxScratch` are heap-allocated via `Box::from_raw(alloc_zeroed(...))`. However, if a future refactor moves these to the stack, or if deep call chains add frame locals, the system will silently corrupt memory.

**Impact**: Latent stack overflow risk. Any change that increases stack usage in net-stack's main loop could trigger corruption.

**Fix**: Move `recv_buf` and `send_buf` to `Vec<u8>` within TcpConn, ensuring they're always heap-allocated regardless of how TcpConns is constructed.

---

### MEDIUM: ext2-server silently truncates paths longer than 64 bytes

**Location**: `user/ext2-server/src/main.rs:748`

**Problem**: When handling Open/Read/Write/Delete/Mkdir requests, the ext2-server truncates paths to 64 bytes via `.min(64)` without notifying the client:

```rust
path_len = path.len().min(64);
path_buf[..path_len].copy_from_slice(path.as_bytes());
```

ext2 supports filenames up to 255 bytes. A path like `/bin/very-long-program-name-that-exceeds-64-bytes` gets silently truncated, potentially opening the wrong file. Affects 5 call sites (lines 748, 753, 758, 762, 775).

**Impact**: Silent data corruption — wrong file opened, wrong data written, wrong file deleted.

**Fix**: Return `FsError::InvalidPath` if path exceeds buffer size:
```rust
if path.len() > path_buf.len() {
    send_error(ch, FsError::InvalidPath);
    continue;
}
```

---

### MEDIUM: http-server silently processes partial/corrupt HTTP headers

**Location**: `user/http-server/src/main.rs:45-63`

**Problem**: The request parsing loop breaks silently on three conditions: (1) buffer full without finding `\r\n\r\n` headers terminator, (2) `read()` returns 0 (EOF), (3) `read()` returns error. In all three cases, the server attempts to parse whatever partial data is in the buffer and serve a response.

**Impact**: Malformed HTTP responses to clients; no error logging for debugging.

**Fix**: Send 400 Bad Request when the buffer fills without a complete header. Log I/O errors. Return 413 Payload Too Large for oversized requests.

---

### ~~MEDIUM: Named services register silently overwrites on capacity overflow~~ FIXED (587d32d)

**Location**: `kernel/src/services/init.rs:50` (MAX_NAMED_SERVICES)

**Problem**: When all named service slots are full, `register_named_service()` silently overwrites the oldest entry instead of returning an error. Current usage is ~10 of 16 slots, but growth is unchecked.

**Impact**: Silent service deregistration. A new service could overwrite `"stdio"` or `"fs"`, breaking all subsequent connections.

**Fix**: ~~Return `Option<()>` and reject registration when full. Log a warning.~~ Changed `register_service()` to return `Option<()>`, rolls back atomic counter on failure, logs warning. Boot callers use `.expect()`, runtime caller (fs launches) handles gracefully.

---

### ~~MEDIUM: Process spawn panics on PID exhaustion~~ ALREADY FIXED

**Location**: `kernel/src/task/process.rs:15` (MAX_PROCS = 64)

**Problem**: `find_free_slot()` panics when all 64 process slots are occupied. While init limits dynamic spawns to 8, there's no guarantee that kernel tasks + user processes stay under 64 during heavy use.

**Impact**: Unrecoverable kernel panic on resource exhaustion.

**Fix**: ~~Return `Option<usize>` from `find_free_slot()`. Propagate error to caller.~~ Already fixed: `find_free_slot()` returns `Option<usize>`, all `spawn_*` functions propagate via `?`, and the init server's dynamic spawn path (line ~1343) handles `None` gracefully. Boot-time callers in `kmain` use `.expect()` which is correct — failure to spawn essential services (init, serial-con, etc.) is genuinely fatal.

---

### ~~MEDIUM: SHM creation panics on slot exhaustion~~ ALREADY FIXED

**Location**: `kernel/src/ipc/mod.rs:14` (MAX_SHM_REGIONS)

**Problem**: `shm_create()` panics when all 32 SHM region slots are occupied. Current usage is low (~2-3 regions at boot), but there's no guard against growth.

**Impact**: User-triggerable kernel panic if a process creates many SHM regions.

**Fix**: ~~Return `Option` or `Result` instead of panicking. Propagate error to syscall handler.~~ Already fixed: `shm_create()` returns `Option<OwnedShm>` and `sys_shm_create` handles `None` by freeing frames and returning `Err(SyscallError::Error)`. The `shm_inc_ref`/`shm_dec_ref` panics are correct per kernel convention — they take kernel-internal IDs where invalid inputs indicate a bug. Syscall handlers validate handles before reaching these functions.

---

## 2. Structural Problems

### net-stack is 3,100 lines — largest single file

**Location**: `user/net-stack/src/main.rs`

The net-stack is now 3,119 lines containing TCP state machine (~800), UDP handling (~200), ARP/DHCP (~300), socket/stream state (~400), packet RX/TX (~600), and multi-interface routing (~200). While the size reflects genuine protocol complexity (not poor design), it makes the file hard to navigate and review.

**Refactoring path**: Extract TCP state machine into `tcp.rs`, DHCP into `dhcp.rs`, and ARP into `arp.rs` within the same crate. Keep the main event loop and socket multiplexing in `main.rs`.

---

### SHM volatile helpers still duplicated (from review 6)

**Location**: `kernel/src/services/net_server.rs:44-58` and `user/net-stack/src/main.rs:62-82`

Two identical sets of `shm_read_u16/u32`, `shm_write_u16/u32` (~40 lines). Still open from review 6.

---

### service.rs spawn function duplication (from review 3)

**Location**: `lib/rvos/src/service.rs:63-191`

6 `spawn_*` functions with 85+ lines of near-identical boot-channel code. Still open from review 3.

---

### `static mut NEXT_EPHEMERAL` violates "no static mut" rule

**Location**: `user/net-stack/src/main.rs:1906-1911`

```rust
static mut NEXT_EPHEMERAL: u16 = 49152;
```

CLAUDE.md states "No static mut. Pass state through function parameters." This should be a local variable in `main()` passed as `&mut u16`.

---

## 3. Security & Isolation

| Severity | Location | Issue | Impact |
|----------|----------|-------|--------|
| MEDIUM | `user/net-stack/src/main.rs:2694` | Frame length from device SHM cast to `usize` without explicit bounds check; `.min(1534)` provides implicit safety but relies on `rx_buf` size | Implicit safety — add explicit validation |
| MEDIUM | `user/net-stack/src/main.rs:1057` | No socket port access control; any process can bind any port | Port hijacking (from review 5, still open) |
| MEDIUM | `kernel/src/mm/elf.rs:172-198` | ELF parser `.unwrap()` on `try_into()` for slice conversions | Malformed ELF panics kernel (from review 5, still open) |
| LOW | `vendor/rust/.../rvos/mod.rs:167` | IPv6 addresses silently mapped to 0.0.0.0:0 | Should return `Unsupported` error (from review 6) |

---

## 4. Performance Cliffs

| Location | Current | Should Be | Penalty |
|----------|---------|-----------|---------|
| `kernel/src/ipc/mod.rs:562` | `channel_clear_blocked_pid()` iterates all 1024 channels on every process exit | Per-process blocked-channel list | O(1024) per exit; noticeable under process churn |
| `drivers/virtio/net.rs:318` | Transmit blocks via WFI until completion | Async completion | Kernel task stalls on every TX (from review 5, still open) |
| `services/console.rs:42` | Line buffer = 256 chars, silent truncation | 1024 chars or dynamic | Long commands corrupted (from review 5, still open) |

---

## 5. Resource Exhaustion Audit

| Resource | Limit | On Exhaustion | Caller Notified? | Changed Since Review 6? | Suggested Fix |
|----------|-------|---------------|------------------|-------------------------|---------------|
| Channels (global) | **1024** | Returns None | Yes | **Yes** (64→1024 in Bug 0012 fix) | Per-process limit (32) prevents monopolization |
| Channels/process | 32 | Returns Error | Yes | **New** (Bug 0013 fix) | Adequate |
| Handles/process | 32 | Returns None | Yes | No | Consider increase to 64 |
| Processes | 64 | Returns None | Yes | No (already Option) | Adequate |
| SHM regions | 32 | Returns None | Yes | No (already Option) | Adequate |
| Page frames | ~32K | Returns None | Yes | No | Adequate |
| mmap regions/proc | 256 | Returns false | Yes (bool) | No | Change to Result |
| Message queue depth | 64 | Returns Err(QueueFull) | Yes | No | Excellent |
| Named services | 16 | Returns None | Yes | **FIXED** (587d32d) | Adequate |
| Boot registrations | 16 | Logs warning, skips | Partial | No | Adequate |
| Console clients | 8 | **Silent drop** | **No** | No | Log + reject |
| Dynamic spawns | 8 | Error response | Yes | No | Adequate |
| Net sockets | 16 | Returns error | Yes | No | Adequate |
| TCP connections | 16 | **Sends RST** | **Yes** | **FIXED** (c30df4f) | Adequate |
| TCP accept backlog | 4/listener | Silent drop | No | No | Send RST |
| Timer clients | 32 | Log + close | Yes (implicit) | No | Adequate |
| ARP cache | TTL eviction | Expires old entries | Implicit | No | Adequate |
| Pending ARP queue | 4/interface | Silent drop | No | **Changed** (now per-interface) | Adequate |
| ext2 open files | 16/client | Returns error | Yes | **New** (Bug 0021 fix) | Adequate |
| Block devices | 4 | Compile-time limit | N/A | **New** | Adequate |
| Breakpoints/process | 8 | Returns error | Yes | No | Adequate |

**Key changes from review 6**: Channel pool expanded 16x (64→1024). Per-process channel limit added (32). TCP connection exhaustion now sends RST instead of silent drop. ext2 file management redesigned with flat slot array (Bug 0021).

**Still problematic**: Console clients silently dropped.

---

## 6. API Consistency & Footguns

### Remaining sentinel values

| Pattern | Count | Locations | Impact |
|---------|-------|-----------|--------|
| `usize::MAX` for "no connection" | 4 | `net-stack/main.rs:789,790,854,856` | Sentinel for "no associated socket/conn" — use `Option<usize>` |
| `let _ = sys_chan_send(...)` | ~5 | `net-stack/main.rs` (reduced from 7 in review 6) | Silent send failures — partially fixed by be4c842 |

### `static mut` usage

| Location | Variable | Status |
|----------|----------|--------|
| ~~`net-stack/main.rs:1906`~~ | ~~`NEXT_EPHEMERAL: u16`~~ | **DONE** (ccfa500) |

---

## 7. Code Duplication

| Pattern | Instances | Lines | Fix | Status |
|---------|-----------|-------|-----|--------|
| `spawn_process*()` variants | 6 | ~130 | Extract `spawn_impl()` | Open (review #3) |
| `shm_read/write_u16/u32` | 2 identical sets | ~40 | Extract to shared lib | Open (review #6) |

---

## 8. Documentation Drift

| Doc | Claim | Actual Code | Status |
|-----|-------|-------------|--------|
| `kernel-abi.md` §10 limits | `MAX_CHANNELS = 64` | `1024` in `ipc/mod.rs:12` | **CRITICAL MISMATCH** |
| `architecture.md` Phase 4 | `MAX_CHANNELS = 32` | `1024` | **CRITICAL MISMATCH** |
| `architecture.md` | No loopback interface | Multi-interface with loopback (42647f1) | **STALE** |
| No `docs/protocols/http.md` | — | HTTP client/server implemented | **MISSING** |
| No `docs/protocols/dns.md` | — | DNS client library implemented | **MISSING** |
| No `docs/protocols/block-device.md` | — | VirtIO block driver + blk_server | **MISSING** |
| No `docs/protocols/dhcp.md` | — | DHCP client in net-stack | **MISSING** |
| `kernel-abi.md` §8 services | Missing "blk" service | blk_server registered as kernel service | **MISSING** |
| `kernel-abi.md` §8 | No spawn-suspended | Implemented in scheduler + init | **MISSING** |
| No ext2 filesystem spec | — | Full ext2 R/W server | **MISSING** |
| No platform abstraction docs | — | FDT parser, parameterized drivers | **MISSING** |

**Correct**:
- All 20 syscall numbers match between docs and code
- All build targets in CLAUDE.md match Makefile
- `docs/protocols/net-raw.md` matches implementation
- `docs/protocols/socket.md` exists and matches (added since review 6)
- `docs/protocols/timer.md` exists and matches (added since review 6)

---

## 9. Bug Pattern Analysis

Analysis of all 17 closed bugs (0001-0021, excluding 0011/0016), with special focus on the Investigation sections added in fafba7c.

### Bug distribution by class

| Pattern | Count | Bugs | Structural Prevention | Recurrence Since Fix? |
|---------|-------|------|-----------------------|-----------------------|
| Ref-counting violations | 3 | 0002, 0007, 0008 | RAII wrappers (OwnedEndpoint) | **0 recurrences** in 107 commits |
| Race conditions | 2 | 0005A, 0004 | `suppress_irq_restore()` pattern | **0 recurrences** |
| Resource exhaustion | 3 | 0012, 0013, 0015 | Pool expansion, per-process limits, VA allocator | **0 recurrences** |
| Protocol/semantic mismatch | 3 | 0001, 0006, 0021 | Flat file slot array (0021) | **0 recurrences** for 0021 |
| EOF/shutdown handling | 2 | 0003, 0010 | N/A (0010 was test artifact) | **0 recurrences** |
| Build/script issues | 3 | 0014, 0017, 0019 | Process group fixes, stdin redirect | **0 recurrences** |
| Stack overflow | 1 | 0015 | Heap allocation rule, 64 KiB stack | **0 recurrences** |

### Investigation insights from bug writeups

**Most effective debugging techniques** (from Investigation sections):
1. **Direct code reading with ownership tracing** — worked for ref-counting bugs (0002, 0007, 0008). Following the chain "who creates → who stores → who closes" reliably found the gap.
2. **Targeted `println!` instrumentation** — worked for scheduling (0005) and memory (0015). Adding prints at decision points in suspect code narrowed root cause faster than other methods.
3. **Vendor source analysis** — required for device interaction bugs (0004). Reading QEMU's `virtio_gpu_handle_ctrl_cb()` revealed BH scheduling behavior that couldn't be inferred from rvOS code alone.
4. **Git log regression identification** — useful when user reports "it used to work." Bug 0002 was identified by user pointing to specific commit.

**Dead ends encountered** (valuable for future debugging):
- Bug 0010: Extensive expect-script reproduction attempts for "spurious suspend" yielded nothing — the behavior was a test artifact.
- Bug 0019: Investigation of IPC timing misdirected attention; root cause was POSIX `&`-backgrounding redirecting stdin to `/dev/null`.
- Bug 0015: Initial hypothesis of SHM identity-map collision was wrong; kernel instrumentation revealed it was stack overflow from large `Message` locals.

### Subsystem bug density

| Subsystem | Bug Count | Most Recent | Status |
|-----------|-----------|-------------|--------|
| IPC / ref counting | 3 | 0008 | Structural fix (RAII) holding |
| Scheduler / context switch | 2 | 0005 | Structural fix holding |
| Networking | 1 | 0021 (ext2 but similar pattern) | Fixed |
| Build / scripts | 3 | 0019 | Fixed |
| GUI / compositor | 2 | 0004 | Fixed (QEMU-side) |
| Debugger | 2 | 0009 | Partially fixed |
| Memory management | 1 | 0015 | Structural fix (VA allocator) |

**Key insight**: Ref-counting was the #1 bug class (3 bugs), but the RAII wrapper migration has been **fully effective** — zero recurrences across 107 commits. The same pattern should be applied to any new resource that requires paired acquire/release.

---

## 10. Dependency & Coupling Map

### Module sizes (lines)

| Module | Lines | Change from Review 6 |
|--------|-------|---------------------|
| `user/net-stack/src/main.rs` | 3,119 | +1,084 (DHCP, DNS, loopback, multi-interface) |
| `kernel/src/task/scheduler.rs` | 1,449 | +200 (SYS_KILL, spawn-suspended, EWMA) |
| `kernel/src/services/init.rs` | 1,418 | +150 (ext2 mount, blk orchestration) |
| `user/ext2-server/src/main.rs` | 823 | **New** |
| `kernel/src/ipc/mod.rs` | 807 | +60 (per-process channel limits) |
| `user/ktest/src/main.rs` | 2,350 | +800 (ext2, timer, debugger, blk tests) |

### Blast radius of key struct changes

| Struct | Files Touched | Impact | Change Since Review 6? |
|--------|---------------|--------|------------------------|
| `Message` (ipc) | 14 files | ABI change; compile-time assertions | No change |
| `Process` (task) | 8 kernel files | Scheduler, syscalls, services, debugger | +breakpoints, +suspended flag |
| `Channel` (ipc) | 5 kernel files | Ref counting, send/recv, blocking | +per-process accounting |
| `Interface` (net-stack) | 1 file | Replaces 5 standalone variables | **New** (42647f1) |
| `TcpConn` (net-stack) | 1 file | +`iface_idx` field | **Changed** (42647f1) |

### New coupling from ext2/block stack

- `lib/rvos-proto/src/blk.rs` types used in: `kernel/src/services/blk_server.rs`, `user/ext2-server/src/main.rs`
- `lib/rvos-proto/src/fs.rs` types used in: `kernel/src/services/init.rs`, `user/ext2-server/src/main.rs`, `user/fs/src/main.rs`, `lib/rvos/src/fs.rs`
- Coupling is well-layered: protocol types → service API → user apps. **No circular dependencies.**

---

## 11. Code Quality

### Sentinel values & error handling

| Location | Current Pattern | Suggested Fix |
|----------|----------------|---------------|
| `net-stack/main.rs:789,790,854,856` | `usize::MAX` for "no connection" | `Option<usize>` or `const NO_CONN: usize = usize::MAX` |
| `net-stack/main.rs:804` | `(now_ticks() & 0xFFFF_FFFF)` raw bitmask | `const TIMESTAMP_MASK: u64` |
| `net-stack/main.rs` (~5 sites) | `let _ = sys_chan_send(...)` | Check return, deactivate socket on close (partially fixed in be4c842) |

### Low-level abstraction usage

| Location | Raw API Used | Higher-level Alternative |
|----------|-------------|--------------------------|
| `net-stack/main.rs` (event loop) | `raw::sys_chan_send`, `raw::sys_chan_recv` | Performance-justified; acceptable |
| `net-stack/main.rs` (SHM access) | Manual volatile ptr casts | Shared shm helper (see duplication §7) |
| `ext2-server/main.rs` | `raw::sys_chan_send_blocking`, `raw::sys_chan_close` | Could use `Channel` wrapper |

### RAII compliance

All new code (ext2-server, blk_server, timer service) correctly uses RAII patterns. GPU/kbd/mouse server conversion from review 6 is holding. **No new RAII violations.**

### Unsafe scope analysis

All unsafe blocks in reviewed code are necessary and minimal:
- SHM volatile reads/writes (net-stack): justified
- Heap allocation via `alloc_zeroed` + `Box::from_raw` (net-stack): follows design rule for >4 KiB allocations
- CSR writes (scheduler): necessary for hardware
- `static mut NEXT_EPHEMERAL` (net-stack): can be eliminated (see §2)

### Unchecked arithmetic on external input

| Location | Operation | Risk | Fix |
|----------|-----------|------|-----|
| `net-stack/main.rs:2694` | `shm_read_u16()` frame length cast to usize | Low (bounded by `.min(1534)`) | Add explicit `> RX_SLOT_SIZE` check before `.min()` |
| `net-stack/main.rs:633` | TCP data offset `(packet[12] >> 4)` | Low (validated by subsequent `packet.len()` check) | Reorder validation for clarity |

---

## 12. Test Coverage Gaps

### Missing regression tests

| Bug | Title | Has Regression Test? | Suggested Test |
|-----|-------|---------------------|----------------|
| 0001 | fbcon windowed mode | No (GUI-only) | Manual GUI test |
| 0002 | GUI shell dead after child exit | **Yes** (`test_two_children_shared_override`) | — |
| 0003 | Compositor FPS drop | No (GUI-only) | Manual bench |
| 0004 | GPU display hang | No (GUI-only) | Manual bench |
| 0005 | Scheduling race | Partial (`test_stress_spawn_exit`) | Explicit race collision test |
| 0006 | Debug suspend wakeup_pending | **No** | `test_debugger_suspend_resume` |
| 0007 | Debugger second attach | **Yes** (a43dfac) | — |
| 0008 | NS overrides missing inc_ref | **Yes** (`test_two_children_shared_override`) | — |
| 0009 | Debugger events require enter | **No** | Event delivery test |
| 0010 | Spurious suspend | No (test artifact) | N/A |
| 0012 | Channel exhaustion | **Yes** (structural fix) | — |
| 0013 | No per-process channel limit | **Partial** | Explicit `test_channel_per_process_limit` |
| 0014 | Worktree cargo config | No (build issue) | CI integration test |
| 0015 | SHM identity-map collision | **Yes** (structural fix) | — |
| 0017 | Orphan QEMU on signal | No (script issue) | Integration test |
| 0018 | VirtIO WFI polling | **Yes** (structural fix) | — |
| 0019 | QEMU lock stdin | No (script issue) | Integration test |
| 0021 | ext2 channel clobber | **No** | `test_ext2_concurrent_opens` |

**Summary**: 7 of 17 bugs have regression tests (41%). 5 are GUI-only or script-only (not ktestable). 5 need new tests: 0006, 0009, 0013, 0021, and a stronger 0005.

### Untested new features

| Feature | Test Coverage | Suggested Test |
|---------|--------------|----------------|
| HTTP client/server | **None** | `test_http_loopback` — server + client on same VM |
| DNS client library | **None** | `test_dns_resolve` — A record query |
| DHCP client | **None** | `test_dhcp_lease` — verify IP obtained |
| Multi-interface loopback | **None** | `test_loopback_route` — verify 127.0.0.1 delivery |
| SYS_KILL syscall | **None** | `test_kill_process`, `test_kill_invalid_pid` |
| spawn-suspended | **None** | `test_spawn_suspended_blocks` |
| Platform HAL / FDT | **None** | `test_fdt_uart_resolved` |
| TCSETFG ioctl | **None** | `test_foreground_group` |
| ext2 read-write | **Yes** (6 tests) | — |
| VFS mount | **Yes** (5 tests) | — |
| Timer service | **Yes** (2 tests) | — |
| Block device | **Yes** (5 tests) | — |

**Summary**: 8 of 12 new features lack test coverage. The 4 tested features (ext2, VFS, timer, block) have good coverage.

### Untested invariants

| Invariant | Where Stated | Tested? | Risk |
|-----------|-------------|---------|------|
| sscratch → current TrapContext | MEMORY.md | **No** | HIGH — Bug 0005 violated this |
| Lock ordering (SCHEDULER → CHANNELS) | kernel/CLAUDE.md | **No** | HIGH — no deadlock detection |
| Per-process channel limit enforcement | Bug 0013 fix | **No** | MEDIUM |
| Channel deactivation at ref_count=0 | MEMORY.md | Implicit only | MEDIUM |

### Untested error paths

| Error Path | Tested? | Risk |
|------------|---------|------|
| Process table full (>64 procs) | **No** | MEDIUM (returns None, handled gracefully) |
| SHM creation exhaustion (>32 regions) | **No** | MEDIUM (returns None, handled gracefully) |
| Global channel pool exhaustion | **No** | MEDIUM |
| ext2 disk full | **No** | HIGH |
| ext2 path > 64 bytes | **No** | HIGH (silent truncation) |
| SYS_KILL invalid PID | **No** | MEDIUM |

---

## 13. What's Good

### Multi-interface net-stack — clean architectural refactor

The replacement of 5 standalone variables (`config`, `our_mac`, `arp_table`, `shm_base`, `raw_handle`) with a typed `Interface` struct array is well-designed. The loopback implementation is elegant: loopback TX pushes directly to the interface's own RX queue, self-IP detection in `send_ip_packet()` handles the "connect to our own IP via eth0" case correctly, and per-interface state isolation makes future multi-NIC support straightforward. Functions take `&mut Interface` (single NIC ops) vs `&mut [Interface; MAX_INTERFACES]` (multi-interface ops) — good borrow-checker ergonomics.

### ext2-server Bug 0021 fix — flat file slot array

The redesign from per-client file channels to a flat `[Option<FileSlot>; MAX_OPEN_FILES]` array correctly handles concurrent file opens through a single client connection. Proper RAII cleanup on channel drop.

### RAII adoption holding steady

Zero ref-counting bugs in 107 commits. The OwnedEndpoint/OwnedShm pattern is consistently used in all new kernel service code (blk_server, timer). The structural fix from bugs 0002/0007/0008 has been fully effective.

### Platform abstraction — clean parameterization

The FDT parser and platform module cleanly extract hardware addresses from the device tree, replacing hardcoded constants. VirtIO MMIO, UART, TTY, PLIC, frame allocator, and page tables are all parameterized. This enables future board support without invasive changes.

### Debugging/observability tools

The new `kstat`, `schedlat`, `ipclat`, `chstat`, `trace`, and `dbg` commands provide comprehensive runtime visibility. Atomic counters in the kernel track scheduler, IPC, IRQ, and page allocation events without lock contention. Histogram-based latency tracking for scheduler and IPC is well-designed.

### Socket protocol — two-channel design still clean

The control+data channel pattern established in review 6 continues to work well with the new features (HTTP, DNS, DHCP). Connection lifecycle is correct.

### Zero circular dependencies — still preserved

The module dependency graph flows cleanly downward through all new code (ext2, block, platform).

### Bug investigation documentation

The addition of Investigation sections to all 17 closed bug docs (fafba7c) creates valuable institutional memory. The debugging techniques documented (ownership tracing, targeted printlns, vendor source analysis) will accelerate future debugging.

---

## 14. Priority Action Items

### Immediate (fix this week)

1. ~~**Return error from ext2-server for paths > 64 bytes** — silent truncation is a data corruption risk (MEDIUM correctness)~~ **DONE** (6bdfb9c)
2. ~~**Update `docs/kernel-abi.md` MAX_CHANNELS** — says 64, actual is 1024 (CRITICAL doc drift)~~ **DONE** (1122aa6)
3. ~~**Replace process spawn panic with error return**~~ **ALREADY FIXED** — `find_free_slot()` returns `Option`, init server handles gracefully
4. ~~**Replace SHM creation panic with error return**~~ **ALREADY FIXED** — `shm_create()` returns `Option`, syscall handler propagates error

### Soon (next sprint)

5. ~~**Add explicit frame length validation in net-stack RX** — bounds check before `.min()` (LOW safety)~~ **DONE** (dbbaeca)
6. ~~**Refactor `static mut NEXT_EPHEMERAL` to local variable** — violates design rule (LOW quality)~~ **DONE** (ccfa500)
7. **Add regression test for Bug 0013** — per-process channel limit enforcement (MEDIUM testing)
8. **Add SYS_KILL ktest** — new syscall with no test (MEDIUM testing)
9. **Add spawn-suspended ktest** — new feature with no test (MEDIUM testing)
10. **Add HTTP loopback integration ktest** — validates net-stack loopback + http-server + http-client (HIGH testing value)
11. ~~**Create missing protocol docs** — HTTP, DNS, DHCP, block device, ext2 (MEDIUM documentation)~~ **DONE** (c4a3d87)
12. ~~**Update architecture.md** — add loopback, ext2, block devices, platform abstraction (MEDIUM documentation)~~ **DONE** (1b38f49)
13. ~~**Improve http-server error handling** — return 400/413 on malformed requests (LOW robustness)~~ **DONE** (3ec4289)
14. ~~**Fix named services silent overwrite** — return error when full (MEDIUM robustness)~~ **DONE** (587d32d)

### Backlog (when convenient)

15. Split net-stack into modules (tcp.rs, dhcp.rs, arp.rs) — reduce 3100-line file
16. Extract SHM volatile helpers to shared lib (review #6 item)
17. Extract `spawn_impl()` helper (review #3 item)
18. Add socket port access control (review #5 item)
19. Add WFI timeout to VirtIO net transmit (review #5 item)
20. Replace `usize::MAX` sentinels in net-stack with `Option<usize>`
21. Add lock ordering documentation / lockdep-style checker
22. Add sscratch invariant verification test
23. Add ext2 disk-full error path test
24. Map IPv6 to `Unsupported` in std::net backend (review #6 item)
25. Increase line buffer from 256 chars (review #5 item)

### Review #6 items — status

| Item | Status |
|------|--------|
| ~~Fix timer deadline arithmetic overflow~~ | **DONE** (cbece96) |
| ~~Add FIN to TcpStream::drop~~ | **DONE** (f3207a5) |
| ~~Define CHAN_CLOSED constant~~ | **DONE** (38e2d0f) |
| ~~Replace .unwrap_or(0) with .expect()~~ | **DONE** (45aee4e) |
| ~~Buffer data-with-ACK in SynReceived~~ | **DONE** (3a7d2dc) |
| ~~Check send results in net-stack~~ | **DONE** (be4c842) |
| ~~Send RST on TCP connection exhaustion~~ | **DONE** (c30df4f) |
| ~~Handle net-server allocation failure~~ | **DONE** (c9dbc36) |
| ~~Add regression test for Bug 0007~~ | **DONE** (a43dfac) |
| ~~Add timer service ktest~~ | **DONE** (410b0c3) |
| ~~Create docs/protocols/socket.md~~ | **DONE** (44b0d80) |
| ~~Create docs/protocols/timer.md~~ | **DONE** (3bc1a1a) |
| ~~Update architecture.md + kernel-abi.md~~ | **DONE** (1122aa6, 1b38f49) |
| ~~Update README process list + syscall table~~ | **DONE** (6d8efc2) |
| ~~Replace register_service() assert with Result~~ | **DONE** (587d32d) |
| Extract SHM volatile helpers to shared lib | OPEN |
| Extract spawn_impl() helper | OPEN |
| Add TCP state machine tests | OPEN (partial coverage via integration) |
| Add socket exhaustion tests | OPEN |
| Map IPv6 to Unsupported in std::net backend | OPEN |
| Define EPHEMERAL_PORT_MIN/MAX constants | OPEN |
| ~~Replace static mut NEXT_EPHEMERAL~~ | **DONE** (ccfa500) |
| Add #[must_use] to IPC functions | OPEN |
| Document lock ordering | OPEN |
| VirtIO net transmit WFI timeout | OPEN |
| Socket port access control | OPEN |

**Completion rate**: 15 of 26 review 6 items completed (58%). All HIGH-priority items completed.
