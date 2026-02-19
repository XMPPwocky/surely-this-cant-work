# Architecture Review 5 — 2026-02-19

Scope: 21 commits since arch-review-4 (454e24e..4bce967). Major features: UDP networking (VirtIO net driver, kernel net-server, userspace net-stack, udp-echo demo), RAII ref-counting wrappers (OwnedEndpoint/OwnedShm), ktest regression tests for past bugs, bug fixes (0006–0010), syscall extraction into arch/syscall/ submodule.

Codebase: ~25,296 lines of Rust + assembly across kernel/, user/, and lib/.

Methodology: 9 parallel reviewers (kernel core, IPC & channels, kernel services, network stack specialist, user apps & std PAL, docs vs implementation, build system & toolchain, bug history & patterns, failure & exhaustion analysis). Special focus on the network stack and unidiomatic error handling (sentinel values instead of Result).

---

## 1. Correctness Bugs (Fix Now)

### HIGH: Memory ordering races in SHM ring control block (kernel↔userspace)

**Location**: `kernel/src/services/net_server.rs:160-180`, `user/net-stack/src/main.rs:818-830` (RX path), `user/net-stack/src/main.rs:196-224` (TX path)

**Problem**: The SHM ring buffer shared between net_server (kernel) and net-stack (userspace) uses control indices (rx_head, rx_tail, tx_head, tx_tail) without correct memory ordering fences.

In the RX path, the kernel writes frame data then issues a Release fence before advancing rx_head. But user-space reads rx_head/rx_tail *before* the Acquire fence (line 824), allowing the CPU to reorder frame data reads before the index reads are visible:

```rust
// user/net-stack/src/main.rs:818-824
let rx_head = shm_read_u32(shm_base, CTRL_RX_HEAD);  // no fence before this
let rx_tail = shm_read_u32(shm_base, CTRL_RX_TAIL);
if rx_head == rx_tail { break; }
handled = true;
core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);  // TOO LATE
```

The same pattern occurs in the TX path (lines 196-224): the kernel reads tx_head/tx_tail then reads frame data, but the Acquire fence is placed after the data reads.

**Impact**: On weakly-ordered CPUs (RISC-V is weakly ordered), user-space can read stale/partial frame data from the SHM ring, causing silent data corruption in received packets or corrupted transmitted packets.

**Fix**: Move the Acquire fence *before* reading ring indices in both RX consumer and TX consumer paths:

```rust
core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
let rx_head = shm_read_u32(shm_base, CTRL_RX_HEAD);
let rx_tail = shm_read_u32(shm_base, CTRL_RX_TAIL);
// Now frame data reads are guaranteed to see the writer's stores
```

---

### HIGH: Integer underflow in VirtIO net driver frame length

**Location**: `kernel/src/drivers/virtio/net.rs:238-242`

**Problem**: `poll_rx()` subtracts `VIRTIO_NET_HDR_SIZE` (10) from `total_len` without checking for underflow:

```rust
let frame_len = total_len as usize - VIRTIO_NET_HDR_SIZE;
```

If the device returns `total_len < 10`, this wraps to a huge value on 64-bit, causing `net_server` to attempt a massive `copy_nonoverlapping` from device buffer memory.

**Impact**: Buffer over-read from device memory; potential kernel crash or data corruption. A malicious or buggy device could trigger this.

**Fix**: Add checked subtraction:
```rust
let frame_len = match (total_len as usize).checked_sub(VIRTIO_NET_HDR_SIZE) {
    Some(len) if len > 0 => len,
    _ => { requeue_rx(desc_idx); return None; }
};
```

---

### HIGH: Silent RX frame truncation without notification

**Location**: `kernel/src/services/net_server.rs:167-176`

**Problem**: When a received frame exceeds `RX_SLOT_SIZE - 2` (1534 bytes), it is silently truncated:

```rust
let copy_len = frame_len.min(RX_SLOT_SIZE - 2);
shm_write_u16(shm_base, slot_offset, copy_len as u16);
```

The size field written to SHM contains the truncated length. The user-space stack has no way to detect that data was lost.

**Impact**: Applications receive truncated UDP datagrams without awareness, causing silent data corruption for payloads near the MTU limit.

**Fix**: Drop oversized frames and log a warning, or increase `RX_SLOT_SIZE` to accommodate maximum Ethernet frames (1518 + VLAN tag = 1522 bytes, well within 1534).

---

### HIGH: SHM region size calculation may be too tight

**Location**: `kernel/src/services/net_server.rs:62-73`

**Problem**: The SHM region allocates 4 pages (16,384 bytes). The layout is: control block (64 bytes at offset 0) + RX ring (8 × 1536 = 12,288 bytes at offset 0x40) + TX ring (2 × 1536 = 3,072 bytes at offset 0x3040). Total: 64 + 12,288 + 3,072 = 15,424 bytes. The last TX slot ends at byte 15,424, which fits within 16,384. However, there is no compile-time or runtime assertion verifying this, and any increase to slot sizes or counts could silently overflow.

**Fix**: Add a static assertion:
```rust
const _: () = assert!(
    CTRL_SIZE + RX_SLOTS * RX_SLOT_SIZE + TX_SLOTS * TX_SLOT_SIZE <= 4 * 4096,
    "SHM ring layout exceeds allocated size"
);
```

---

### HIGH: Missing IPv4 total_length >= header_length validation

**Location**: `user/net-stack/src/main.rs:270-295`

**Problem**: The IPv4 parser validates `total_len > packet.len()` but never checks `total_len >= hdr_len`. A malformed packet with `total_len < hdr_len` causes the payload slice `&packet[hdr_len..total_len as usize]` to panic (inverted range).

**Fix**: Add validation:
```rust
if (total_len as usize) < hdr_len {
    return None;
}
```

---

### MEDIUM: No UDP checksum validation

**Location**: `user/net-stack/src/main.rs:365-377`

**Problem**: UDP checksum is completely ignored. While IPv4 UDP checksums are optional when set to 0, non-zero checksums should be validated. Corrupted packets from transmission errors are silently accepted.

**Fix**: When the checksum field is non-zero, compute and verify the UDP pseudo-header checksum per RFC 768.

---

### MEDIUM: TX ring full causes silent packet drop

**Location**: `user/net-stack/src/main.rs:461-485`

**Problem**: When the TX ring is full (only 2 slots), `tx_frame()` silently returns without transmitting. The caller (including SendTo response paths) has no indication the frame was dropped.

**Fix**: Return a bool from `tx_frame()` and propagate failure to the application via `NetResponse::Error`.

---

### MEDIUM: No ARP cache timeout or invalidation

**Location**: `user/net-stack/src/main.rs:105-159`

**Problem**: ARP entries are never expired. Stale entries persist until evicted by the 8-entry FIFO cache. If a host's MAC changes, the stack sends to the old MAC indefinitely.

**Fix**: Add a timestamp field to `ArpEntry` and expire entries after a configurable TTL (RFC 826 suggests ~300s). Requires a clock source (SYS_CLOCK syscall is available).

---

### MEDIUM: VirtIO net transmit() blocks forever via WFI

**Location**: `kernel/src/drivers/virtio/net.rs:318-328`

**Problem**: `transmit()` loops on WFI waiting for the device to complete. If the device hangs, the kernel task blocks indefinitely with no timeout.

**Fix**: Add a timeout counter using the CLINT timer; return `false` after N iterations.

---

### MEDIUM: Pending ARP queue has no backoff or expiry

**Location**: `user/net-stack/src/main.rs:939-955`

**Problem**: Unresolved ARP entries trigger repeated ARP requests every main-loop iteration (no backoff). With only 4 pending slots (`MAX_PENDING`), a single unreachable host fills the queue and blocks all new outbound traffic.

**Fix**: Add retry count, exponential backoff, and a maximum retry limit (e.g., 5 attempts). Drop packets and notify the client after exhaustion.

---

## 2. Structural Problems

### Pervasive sentinel-value error handling instead of Result

**Location**: System-wide across syscall layer, user libraries, and applications

The most significant structural problem is the widespread use of sentinel values (`usize::MAX`, `0`, `-1`, bare integer codes) instead of Rust's `Result` type for error handling. This affects 5 distinct layers:

**Layer 1 — Kernel syscall handlers** (`kernel/src/arch/syscall/chan.rs`, `mem.rs`):
All syscall handlers return raw `usize` with undocumented magic numbers: `0` = success, `1` = empty, `2` = closed, `5` = queue full, `usize::MAX` = generic error. These appear as bare literals (`=> 5,`) without named constants or inline documentation. ~30 return sites across 2 files.

**Layer 2 — User-space raw syscall wrappers** (`lib/rvos/src/raw.rs`):
Wrappers like `sys_chan_recv_blocking()` return raw `usize` with inconsistent documentation. Some document error codes; others don't.

**Layer 3 — Typed channel API** (`lib/rvos/src/channel.rs:273-280`):
`recv_blocking()` maps all non-zero, non-2 error codes to `RecvError::Closed` via a catch-all `_ => Err(RecvError::Closed)`. This masks `InvalidHandle`, `NoResources`, `BadAddress`, and `QueueFull` errors.

**Layer 4 — Library functions** (`lib/rvos/src/tty.rs:7-31`, `lib/rvos/src/fs.rs:29`):
`tty::ioctl()` returns `-1` for 3 distinct failure modes (invalid handle, syscall failure, decode error). `fs::file_open_raw()` maps all RPC errors to `SysError::NoResources`.

**Layer 5 — Applications** (`user/net-stack/src/main.rs`, `user/udp-echo/src/main.rs`):
net-stack ignores return codes with `let _ = raw::sys_chan_send(...)` at 6+ call sites. udp-echo uses `.unwrap()` on all channel operations (3 sites). net-stack initialization (lines 760, 764) ignores blocking syscall return codes entirely.

**Refactoring path**:
1. Define named constants for syscall return codes (`SUCCESS = 0`, `CHANNEL_CLOSED = 2`, `QUEUE_FULL = 5`, etc.)
2. Have syscall handlers return `Result<usize, SyscallError>` internally, converting at the ABI boundary
3. Add `SysError` variant to `RecvError`/`SendError` to preserve error information through the typed channel API
4. Replace `tty::ioctl() -> i32` with `tty::ioctl() -> Result<i32, TtyError>`
5. Replace `let _ =` patterns in net-stack with explicit error checking

---

### Network stack architecture: clean separation, weak error flow

The network stack has a well-designed three-layer architecture (VirtIO driver → kernel net-server → user-space net-stack → applications) with clean IPC boundaries and appropriate use of SHM for bulk data transfer. However, errors flow only downward (silent drops) with no upward backpressure:

- Driver → net-server: frame too short → no notification
- net-server → net-stack: RX ring full → frame requeued, no doorbell
- net-stack → application: TX ring full → silent drop; truncated payload → `unwrap_or(0)`

Every layer silently absorbs errors rather than propagating them.

---

### Raw endpoint IDs in gpu_server, kbd_server, mouse_server (from review #4, still open)

**Location**: `kernel/src/services/gpu_server.rs`, `kbd_server.rs`, `mouse_server.rs`

These 3 services store raw endpoint IDs instead of `OwnedEndpoint`. While kernel task endpoints are cleaned up on process exit, this violates the RAII convention documented in CLAUDE.md and creates inconsistency with `sysinfo.rs` and `math.rs` which correctly use `OwnedEndpoint`.

---

### service.rs spawn function duplication (from review #3, still open)

**Location**: `lib/rvos/src/service.rs:63-191`

6 `spawn_*` functions with 85+ lines of near-identical boot-channel code.

---

## 3. Security & Isolation

| Severity | Location | Issue | Impact |
|----------|----------|-------|--------|
| HIGH | `net-stack/main.rs:662-679` | No socket port access control; any process can bind port 53, 67, etc. | Port hijacking of well-known services |
| HIGH | `net-stack/main.rs:270-295` | No IP fragmentation handling; malformed fragment offsets not validated | Potential crash on crafted packets |
| MEDIUM | `kernel/src/mm/elf.rs:172-198` | ELF parser uses `.unwrap()` on `try_into()` for slice conversions | Malformed ELF binary panics the kernel |
| MEDIUM | `kernel/src/services/net_server.rs:167` | Frame truncation writes to SHM without bounds assertion | Edge case could write beyond SHM boundary |
| MEDIUM | `kernel/src/arch/syscall/mem.rs:102-120` | Partial mmap failure cleanup can panic in `unmap()` | User-triggerable kernel panic via OOM |
| LOW | `net-stack/main.rs:25-28` | Hardcoded IP/gateway/netmask (QEMU-only) | Not a security issue, but limits deployment |
| LOW | `drivers/virtio/net.rs:83-92` | No MAC address validation (all-zeros, all-ones, multicast) | Malformed MAC causes ARP issues |

---

## 4. Performance Cliffs

| Location | Current | Should Be | Penalty |
|----------|---------|-----------|---------|
| `net_server.rs:22` | TX ring = 2 slots | 8–16 slots | 4–8x throughput reduction under burst; silent drops when full |
| `net-stack/main.rs:939-955` | ARP retry every iteration, no backoff | Exponential backoff with 5-retry limit | Potential ARP storm consuming all TX bandwidth |
| `net-stack/main.rs:612` | UDP payload truncated to fixed 900 bytes | Use `msg.data.len() - header_overhead` | Wastes ~100 bytes of available message space per datagram |
| `drivers/virtio/net.rs:318` | Transmit blocks via WFI until completion | Async transmit with completion callback | Kernel task stalls on every packet send |
| `net-stack/main.rs:105` | ARP cache = 8 entries, FIFO eviction | LRU eviction, 32+ entries | Frequent ARP re-resolution under moderate peer count |
| `services/console.rs:42` | Line buffer = 256 chars, silent truncation | 1024 chars or dynamic allocation | Long commands silently corrupted |

---

## 5. Resource Exhaustion Audit

| Resource | Limit | On Exhaustion | Caller Notified? | Uses Result? | Suggested Fix |
|----------|-------|---------------|------------------|--------------|---------------|
| Channels | 64 | Logs warning, returns None | Yes (Option) | Yes | Adequate. Add metrics. |
| Handles/process | 32 | Returns None | Yes (Option) | Yes | Adequate. No test coverage. |
| Processes | 64 | Returns None | Yes (Option) | Yes | Adequate. No test coverage. |
| Page frames | ~32K | Returns None | Yes (Option) | Yes | Good. Process spawn panics on failure (see review #4). |
| mmap regions/proc | 256 | Returns false | Yes (bool) | **No** | Change to `Result<(), &'static str>` |
| Message queue depth | 64 | Returns Err(QueueFull) | Yes | Yes | Excellent. Has backpressure. |
| Named services | 12 | **Panics** (assert!) | **No** | **No** | Replace assert with Result; allow graceful degradation |
| Boot registrations | 16 | Logs warning, skips | Partial (log only) | **No** | Increase to 32+; return Result to prevent deadlock |
| Console clients | 8 | Logs warning, drops client | Partial (log only) | **No** | Increase to 16; send rejection to client |
| FS launch contexts | 8 | Silent drop | **No** | **No** | Return error to spawn requester |
| Dynamic spawn pending | 8 | Silent drop | **No** | **No** | Return error; requester hangs forever otherwise |
| IPC message payload | 1024 bytes | **Silent truncation** | **No** | **No** | Return error if message too large |
| Caps per message | 4 | **Silent drop of excess** | **No** | **No** | Return error if caps.len() > MAX_CAPS |
| Net RX ring (SHM) | 8 slots | Requeues to driver | Implicit | N/A | Adequate. Add drop counter. |
| Net TX ring (SHM) | 2 slots | Silent drop by client | **No** | **No** | Increase to 8; return error from tx_frame() |
| ARP cache | 8 entries | FIFO eviction | No | N/A | Increase to 32; add LRU |
| Pending ARP queue | 4 packets | Silent drop | **No** | **No** | Add retry limit; notify client of failure |
| Net sockets | 8 | Returns error | Yes | Partial | Adequate. |
| Breakpoints/proc | 8 | Sends error | Yes | Implicit | Adequate. |
| TTY line buffer | 256 chars | Silent truncation | **No** | **No** | Ring bell or send backspace on overflow |

**Critical pattern**: 7 resources use "silent drop" on exhaustion with no caller notification. This is the primary error-handling weakness in the codebase.

---

## 6. API Consistency & Footguns

### Functions returning sentinel values instead of Result

| Function | Returns | Sentinel | Should Return | File |
|----------|---------|----------|---------------|------|
| `sys_chan_create` | `usize` | `usize::MAX` | `Result<(usize, usize), SyscallError>` | `syscall/chan.rs:13` |
| `sys_chan_send` | `usize` | `0/5/usize::MAX` | `Result<(), SendError>` | `syscall/chan.rs:118` |
| `sys_chan_recv` | `usize` | `0/1/2/usize::MAX` | `Result<(), RecvError>` | `syscall/chan.rs:146` |
| `sys_mmap` | `usize` | `usize::MAX` | `Result<usize, MmapError>` | `syscall/mem.rs:9` |
| `tty::ioctl` | `i32` | `-1` | `Result<i32, TtyError>` | `lib/rvos/src/tty.rs:7` |
| `request_service` (shell) | `usize` | `usize::MAX` | `Result<usize, ConnectError>` | `user/shell/src/shell.rs:17` |
| `add_mmap_region` | `bool` | `false` | `Result<(), &'static str>` | `task/process.rs` |
| `connect_to_service` (PAL) | `Option<usize>` | `None` | `Result<usize, SysError>` | `vendor/.../ipc.rs:98` |

### Silent error swallowing patterns

| Pattern | Count | Locations | Impact |
|---------|-------|-----------|--------|
| `let _ = sys_chan_send(...)` | 6+ | `net-stack/main.rs:484,626,678,696,709,723` | Send failures silently ignored; clients hang |
| `.unwrap_or(0)` on serialization | 11 | `net-stack/main.rs:483,615,667,...` | Empty messages sent on encode failure |
| `.unwrap()` on channel ops | 3 | `udp-echo/main.rs:23,44,71` | Panics on any channel error |
| Ignored blocking syscall returns | 2 | `net-stack/main.rs:760,764` | Init hangs if send fails |
| `_ => Err(RecvError::Closed)` catch-all | 1 | `lib/rvos/channel.rs:278` | All errors mapped to "Closed" |

### Missing RAII wrappers / cleanup-on-drop

| Resource | Has RAII? | Location |
|----------|-----------|----------|
| Channel endpoints (kernel) | Yes (OwnedEndpoint) | `ipc/owned.rs` |
| SHM regions | Yes (OwnedShm) | `ipc/owned.rs` |
| FsLaunchCtx endpoints | **Manual** (raw usize + Drop) | `services/init.rs:193-244` |
| Console client endpoints | **Manual** (raw usize + from_raw in cleanup) | `services/console.rs:134-153` |
| GPU/kbd/mouse endpoints | **None** (raw usize, no cleanup) | gpu_server.rs, kbd_server.rs, mouse_server.rs |

---

## 7. Code Duplication

| Pattern | Instances | Lines | Fix |
|---------|-----------|-------|-----|
| `spawn_process*()` variants | 6 | ~130 | Extract `spawn_impl()` with optional caps/args/overrides (review #3 item, still open) |
| `shm_read_u16/u32 + shm_write_u16/u32` | 2 identical sets | ~40 | Defined in both `net_server.rs:30-56` and `net-stack/main.rs:57-95`; extract to shared lib |
| Blocking recv loop pattern | 4 | ~60 | `sys_chan_recv_blocking`, `sys_chan_send_blocking`, `accept_client`, `channel_recv_blocking` all use the same check→block→retry loop |
| `to_bytes(...).unwrap_or(0)` + send | 11 | ~55 | Extract `send_response()` helper that handles encode failure |

---

## 8. Documentation Drift

| Doc | Claim | Actual Code |
|-----|-------|-------------|
| `architecture.md` §5 service list | 7 kernel tasks listed; no net-server | `main.rs:176-181` spawns net-server conditionally; registered as "net-raw" |
| `architecture.md` service topology diagram | Shows init→serial-con, fb-con, sysinfo, math | Missing: net-raw, process-debug, gpu, kbd, mouse |
| `kernel-abi.md` §7 Available Services | 4 services: stdio, sysinfo, math, fs | Actual: 9 services (+ gpu, kbd, mouse, process-debug, net-raw) |
| `kernel-abi.md` §2 syscall table | 18 syscalls listed | 20 in code: missing SYS_CHAN_POLL_ADD (208), SYS_BLOCK (209) |
| `architecture.md` §3 trap handling | Stack-based trap frames; sscratch zero-check | Per-task TrapContext (commit 4fbec34); sstatus.SPP for mode detection |
| No network protocol doc | — | `net_server.rs` + `net-stack/main.rs` implement full SHM ring protocol with no corresponding `docs/protocols/net-raw.md` |
| No RAII adoption status doc | CLAUDE.md states convention | gpu_server, kbd_server, mouse_server violate it; no tracking |

---

## 9. Bug Pattern Analysis

| Pattern | Count | Most Recent | Structural Prevention |
|---------|-------|-------------|----------------------|
| Ref counting violations | 4 | Bug 0008 | RAII wrappers (commit 28cd40d) — **0 recurrences post-fix** |
| Race conditions | 2 | Bug 0005a | `suppress_irq_restore()` pattern |
| Resource exhaustion / busy-wait | 2 | Bug 0004 | WFI-based polling convention |
| Silent error drops | 2 | Bug 0009 | No structural fix yet — **this is the active bug class** |
| Protocol/API misuse | 1 | Bug 0006 | `force_block_process()` for debug operations |
| Multi-channel blocking | 1 | Bug 0009 | `sys_chan_poll_add` + `sys_block` pattern |

**Key insight**: The RAII wrapper migration (commit 28cd40d) successfully eliminated the ref-counting bug class (4 bugs, 0 recurrences). The **active recurring pattern** is now **silent error handling** — functions that return sentinel values or ignore error codes. The network stack, being newest code, is the worst offender (6+ `let _ =` sites, 11 `.unwrap_or(0)` sites, 2 ignored blocking returns). This mirrors the pre-RAII era where manual ref counting was "the way things were done" until structural enforcement was added.

**Recommendation**: The same approach that fixed ref counting (RAII wrappers making the wrong thing impossible) should be applied to error handling: define `Result`-returning internal APIs that make ignoring errors a compile-time error via `#[must_use]`.

---

## 10. Dependency & Coupling Map

### Blast radius of key struct changes

| Struct | Files touched | Impact |
|--------|---------------|--------|
| `Message` (ipc) | 14 files across kernel/lib/user/vendor | ABI change; requires synchronized update of 4 compile-time assertion sites |
| `Process` (task) | 8 kernel files | Scheduler, syscalls, services, debugger all depend on field layout |
| `Channel` (ipc) | 5 kernel files | Ref counting, send/recv, blocking, transport, owned |
| `TrapContext` | 4 files + assembly | trap.rs, scheduler.rs, process.rs, trap.S; field offsets are hardcoded in asm |

### Files that change together (from git history)

- `init.rs` + `ipc/mod.rs` — 3 bug fixes (0002, 0008, cap transfer issues)
- `scheduler.rs` + `spinlock.rs` — 2 bug fixes (0005a race, preempt)
- `proc_debug.rs` + `trap.rs` — 2 bug fixes (0006, 0007)

### Hidden coupling through globals

| Global | Location | Accessed by |
|--------|----------|-------------|
| `SCHEDULER` (SpinLock) | `task/scheduler.rs` | All syscall handlers, timer interrupt, services (via wake_process) |
| `NET` (static mut) | `drivers/virtio/net.rs` | net_server only (good isolation) |
| `GPU`, `KEYBOARD`, `TABLET` | `drivers/virtio/*.rs` | Respective servers only (good isolation) |
| `CHANNELS`, `SHM_REGIONS` | `ipc/mod.rs` | All IPC operations; protected by SpinLock |
| `NET_CONTROL_EP` (AtomicUsize) | `services/net_server.rs:29` | kmain (set) + net_server task (read); `usize::MAX` sentinel for uninitialized |

### Module dependency flow

All dependencies flow downward: `services → ipc → task → mm → sync → arch`. **No circular dependencies.** This excellent property is preserved since review #4.

---

## 11. What's Good

### RAII ref-counting wrappers (28cd40d) — structural bug prevention

The migration to `OwnedEndpoint` and `OwnedShm` eliminated the most frequent bug class (4 instances of ref counting violations). Zero recurrences in the 10 days since introduction. The RAII invariant is documented in CLAUDE.md and enforced through code review. `KernelTransport::send()` correctly uses `OwnedEndpoint::clone_from_raw()` for capability transfers.

### Network stack layer separation

The three-layer architecture (VirtIO driver → kernel net-server → user-space net-stack) has clean boundaries. The VirtIO driver is isolated behind a simple API (`init()`, `poll_rx()`, `transmit()`, `requeue_rx()`). The SHM ring buffer avoids per-packet IPC overhead. Capability-based SHM access ensures only authorized processes can read/write the ring.

### Syscall extraction into arch/syscall/ submodule (0281788)

The review #4 recommendation to extract trap.rs syscall handlers was completed. The 1,139-line god module is now split into `chan.rs`, `mem.rs`, `misc.rs`, and `mod.rs` with clean dispatch. This significantly improves auditability.

### Ktest regression suite (364b7cd)

Regression tests for past kernel bugs (bugs 0002, 0005, 0008) with memory leak detection and benchmark thresholds. The expect-based serial testing infrastructure enables automated CI.

### Process exit cleanup ordering (scheduler.rs)

The exit sequence correctly snapshots state under lock, releases the lock before calling `channel_close` (avoiding SCHEDULER↔CHANNELS deadlock), and explicitly drops heap-allocated Vecs before `schedule()`. Well-documented with inline comments.

### Zero circular dependencies — preserved

Module dependency graph still flows cleanly downward with no cycles. The new net_server and net driver maintain this property.

### Compile-time ABI assertions — expanded

Message size and layout assertions now cover all 4 definition sites (kernel, lib/rvos, lib/rvos-wire, vendor/rust PAL), catching ABI drift at compile time.

---

## 12. Priority Action Items

### Immediate (fix this week)

1. **Fix memory ordering in SHM ring control block** — Move Acquire fences before index reads in net-stack RX and TX consumer paths (HIGH correctness)
2. **Add checked subtraction in VirtIO net poll_rx()** — Prevent integer underflow on short frames (HIGH correctness)
3. **Add static assertion for SHM ring layout size** — Prevent silent buffer overflow on constant changes (HIGH safety)
4. **Add IPv4 total_len >= hdr_len validation** — Prevent panic on malformed packets (HIGH correctness)
5. **Define named constants for syscall return codes** — Replace bare literals (`5`, `2`, `usize::MAX`) with `QUEUE_FULL`, `CHANNEL_CLOSED`, `ERROR` (HIGH maintainability)

### Soon (next sprint)

6. **Add error checking to net-stack syscall returns** — Replace `let _ =` with explicit error handling at 6+ sites (HIGH reliability)
7. **Replace `.unwrap()` in udp-echo with error handling** — 3 panic sites on channel operations (HIGH reliability)
8. **Add `SysError` variant to `RecvError`/`SendError`** — Stop mapping all errors to `Closed` in `channel.rs:278` (MEDIUM correctness)
9. **Replace `tty::ioctl() -> i32` with `Result<i32, TtyError>`** — Eliminate `-1` sentinel value (MEDIUM idiom)
10. **Add UDP checksum validation for non-zero checksums** — RFC 768 compliance (MEDIUM correctness)
11. **Implement ARP cache TTL and retry backoff** — Prevent stale entries and ARP storms (MEDIUM reliability)
12. **Increase TX ring from 2 to 8 slots** — Reduce silent packet drops under burst (MEDIUM performance)
13. **Create `docs/protocols/net-raw.md`** — Document SHM ring buffer layout and request/response format (MEDIUM documentation)
14. **Update architecture.md service list and topology** — Add net-raw, process-debug, and other missing services (MEDIUM documentation)
15. **Update kernel-abi.md syscall table** — Add SYS_CHAN_POLL_ADD (208) and SYS_BLOCK (209) (MEDIUM documentation)
16. **Convert gpu_server/kbd_server/mouse_server to OwnedEndpoint** — (MEDIUM consistency, from review #4)

### Backlog (when convenient)

17. Replace `register_service()` assert with Result — prevent boot panic on service overflow
18. Increase `MAX_BOOT_REGS` from 16 to 32 — prevent deadlock on >16 processes
19. Return error (not silent drop) for oversized IPC messages and excess capabilities
20. Add exhaustion tests: channels, handles, processes, mmap regions
21. Extract `spawn_impl()` helper to deduplicate service.rs (review #3 item)
22. Add `#[must_use]` to all Result-returning IPC functions (review #4 item)
23. Add WFI timeout to VirtIO net `transmit()` — prevent kernel hang on device failure
24. Document lock ordering in kernel/LOCK_ORDERING.md (review #4 item)
25. Add transmit timeout and error return to net driver
26. Implement socket port access control (reject privileged ports without capability)
27. Standardize wire-format error responses (review #4 item)

### Review #4 items — status

| Item | Status |
|------|--------|
| ~~Add `channel_inc_ref()` to `send_ok_with_cap()` (7 sites)~~ | **DONE** (28cd40d — RAII wrappers) |
| ~~Add rollback to SYS_CHAN_CREATE handle allocation~~ | **DONE** (2bba857) |
| ~~Replace panics with Result in Process::new_kernel/new_user_elf~~ | **DONE** (2bba857) |
| ~~Replace panic in find_free_slot with Option~~ | **DONE** (2bba857) |
| ~~Fix integer underflow in ustack_ppn~~ | **DONE** (2bba857) |
| ~~Extract trap.rs syscall handlers into arch/syscall/~~ | **DONE** (0281788) |
| ~~Fix `KernelTransport::send()` cap inc_ref~~ | **DONE** (28cd40d — uses clone_from_raw) |
| ~~Replace page_table.rs `.expect()` with error propagation~~ | **DONE** (1cc087e) |
| ~~Fix hardcoded `x86_64-unknown-linux-gnu` in Makefile~~ | **DONE** (1cc087e) |
| Update architecture.md trap handling sections | OPEN |
| Convert gpu/kbd/mouse servers to OwnedEndpoint | OPEN |
| Extract service.rs spawn duplication | OPEN |
| Document lock ordering | OPEN |
| Add `#[must_use]` to IPC functions | OPEN |
| Standardize wire-format error responses | OPEN |
| Syscall numbers not centralized | OPEN → superseded by "named constants for return codes" (item #5 above) |
