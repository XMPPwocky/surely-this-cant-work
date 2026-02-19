# Architecture Review 6 — 2026-02-19

Scope: 24 commits since arch-review-5 (f5ea073..77e664a). Major features: TCP state machine, socket protocol/API (UdpSocket, TcpListener, TcpStream), timer kernel service, std::net backend for rvOS, OwnedEndpoint conversion for GPU/kbd/mouse servers, sentinel→Result migration completion, ARP cache TTL, TX ring increase (2→4 slots), SHM bump to 5 pages, net-raw protocol documentation, kernel-abi and architecture doc updates.

Codebase: ~27,505 lines of Rust + assembly across kernel/, user/, and lib/.

Methodology: 6 parallel reviewers (kernel internals, services & applications, cross-cutting analysis, code quality, test coverage, docs & build). Special focus on TCP state machine correctness, socket lifecycle, and review 5 item completion.

---

## 1. Correctness Bugs (Fix Now)

### HIGH: Timer deadline arithmetic overflow

**Location**: `kernel/src/services/timer.rs:140`

**Problem**: The timer service calculates deadlines as `now + duration_us * TICKS_PER_US` where `TICKS_PER_US = 10`. If a client sends `duration_us` near `u64::MAX`, the multiplication `u64::MAX * 10` overflows, producing an incorrect deadline in the past. Since `duration_us` comes from user input via deserialization, any process can trigger this.

```rust
c.deadline = now + duration_us * TICKS_PER_US;  // overflow on large duration_us
```

**Impact**: On debug builds, panic. On release builds, silent wrap to a small value — the timer fires immediately or at an incorrect time. A malicious process could crash the timer service (debug) or cause unexpected behavior.

**Fix**: Use saturating arithmetic:
```rust
c.deadline = now.saturating_add(duration_us.saturating_mul(TICKS_PER_US));
```

---

### HIGH: TcpStream::drop doesn't send FIN — connection lingers in TIME_WAIT

**Location**: `vendor/rust/library/std/src/sys/net/connection/rvos/tcpstream.rs:191-194`

**Problem**: The `Drop` implementation only closes the channel handle:
```rust
impl Drop for TcpStream {
    fn drop(&mut self) {
        syscall_close(self.handle);
    }
}
```

The remote end never receives a FIN or RST. The TCP connection on the net-stack side enters TIME_WAIT (2 seconds) or stays ESTABLISHED until the retransmit timer expires (up to 8 retransmissions × exponential backoff). With only 16 TCP connection slots (`MAX_TCP_CONNS`), rapid connect/drop cycles exhaust the pool.

**Impact**: Connection slot exhaustion under moderate load. The same issue affects `UdpSocket::drop` and `TcpListener::drop` — though those are less critical since UDP is stateless and listener cleanup is simpler.

**Fix**: Send a Shutdown request before closing:
```rust
impl Drop for TcpStream {
    fn drop(&mut self) {
        // Best-effort FIN; errors ignored since we're dropping
        let _ = self.shutdown(Shutdown::Both);
        syscall_close(self.handle);
    }
}
```

---

### MEDIUM: TCP SynReceived state discards data piggybacked on handshake ACK

**Location**: `user/net-stack/src/main.rs:1359-1393`

**Problem**: When transitioning from SynReceived to Established, the handler validates the ACK and updates state but discards any data payload in the packet. RFC 793 Section 3.9 permits data in the handshake-completing ACK. The data is silently lost.

**Impact**: Rare in practice (most TCP stacks send data only after the handshake), but causes silent data loss when it occurs. Breaks RFC conformance.

**Fix**: After transitioning to Established (line 1368), check for data and buffer it:
```rust
if !data.is_empty() && tcp.seq == conn.rcv_nxt {
    let space = conn.recv_buf.len() - conn.recv_len;
    let copy_len = data.len().min(space);
    conn.recv_buf[conn.recv_len..conn.recv_len + copy_len]
        .copy_from_slice(&data[..copy_len]);
    conn.recv_len += copy_len;
    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(copy_len as u32);
}
```

---

### MEDIUM: Net server panics on physical memory exhaustion

**Location**: `kernel/src/services/net_server.rs:70-71, 83-84, 87-88`

**Problem**: Three `expect()` calls panic if resources are unavailable:
```rust
frame_alloc_contiguous(SHM_PAGE_COUNT).expect("net_server: failed to allocate...");
ipc::shm_create(shm_ppn, SHM_PAGE_COUNT).expect("net_server: failed to create...");
mac_address().expect("net_server: no net device");
```

Physical memory exhaustion or fragmentation is a legitimate runtime condition. Panicking kills the entire network service for all processes.

**Impact**: User-triggerable service crash if memory is tight at boot.

**Fix**: Return gracefully (log and exit):
```rust
let shm_ppn = match frame::frame_alloc_contiguous(SHM_PAGE_COUNT) {
    Some(ppn) => ppn,
    None => { crate::println!("[net-server] OOM, shutting down"); return; }
};
```

---

## 2. Structural Problems

### SHM volatile helpers duplicated between kernel and user-space

**Location**: `kernel/src/services/net_server.rs:44-58` and `user/net-stack/src/main.rs:62-82`

Two identical sets of `shm_read_u16`, `shm_write_u16`, `shm_read_u32`, `shm_write_u32` functions (~40 lines total). Both use the same volatile read/write pattern.

**Refactoring path**: Extract to `lib/rvos/src/shm.rs` or `lib/rvos-wire/src/shm.rs`. The kernel already uses `lib/rvos-wire` for protocol types, so the shared volatile helpers would fit there.

---

### `let _ = sys_chan_send(...)` pattern persists (7 sites)

**Location**: `user/net-stack/src/main.rs:894, 1318, 1355, 1682, 1759, 1766, 2117`

These 7 `let _ =` sites silently discard send errors. While some are legitimate fire-and-forget doorbells (line 894), others send socket responses to clients — if the send fails, the client hangs waiting for a response.

**Classification**:
- Line 894: Fire-and-forget doorbell — `let _ =` is acceptable
- Lines 1318, 1355, 1682: Socket response sends — should check `ret == 2` (channel closed) and deactivate the socket
- Lines 1759, 1766: Helper functions `send_sock_ok`/`send_sock_error` — callers don't know if send failed
- Line 2117: Socket control response — should check for closed channel

**Fix**: Have `send_sock_ok`/`send_sock_error` return `bool` indicating success, and have callers deactivate the socket on failure.

---

### `.unwrap_or(0)` on serialization (18 sites in net-stack)

**Location**: `user/net-stack/src/main.rs` — 18 occurrences (lines 893, 1057, 1153, 1167, 1317, 1354, 1681, 1758, 1765, 1833, 1839, 1858, 1872, 1889, 1909, 2018, 2078, 2188)

All serialize fixed protocol response types that should never fail at runtime. If they do fail, the client receives an empty message (len=0), which is silently ignored.

**Fix**: Replace with `expect()` — serialization of known-good fixed-layout types is a programming error if it fails. This matches the kernel's panic-on-internal-error convention.

---

### Magic number `2` for "channel closed" throughout net-stack (7 sites)

**Location**: `user/net-stack/src/main.rs` — 7 occurrences of `ret == 2` / `if ret == 2`

The constant `2` for `ChannelClosed` comes from the kernel ABI but is not exposed as a named constant in the user-space libraries.

**Fix**: Add to `lib/rvos/src/raw.rs`:
```rust
pub const CHAN_CLOSED: usize = 2;
```

---

### service.rs spawn function duplication (from review #3, still open)

**Location**: `lib/rvos/src/service.rs:63-191`

6 `spawn_*` functions with 85+ lines of near-identical boot-channel code.

---

## 3. Security & Isolation

| Severity | Location | Issue | Impact |
|----------|----------|-------|--------|
| HIGH | `user/net-stack/src/main.rs:1769-1775` | Ephemeral port allocator uses `static mut` — no synchronization needed (single-threaded), but off-by-one: upper bound is 65534 not 65535, losing port 65535 | Minor: 1 lost port |
| MEDIUM | `user/net-stack/src/main.rs:1057` | No socket port access control; any process can bind any port | Port hijacking of well-known services (from review 5, still open) |
| MEDIUM | `kernel/src/mm/elf.rs:172-198` | ELF parser uses `.unwrap()` on `try_into()` for slice conversions | Malformed ELF binary panics the kernel (from review 5, still open) |
| MEDIUM | `kernel/src/arch/syscall/mem.rs:102-120` | Partial mmap failure cleanup can panic in `unmap()` | User-triggerable kernel panic via OOM (from review 5, still open) |
| LOW | `vendor/rust/.../rvos/mod.rs:167` | IPv6 addresses silently mapped to 0.0.0.0:0 | Incorrect behavior; should return `Unsupported` error |

---

## 4. Performance Cliffs

| Location | Current | Should Be | Penalty |
|----------|---------|-----------|---------|
| `net-stack/main.rs:1045` | UDP payload truncated to hardcoded `900` bytes | Use `MAX_MSG_SIZE - wire_overhead` (~950+) | ~5% wasted payload capacity per datagram |
| `net-stack/main.rs:50` | `MAX_TCP_CONNS = 16` with no RST on exhaustion | Send RST for new SYNs when full | Incoming connections silently blackholed; retransmit storm from peers |
| `net-stack/main.rs:53` | `TCP_ACCEPT_BACKLOG = 4` per listener, silent drop | Send RST or log | Accept queue overflow silently drops connections |
| `drivers/virtio/net.rs:318` | Transmit blocks via WFI until completion | Async completion | Kernel task stalls on every TX (from review 5, still open) |
| `services/console.rs:42` | Line buffer = 256 chars, silent truncation | 1024 chars or dynamic | Long commands silently corrupted (from review 5, still open) |

---

## 5. Resource Exhaustion Audit

| Resource | Limit | On Exhaustion | Caller Notified? | Changed Since Review 5? | Suggested Fix |
|----------|-------|---------------|------------------|-------------------------|---------------|
| Channels | 64 | Returns None | Yes | No | Adequate |
| Handles/process | 32 | Returns None | Yes | No | Adequate |
| Processes | 64 | Returns None | Yes | No | Adequate |
| Page frames | ~32K | Returns None | Yes | No | Adequate |
| mmap regions/proc | 256 | Returns false | Yes (bool) | No | Change to Result |
| Message queue depth | 64 | Returns Err(QueueFull) | Yes | No | Excellent |
| Named services | 12 | **Panics** (assert!) | **No** | No | Replace assert with Result |
| Boot registrations | 16 | Logs warning, skips | Partial | No | Return error to prevent deadlock |
| Console clients | 8 | **Silent drop** | **No** | No | Log + send rejection |
| FS launch contexts | 8 | Error response | Yes | No | Adequate |
| Dynamic spawns | 8 | Error response | Yes | No | Adequate |
| IPC message payload | 1024 bytes | **Silent truncation** | **No** | No | Return error |
| Caps per message | 4 | **Silent drop** | **No** | No | Return error |
| Net RX ring (SHM) | 8 slots | Requeues to driver | Implicit | No | Adequate |
| Net TX ring (SHM) | 4 slots | **Silent drop** | **No** | **Yes** (2→4 in 979cc5e) | Return error from tx_frame() |
| ARP cache | TTL-based eviction | Old entries expire | Implicit | **Yes** (TTL added in 44c6202) | Adequate |
| Pending ARP queue | 4 packets | **Silent drop** | **No** | **Yes** (backoff added in 44c6202) | Adequate for now |
| Net sockets | 16 | Returns error | Yes | **Yes** (new socket protocol) | Adequate |
| Timer clients | 32 | Log + close channel | Yes (implicit) | **New** (9906cda) | Adequate |
| TCP connections | 16 | **SYN silently ignored** | **No** | **New** (9b3df94) | Send RST |
| TCP accept backlog | 4/listener | **Accept silently dropped** | **No** | **New** (9b3df94) | Send RST or log |
| NS overrides/proc | 16 | **Silent truncation** | **No** | No | Log warning |
| TTY line buffer | 256 chars | **Silent truncation** | **No** | No | Ring bell on overflow |

**Review 5 comparison**: TX ring doubled (2→4), ARP cache gained TTL eviction, ARP pending gained retry backoff. 3 new resource pools (timer clients, TCP connections, TCP accept backlog) — timer has proper notification; TCP pools silently drop.

---

## 6. API Consistency & Footguns

### Remaining sentinel values

| Pattern | Count | Locations | Impact |
|---------|-------|-----------|--------|
| `ret == 2` for channel closed | 7 | `net-stack/main.rs` | Hardcoded ABI constant without named const |
| `usize::MAX` for "no listener" | 3 | `net-stack/main.rs` (TCP conn fields) | Sentinel for "no associated socket" |
| `unwrap_or(0)` on serialization | 18 | `net-stack/main.rs` | Empty message on encode failure |
| `let _ = sys_chan_send(...)` | 7 | `net-stack/main.rs` | Silent send failures |

### `static mut` usage

| Location | Variable | Issue |
|----------|----------|-------|
| `net-stack/main.rs:1771` | `NEXT_EPHEMERAL: u16` | Single-threaded so safe, but violates MEMORY.md "no static mut" rule |

---

## 7. Code Duplication

| Pattern | Instances | Lines | Fix |
|---------|-----------|-------|-----|
| `spawn_process*()` variants | 6 | ~130 | Extract `spawn_impl()` (review #3 item, still open) |
| `shm_read_u16/u32 + shm_write_u16/u32` | 2 identical sets | ~40 | Extract to shared lib |
| `send_sock_ok` / `send_sock_error` pattern | 2 helpers + 7 inline | ~35 | Already partially extracted; callers should check return |

---

## 8. Documentation Drift

| Doc | Claim | Actual Code | Status |
|-----|-------|-------------|--------|
| `architecture.md` Phase 5 process list | No timer service | `main.rs:221` spawns timer kernel task | **STALE** |
| `kernel-abi.md` §7 Available Services | Lists "net" service | Registered as "net-raw"; references old NetRequest/NetResponse protocol (removed in 69b1136) | **STALE** |
| `kernel-abi.md` §7 | No timer service | Timer service registered, uses TimerRequest/TimerResponse | **MISSING** |
| `README.md` process list | No timer (PIDs 0-9) | Timer is PID ~10 | **STALE** |
| `README.md` syscall table | 16 syscalls | 18 actual: missing SYS_TRACE (230), SYS_SHUTDOWN (231) | **STALE** |
| No `docs/protocols/socket.md` | — | Full socket protocol with SocketsRequest/SocketsResponse + SocketRequest/SocketResponse + SocketData | **MISSING** |
| No `docs/protocols/timer.md` | — | Timer protocol: TimerRequest::After → TimerResponse::Expired | **MISSING** |
| No TCP state machine docs | — | 11-state TCP implementation in net-stack (800+ lines) | **MISSING** |
| No std::net backend docs | — | Full TcpStream/TcpListener/UdpSocket PAL backend (~300 lines) | **MISSING** |
| `docs/protocols/net-raw.md` | SHM layout, ring sizes, control offsets | All constants match net_server.rs exactly | **CORRECT** |
| All numeric constants in docs | Various limits | All match actual code values | **CORRECT** |

---

## 9. Bug Pattern Analysis

| Pattern | Count | Most Recent | Structural Prevention | Recurrence Since Fix? |
|---------|-------|-------------|----------------------|-----------------------|
| Ref counting violations | 4 | Bug 0008 | RAII wrappers (commit 28cd40d) | **0 recurrences** |
| Race conditions | 2 | Bug 0005 | `suppress_irq_restore()` pattern | **0 recurrences** |
| Silent error drops | 2 | Bug 0009 | Sentinel→Result migration (d930faa) | **0 new bugs, but pattern persists in net-stack** |
| Resource exhaustion | 2 | Bug 0004 | WFI-based polling convention | **0 recurrences** |
| Protocol/API misuse | 1 | Bug 0006 | `force_block_process()` | **0 recurrences** |
| Integer overflow | 1 | d930faa fix | `checked_sub` in VirtIO net | **New: timer.rs:140 (unfixed)** |
| Stack overflow | 1 | 8f71d8e fix | Heap allocation rule in MEMORY.md | **0 recurrences** |

**Key insight**: The RAII wrapper migration continues to hold — zero ref-counting bugs in the 24-commit period. The sentinel→Result migration was completed for the syscall layer (d930faa) but the net-stack user-space code still has 18 `.unwrap_or(0)` sites and 7 `let _ =` sites. The **active risk area** is now the **TCP state machine** — 800+ lines of new protocol code with complex state transitions and no test coverage.

---

## 10. Dependency & Coupling Map

### Blast radius of key struct changes

| Struct | Files touched | Impact | Change Since Review 5? |
|--------|---------------|--------|------------------------|
| `Message` (ipc) | 14 files | ABI change; 4+ compile-time assertion sites | No change |
| `Process` (task) | 8 kernel files | Scheduler, syscalls, services, debugger | No change |
| `Channel` (ipc) | 5 kernel files | Ref counting, send/recv, blocking | No change |
| `SocketRequest/Response` (proto) | 4 files | net-stack, socket.rs, std::net backend | **New** coupling |
| `TimerRequest/Response` (proto) | 2 files | timer.rs, timer protocol | **New** coupling (minimal) |

### New coupling from networking/socket stack

- `lib/rvos-proto/src/socket.rs` types used in: `user/net-stack/src/main.rs`, `lib/rvos/src/socket.rs`, `vendor/rust/library/std/src/sys/net/connection/rvos/*.rs` (4 files)
- `lib/rvos/src/socket.rs` API used in: `vendor/rust/library/std/src/sys/net/connection/rvos/*.rs` (3 files: tcpstream, tcplistener, udp)
- Coupling is well-layered: protocol types → socket API → std::net backend → user apps

### Module dependency flow

All dependencies still flow downward: `services → ipc → task → mm → sync → arch`. **No circular dependencies** — preserved from review 5.

---

## 11. Code Quality

### Sentinel values & error handling

| Location | Current Pattern | Impact | Suggested Fix |
|----------|----------------|--------|---------------|
| `net-stack/main.rs` (7 sites) | `ret == 2` bare literal | Unreadable ABI constant | Define `CHAN_CLOSED = 2` in lib/rvos |
| `net-stack/main.rs` (18 sites) | `.unwrap_or(0)` on serialize | Empty message on failure | Use `.expect()` |
| `net-stack/main.rs` (7 sites) | `let _ = sys_chan_send(...)` | Silent send failure | Check return, deactivate socket on close |
| `net-stack/main.rs:1771` | `static mut NEXT_EPHEMERAL` | Violates "no static mut" rule | Use `Cell<u16>` or pass as `&mut u16` parameter |

### Low-level abstraction usage

| Location | Raw API Used | Higher-level Alternative |
|----------|-------------|--------------------------|
| `net-stack/main.rs` (entire file) | `raw::sys_chan_send`, `raw::sys_chan_recv` | Typed channel API from `lib/rvos/src/channel.rs` |
| `net-stack/main.rs` (SHM access) | Manual volatile ptr casts | Should use shared shm helper functions |

**Note**: net-stack's use of raw APIs is partially justified by performance (avoiding typed channel overhead in a hot loop), but the SHM helpers should still be deduplicated.

### RAII compliance

| Resource | Status | Notes |
|----------|--------|-------|
| GPU server endpoints | **DONE** (4671c48) | Correctly uses OwnedEndpoint |
| KBD server endpoints | **DONE** (4671c48) | Correctly uses OwnedEndpoint |
| Mouse server endpoints | **DONE** (4671c48) | Correctly uses OwnedEndpoint |
| Timer client endpoints | **Correct** | Uses `Option<OwnedEndpoint>` with proper deactivate() |
| FsLaunchCtx endpoints | Manual (raw usize + Drop) | Not changed (from review 5) |
| Console client endpoints | Manual (raw usize) | Not changed (from review 5) |

### Magic numbers

| Location | Number | Meaning | Suggested Constant |
|----------|--------|---------|-------------------|
| `net-stack/main.rs:1045` | `900` | Max UDP payload in SocketData response | `MAX_UDP_PAYLOAD_IN_RESPONSE` |
| `net-stack/main.rs:1771` | `49152` | Ephemeral port range start | `EPHEMERAL_PORT_MIN` |
| `net-stack/main.rs:1775` | `65534` | Ephemeral port range end (off-by-one vs RFC 6056 max 65535) | `EPHEMERAL_PORT_MAX` |

### Memory ordering

SHM ring buffer fences are **correctly placed** in both kernel and user-space:
- **Producer** (writer): writes data → Release fence → advances head pointer
- **Consumer** (reader): reads head/tail → Acquire fence → reads data

This follows the standard SPSC ring buffer pattern. The review 5 finding claiming Acquire fences needed to be before index reads was incorrect — the current placement (between index reads and data reads) is the correct pattern for RISC-V.

### Unchecked arithmetic

| Location | Operation | Risk | Fix |
|----------|-----------|------|-----|
| `timer.rs:140` | `duration_us * TICKS_PER_US` | Overflow on large user input | Use `saturating_mul` |
| TCP sequence numbers | `wrapping_add`, `wrapping_sub` throughout | None — correctly uses wrapping | No fix needed |

---

## 12. Test Coverage Gaps

### Missing regression tests

| Bug | Fix Commit | Has Regression Test? | Suggested Test |
|-----|-----------|---------------------|----------------|
| 0002 | a33a409 | YES (`test_ns_override_cap_delivery`, `test_two_children_shared_override`) | — |
| 0005 | 0d61c7f | PARTIAL (`test_yield_latency` — latency, not race) | Explicit race test under heavy timer/IPC |
| 0007 | 42fbc79 | **NO** | Attach debugger, detach, attach again — verify second attach succeeds |
| 0008 | 364b7cd | YES (`test_two_children_shared_override`) | — |

### Untested new code

| Feature | Files | Lines | Test Coverage | Suggested Test |
|---------|-------|-------|---------------|----------------|
| Timer service | `kernel/src/services/timer.rs` | 185 | **None** | Deadline ordering, precision, slot exhaustion (32 clients), channel close mid-timer |
| Socket protocol | `lib/rvos-proto/src/socket.rs` | ~153 | **None** | Serialization round-trip for all variants |
| Socket client API | `lib/rvos/src/socket.rs` | ~250 | **None** | Bind/send/recv lifecycle, error paths |
| TCP state machine | `user/net-stack/src/main.rs` | ~800 | **Demo only** (tcp-echo) | State transitions (11 states), RST handling, retransmission, seq wraparound |
| std::net backend | `vendor/rust/.../rvos/` | ~300 | **Demo only** | Error paths, partial reads/writes, shutdown semantics |

### Untested invariants

| Invariant | Where Stated | Tested? | Suggested Test |
|-----------|-------------|---------|----------------|
| Cap transfer ref counting | MEMORY.md, Bug 0002 | Partial | Already covered by bug 0002/0008 regression tests |
| Close after cap transfer | MEMORY.md, Bug 0007 | **No** | Debugger second-attach regression test |
| Lock ordering (SCHEDULER → CHANNELS) | kernel/CLAUDE.md | **No** | Stress: heavy spawn + channel activity |
| sscratch always → current TrapContext | MEMORY.md | **No** | Trap handler hook to verify after each switch |
| TCP state machine transitions | RFC 793 | **No** | State transition matrix test |
| Socket cleanup on disconnect | Design convention | **No** | Close socket handle, verify port freed |

### Exhaustion path tests

| Resource | Limit | Has Exhaustion Test? | Test |
|----------|-------|-----------------------|------|
| Channels | 64 | YES | `test_chan_create_close_loop` |
| Handles | 32 | YES | `test_handle_exhaustion` |
| Message queue | 64 | YES | `test_queue_full_then_drain` |
| mmap regions | 256 | YES | `test_mmap_many_regions` |
| Processes | 64 | PARTIAL | `test_stress_spawn_exit` (only 3) |
| Timer clients | 32 | **No** | Connect 32+ clients, verify rejection |
| TCP connections | 16 | **No** | Open 16+ connections, verify RST/error |
| Sockets | 16 | **No** | Create 16+ sockets, verify NoResources |
| SHM regions | (no limit) | **No** | Create until exhaustion |

---

## 13. What's Good

### TCP state machine — clean architecture despite complexity

The TCP implementation (`user/net-stack/src/main.rs`) handles 11 states with proper sequence number wrapping, retransmission with exponential backoff, TIME_WAIT cleanup, and FIN/RST handling. Named constants for all TCP flags and protocol parameters. State enum is clear and transitions are explicit. Buffer management (send_buf compaction after ACK) is correct and efficient.

### Socket protocol — well-layered two-channel design

The socket API uses a clean two-channel pattern: one control channel (`SocketsRequest`/`SocketsResponse`) for creating sockets, then a per-socket channel (`SocketRequest`/`SocketResponse`/`SocketData`) for data transfer. Cap transfer delivers the per-socket channel correctly. This enables multiple concurrent sockets per client without multiplexing complexity.

### std::net backend — proper std integration

The PAL backend (`vendor/rust/library/std/src/sys/net/connection/rvos/`) correctly maps Rust's `std::net` types to the rvOS socket protocol. Error mapping is complete. Address conversion handles IPv4 correctly. `tcp-echo` and `udp-echo` both work with standard `std::net` types, proving the full stack.

### Timer service — minimal and correct RAII design

`kernel/src/services/timer.rs` is 185 lines with clean RAII for client slots (`Option<OwnedEndpoint>`), proper deactivation on channel close, and efficient `block_with_deadline` for precise wakeups. Slot exhaustion is handled gracefully (log + drop = RAII close).

### OwnedEndpoint conversion — GPU/kbd/mouse servers (4671c48)

The conversion from raw endpoint IDs to `OwnedEndpoint` in all three device servers is correct and complete. RAII cleanup on function return/client disconnect. No manual ref counting needed.

### SHM ring buffer memory ordering — correct

Both the kernel producer (Release before head advance) and user-space consumer (Acquire between index reads and data reads) follow the standard SPSC pattern. The compile-time assertion (`net_server.rs:30-33`) prevents layout overflow.

### Syscall Result migration — complete

All syscall handlers return `SyscallResult`. Named error constants (`SyscallError` enum). Debug assertions catch success/error code collisions. No sentinel values remain in the dispatch layer.

### Zero circular dependencies — still preserved

Module dependency graph flows cleanly downward. The new socket/timer protocol types in `lib/rvos-proto` don't create cycles.

---

## 14. Priority Action Items

### Immediate (fix this week)

1. **Fix timer deadline arithmetic overflow** — `saturating_mul` + `saturating_add` (HIGH correctness, 1-line fix)
2. **Add FIN to TcpStream::drop** — prevents connection slot exhaustion (HIGH reliability)
3. **Define `CHAN_CLOSED` constant** — replace 7 bare `== 2` checks in net-stack (HIGH maintainability)
4. **Replace `.unwrap_or(0)` with `.expect()`** — 18 sites in net-stack; makes serialization failures crash loudly instead of silently sending empty messages (MEDIUM correctness)

### Soon (next sprint)

5. **Buffer data-with-ACK in SynReceived** — TCP RFC compliance (MEDIUM correctness)
6. **Check send results in net-stack** — replace `let _ =` with socket deactivation on channel close at response-send sites (MEDIUM reliability)
7. **Send RST on TCP connection exhaustion** — instead of silently ignoring SYNs (MEDIUM reliability)
8. **Handle net-server allocation failure gracefully** — replace `expect()` with log + return (MEDIUM robustness)
9. **Add regression test for Bug 0007** — debugger second-attach (MEDIUM test coverage)
10. **Add timer service ktest** — deadline ordering, slot exhaustion, precision (MEDIUM test coverage)
11. **Create `docs/protocols/socket.md`** — document the socket protocol (MEDIUM documentation)
12. **Create `docs/protocols/timer.md`** — document the timer protocol (MEDIUM documentation)
13. **Update architecture.md and kernel-abi.md** — add timer service, fix "net" → "net-raw", remove old NetRequest/NetResponse references (MEDIUM documentation)
14. **Update README process list and syscall table** — add timer, SYS_TRACE, SYS_SHUTDOWN (LOW documentation)

### Backlog (when convenient)

15. Replace `register_service()` assert with Result — prevent boot panic on service overflow
16. Extract SHM volatile helpers to shared lib — deduplicate 40 lines
17. Extract `spawn_impl()` helper — deduplicate service.rs (review #3 item)
18. Add TCP state machine tests — state transitions, retransmission, seq wraparound
19. Add socket exhaustion tests — 16+ sockets, 16+ TCP connections
20. Map IPv6 to `Unsupported` in std::net backend — instead of silent 0.0.0.0 mapping
21. Define `EPHEMERAL_PORT_MIN`/`MAX` constants — fix off-by-one (65534 vs 65535)
22. Replace `static mut NEXT_EPHEMERAL` with `Cell<u16>` — follow "no static mut" rule
23. Add `#[must_use]` to IPC Result functions (review #4 item)
24. Document lock ordering in kernel/LOCK_ORDERING.md (review #4 item)
25. Add WFI timeout to VirtIO net `transmit()` (review #5 item)
26. Implement socket port access control (review #5 item)

### Review #5 items — status

| Item | Status |
|------|--------|
| ~~Fix memory ordering in SHM ring control block~~ | **DONE** (was actually correct; review 5 finding was incorrect) |
| ~~Add checked subtraction in VirtIO net poll_rx()~~ | **DONE** (d930faa — uses `checked_sub`) |
| ~~Add static assertion for SHM ring layout size~~ | **DONE** (979cc5e — `const _: ()` assertion) |
| ~~Add IPv4 total_len >= hdr_len validation~~ | **DONE** (d930faa — line 356) |
| ~~Define named constants for syscall return codes~~ | **DONE** (d930faa — `SyscallError` enum) |
| ~~Add UDP checksum validation~~ | **DONE** (6c7a485) |
| ~~Implement ARP cache TTL and retry backoff~~ | **DONE** (44c6202) |
| ~~Increase TX ring from 2 to 8 slots~~ | **PARTIAL** (979cc5e — increased to 4, not 8) |
| ~~Create `docs/protocols/net-raw.md`~~ | **DONE** (ed0866d) |
| ~~Update architecture.md service list~~ | **PARTIAL** (26c4560 — added most services, missed timer) |
| ~~Update kernel-abi.md syscall table~~ | **PARTIAL** (5cb9e44 — added SHM syscalls, missed SYS_TRACE/SYS_SHUTDOWN in README) |
| ~~Convert gpu/kbd/mouse to OwnedEndpoint~~ | **DONE** (4671c48) |
| Add error checking to net-stack syscall returns | OPEN (7 `let _ =` sites remain) |
| Replace `.unwrap()` in udp-echo with error handling | CLOSED (udp-echo rewritten with std::net in 77e664a) |
| Add `SysError` variant to `RecvError`/`SendError` | OPEN |
| Replace `tty::ioctl() → i32` with Result | OPEN |
| Extract service.rs spawn duplication | OPEN |
| Add `#[must_use]` to IPC functions | OPEN |
| VirtIO net transmit WFI timeout | OPEN |
| Socket port access control | OPEN |
