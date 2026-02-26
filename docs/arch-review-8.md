# Architecture Review 8 — 2026-02-26

Scope: 28 commits since arch-review-7 (a365426..242ca79). Major features: system watchdog, idle-service heartbeat fix, ktests for channel limit / SYS_KILL / spawn-suspended / HTTP loopback, protocol docs, http-client DNS fix, bug investigations (0022–0026).

Codebase: ~36,700 lines of Rust + assembly.

**Focus**: This review answers a specific question — *for each userland app, does the code look reasonable? Clean and easy to understand? If not, is something missing in the kernel or libraries?*

---

## 1. Per-App Scorecard

| App | LOC | Score | Verdict | Primary Pain Point |
|-----|-----|-------|---------|--------------------|
| hello | ~80 | 9/10 | Clean | None |
| ktest-helper | ~60 | 9/10 | Clean | None |
| http-client | ~80 | 9/10 | Clean — uses `TcpStream` | None |
| tcp-echo | ~63 | 9/10 | Clean — uses `TcpListener` | None |
| udp-echo | ~34 | 9/10 | Clean — uses `UdpSocket` | None |
| http-server | ~206 | 8/10 | Clean — uses std I/O | Minor: retry-on-WouldBlock |
| bench | ~350 | 8/10 | Clean | Minor: manual printf |
| ktest | ~800 | 8/10 | Clean | Minor: test boilerplate |
| triangle | 8/10 | Clean — uses `rvos_gfx` | 40-line window handshake |
| winclient | ~270 | 7/10 | Readable but boilerplate | 40-line window handshake + manual double-buffer |
| shell | ~600 | 6/10 | Mixed | Low-level sysinfo IPC, no streaming recv |
| fbcon | ~575 | 6/10 | Mixed | Duplicate window setup, raw pointer FB |
| ipc-torture | ~708 | 5/10 | Intentionally low-level | By design (stress test) |
| gui-bench | ~220 | 5/10 | Repetitive | Custom `connect_window()` reimplements library |
| nc | ~620 | 4/10 | Messy | Raw IPC everywhere, duplicated relay loops |
| dbg | ~400 | 4/10 | Boilerplate-heavy | 10 identical RPC stubs, manual handle juggling |
| fs | ~1302 | 7/10 | Clean but verbose | Two-phase recv pattern, unsafe global |
| ext2-server | ~848 | 7/10 | Clean but formulaic | Same two-phase pattern as fs |
| net-stack | ~2000 | 6/10 | Complex but reasonable | Raw SHM, magic byte offsets, no packet structs |
| window-server | ~870 | 7/10 | Clean for its domain | GPU init mixes raw/typed channels |

**Pattern**: Apps that use high-level wrappers (`TcpStream`, `UdpSocket`, `rvos_gfx::Framebuffer`) score 8–9. Apps that touch raw IPC (`Message::new()` + serialize + send + recv + deserialize) score 4–6. The library has *some* wrappers but not enough.

---

## 2. The Five Ugliest Patterns

### 2a. Window Creation Ceremony (40 lines, repeated in 4 apps)

**Where**: `winclient:16–55`, `fbcon:370–410`, `triangle:21–48`, `gui-bench:82–117`

Every GUI app does this:

```rust
let win_ctl = rvos::connect_to_service("window").unwrap().into_raw_handle();
let mut win_ctl_ch = Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
win_ctl_ch.send(&CreateWindowRequest { width, height }).unwrap();
let create_resp = win_ctl_ch.recv_blocking().unwrap();
let req_chan = create_resp.req_channel.raw();
let event_chan = create_resp.event_channel.raw();
let mut win_client = WindowClient::new(UserTransport::new(req_chan));
let info = match win_client.get_info(1) { ... };
let shm_handle = match win_client.get_framebuffer(2) { ... };
let fb_base = raw::mmap(shm_handle, size).unwrap();
// ... double-buffer setup ...
```

35–40 lines before drawing a single pixel. `gui-bench` even wrote its own `connect_window()` helper because it was so painful.

**Should be**:
```rust
let mut window = Window::create(400, 300)?;
let fb = window.back_buffer();
fb.clear(0xFF000000);
window.present()?;
```

### 2b. RPC Boilerplate (6 lines per call, repeated 10× in dbg)

**Where**: `dbg:81–130` (attach), and then identically for suspend, resume, regs, setreg, mem, write, breakpoint, clear, backtrace.

```rust
let mut msg = rvos::Message::new();
msg.len = rvos_wire::to_bytes(&request, &mut msg.data).unwrap_or(0);
let ret = raw::sys_chan_send_blocking(handle, &msg);
if ret != 0 { /* error */ }
let mut resp_msg = rvos::Message::new();
let ret = raw::sys_chan_recv_blocking(handle, &mut resp_msg);
if ret != 0 { /* error */ }
let resp: T = rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len])?;
```

Ten RPC methods × 6 lines = 60 lines of pure boilerplate. A `DebugClient` with `fn attach(&mut self, pid: usize) -> Result<AttachResponse>` would replace all of it.

**Root cause**: `define_protocol!` generates server-side dispatch but no client-side caller. `MathClient` exists as a hand-written example but the pattern was never generalized.

### 2c. Raw Wire Tag Dispatch (magic `msg.data[0]` matching)

**Where**: `nc:256–272`, `nc:343–356`, `nc:557–580`

```rust
match msg.data[0] {
    0 if msg.len == 1 => {} // Ok – shutdown ack
    0 => {  // Data
        if let Ok(SocketData::Data { data }) =
            rvos_wire::from_bytes::<SocketData<'_>>(&msg.data[..msg.len]) { ... }
    }
    1 => return, // error
    4 => {} // sent ack
    _ => {}
}
```

The comments exist *because* the code is confusing. The wire format leaks into application logic. This pattern appears 3 times in nc alone.

**Root cause**: The typed `Channel<S, R>` can only decode one response type. Socket channels multiplex `SocketResponse`, `SocketData`, and `SocketError` on the same channel, forcing manual tag inspection.

### 2d. Manual Double-Buffer Arithmetic

**Where**: `winclient:60–71,240–263`, `fbcon:407–426,571–574`, `gui-bench:124–130`

```rust
let mut current_back = 1u8;
let back_offset = if current_back == 0 { 0 } else { pixels_per_buffer };
let front_offset = if current_back == 0 { pixels_per_buffer } else { 0 };
unsafe {
    core::ptr::copy_nonoverlapping(
        fb_base.add(front_offset), fb_base.add(back_offset), pixels_per_buffer,
    );
}
current_back = 1 - current_back;
```

Three apps independently implement buffer-swap state tracking. `fbcon` must also manually update its console's `fb` pointer after each swap. Error-prone and duplicated.

### 2e. Two-Phase Recv Pattern in Servers

**Where**: `fs:911–962,966–1055`, `ext2-server:683–831`

Poll-based servers can't hold a borrow across dispatch (the `Channel` borrow prevents calling mutable methods on the server state). The workaround is: recv into temp buffer, copy parameters to stack, release borrow, then dispatch. This is correct but creates ~50 lines of formulaic code per channel type.

```rust
// Phase 1: recv and extract
let msg = try_recv(handle);
let (read_params, write_params, ioctl, file_closed) = match parse(msg) {
    Read { offset, len } => (Some((offset, len)), None, false, false),
    Write { offset, data } => { buf.copy_from_slice(data); (None, Some((offset, len)), false, false) }
    // ...
};
// Phase 2: dispatch
if let Some((off, len)) = read_params { handle_read(off, len); }
if let Some((off, len)) = write_params { handle_write(off, len, &buf); }
```

---

## 3. What the Clean Apps Have in Common

The 8/10 and 9/10 apps share one trait: they use **high-level wrappers that hide IPC**.

| App | Wrapper Used | Lines of Raw IPC |
|-----|-------------|------------------|
| http-client | `std::net::TcpStream` | 0 |
| tcp-echo | `std::net::TcpListener` | 0 |
| udp-echo | `rvos::socket::UdpSocket` | 0 |
| http-server | `std::net::TcpListener` | 0 |
| hello | `std::fs::*` | 0 |
| triangle | `rvos_gfx::Framebuffer` | ~15 (window setup only) |

The `TcpStream`/`UdpSocket` wrappers in `lib/rvos/src/socket.rs` are the **gold standard**. They hide `Message`, `rvos_wire`, raw handles, and channel lifecycle behind a familiar `Read`/`Write` API. GUI apps need the same treatment.

---

## 4. Missing Abstractions (Prioritized)

### HIGH: Window Client Wrapper

**Impact**: Would clean up 4 apps immediately (winclient, fbcon, triangle, gui-bench).

Proposed API in `lib/rvos/src/window.rs`:

```rust
pub struct Window {
    client: WindowClient,
    event_channel: RawChannel,
    fb_base: *mut u32,
    width: u32, height: u32, stride: u32,
    pixels_per_buffer: usize,
    current_back: u8,
    swap_seq: u32,
}

impl Window {
    pub fn create(width: u32, height: u32) -> Result<Self, WindowError>;
    pub fn back_buffer(&mut self) -> Framebuffer<'_>;
    pub fn present(&mut self) -> Result<(), WindowError>;
    pub fn poll_event(&mut self) -> Option<WindowEvent>;
    pub fn event_handle(&self) -> usize;  // for poll_add
}

impl Drop for Window {
    fn drop(&mut self) { /* unmap, close channels */ }
}
```

This encapsulates: service connection, CreateWindow handshake, SHM mapping, double-buffer management, and swap sequencing. The `Framebuffer` type from `rvos_gfx` provides safe pixel access.

### HIGH: Auto-Generated Protocol Clients

**Impact**: Would clean up dbg (10 RPC stubs), shell (sysinfo interaction), nc (socket RPC).

The `define_protocol!` macro already generates server-side dispatch. Extend it to also emit a client struct:

```rust
// Auto-generated:
pub struct DebugClient {
    transport: UserTransport,
}

impl DebugClient {
    pub fn attach(&mut self, pid: usize) -> Result<AttachResponse, RpcError> {
        self.transport.rpc_call(&DebugRequest::Attach { pid })
    }
    pub fn suspend(&mut self) -> Result<SuspendResponse, RpcError> { ... }
    // ... one method per request variant
}
```

`MathClient` is the proof-of-concept — it works well but was hand-written. Generalizing this to all protocols would eliminate hundreds of lines across the codebase.

### MEDIUM: Streaming Response Iterator

**Impact**: Would clean up shell's sysinfo loop, readdir in fs/ext2-server.

```rust
pub struct StreamReceiver<'a, R: MessageType> {
    channel: &'a mut RawChannel,
    buf: Box<Message>,
    _phantom: PhantomData<R>,
}

impl<R: MessageType> Iterator for StreamReceiver<'_, R> {
    type Item = R::Msg<'_>;
    fn next(&mut self) -> Option<Self::Item> {
        // recv_blocking, return None when len==0 (end sentinel)
    }
}
```

Current pattern (shell):
```rust
loop {
    raw::sys_chan_recv_blocking(h, &mut resp);
    if resp.len == 0 { break; }
    io::stdout().write_all(&resp.data[..resp.len]).ok();
}
```

Desired:
```rust
for line in sysinfo_chan.recv_stream::<SysinfoLine>() {
    print!("{}", line);
}
```

### MEDIUM: Event Multiplexer

**Impact**: Would simplify dbg (stdin + debug events), nc (stdin + socket), window-server (ctl + kbd + mouse).

```rust
pub struct Reactor {
    handles: Vec<usize>,
}

impl Reactor {
    pub fn add(&mut self, handle: usize);
    pub fn remove(&mut self, handle: usize);
    pub fn wait(&self) -> Vec<usize>;  // returns ready handles
}
```

Current pattern (dbg):
```rust
raw::sys_chan_poll_add(stdin_h);
if let Some(eh) = dbg.event_handle {
    raw::sys_chan_poll_add(eh);
}
raw::sys_block();
// ... manually check each handle
```

### LOW: Packet Codec Trait

**Impact**: Would clean up net-stack's manual header parsing.

```rust
trait PacketCodec: Sized {
    fn parse(buf: &[u8]) -> Option<(Self, &[u8])>;
    fn write(&self, buf: &mut [u8]) -> usize;
}
```

Current: `parse_eth()`, `parse_ipv4()`, `parse_tcp()` are all standalone functions with hardcoded byte offsets. Building packets uses inline `buf[0] = 0x00; buf[1] = 0x01; ...` with comments explaining each field. Correct but fragile.

### LOW: Volatile Memory Wrapper

**Impact**: Would clean up net-stack's SHM ring buffer access.

```rust
struct VolatileReg<T> { ptr: *mut T }
impl<T: Copy> VolatileReg<T> {
    fn read(&self) -> T { unsafe { self.ptr.read_volatile() } }
    fn write(&self, val: T) { unsafe { self.ptr.write_volatile(val) } }
}
```

Current: `shm_read_u32(base, offset)` / `shm_write_u32(base, offset, val)` — untyped, easy to misalign.

---

## 5. Library Assessment

### What's Good

| Module | Quality | Notes |
|--------|---------|-------|
| `lib/rvos/src/channel.rs` | Excellent | RAII, type-safe `Channel<S, R>`, GAT-based zero-copy recv |
| `lib/rvos/src/message.rs` | Excellent | Layout assertions, `Message::boxed()` heap pattern |
| `lib/rvos/src/service.rs` | Good | One-liner service discovery, spawn variants |
| `lib/rvos/src/socket.rs` | Good | `TcpStream`/`UdpSocket` hide all IPC complexity |
| `lib/rvos/src/transport.rs` | Good | Clean `UserTransport` wrapping |
| `lib/rvos/src/dns.rs` | Good | Full DNS implementation with compression pointers |
| `lib/rvos/src/raw.rs` | Good | Consistent syscall wrappers |
| `lib/rvos/src/error.rs` | Adequate | `SysError`, `RecvError`, `RpcError` — could be unified |
| `lib/rvos-gfx` | Adequate | `Framebuffer` struct works but isn't used by most GUI apps |
| `lib/rvos-wire` | Good | Protocol serialization with GAT message types |

### What's Missing

1. **Window wrapper** — Socket has `TcpStream`; windows have nothing equivalent
2. **Protocol client codegen** — Server dispatch exists; client stubs don't
3. **Streaming recv** — Channels support one-shot request/response but not streams
4. **Event multiplexing** — Raw `poll_add` + `sys_block`, no reactor
5. **Unified error type** — `SysError`, `RecvError`, `RpcError` don't compose

### Inconsistencies

| Layer | Pattern | Issue |
|-------|---------|-------|
| std PAL `ipc.rs` | Raw `sys_chan_send_blocking(handle, &msg)` | Duplicates lib/rvos logic |
| std PAL `connect_to_service()` | Returns `Option<usize>` (raw handle) | Should return `Option<RawChannel>` |
| `Channel<S, R>` | Single response type per channel | Can't decode multiplexed messages (socket problem) |
| `Message::new()` | Stack-allocated, caps default to 0 | `Message::boxed()` defaults caps to `NO_CAP` — inconsistent |

---

## 6. std PAL Assessment

The std PAL (`vendor/rust/library/std/src/sys/rvos/`) provides enough for text-based programs but forces GUI/network apps to drop to `rvos::` APIs.

**What works well**: `println!`, `File::open`/`read`/`write`, `std::env::args`, heap allocation, `TcpStream`/`TcpListener`/`UdpSocket` (via std trait impls on `rvos::socket` types).

**What's broken**: `std::thread::spawn` (not implemented), `std::time::SystemTime` (unsupported), `std::env::temp_dir()` (panics), `std::process::Command` (unsupported), `std::net` native types (must use `rvos::socket` wrappers with std trait impls).

**Key gap**: No heartbeat integration. If a user-space service blocks for >10s in `std::io::Read`, the watchdog kills it. Critical services must manually loop + call `sys_heartbeat()`.

---

## 7. Bug Pattern Analysis

| Pattern | Count (since review 7) | Fix |
|---------|------------------------|-----|
| Resource leak on error path | 1 (Bug 0022: service exit during handle_service_request) | Added is_active() check |
| Watchdog false positive | 1 (Bug 0025: idle services don't heartbeat) | Block with deadline pattern |
| Stack pressure from large types | 2 (Message on stack, net_server 1534-byte buffer) | `Message::boxed()`, heap alloc |
| Single-client service design | 2 (Bug 0024: blk_server, Bug 0026: sysinfo) | Documented, pending fix |

**Trend**: Stack-pressure bugs are declining (design rules working). Service-architecture issues are the new category — single-client blocking designs cause hangs under concurrent load.

---

## 8. What's Good (Preserve These)

1. **Socket abstraction quality** — `TcpStream`/`UdpSocket` hide all IPC. This is the target quality bar for all service wrappers.
2. **Channel RAII discipline** — `RawChannel` and `Channel<S, R>` close on drop. No manual cleanup needed when used properly.
3. **Zero-copy message deserialization** — GAT-based `MessageType` allows borrowed types. `FsRequest<'a>` borrows from receive buffer; `&mut self` borrow prevents use-after-free.
4. **`Message::boxed()` pattern** — Avoids 1KB struct on 32KB stack. Design rule is well-followed.
5. **Protocol type safety** — `Channel<S, R>` enforces send/receive types at compile time. Can't accidentally send a `FsRequest` on a `SocketRequest` channel.
6. **Simple apps are genuinely simple** — hello, tcp-echo, udp-echo, ktest-helper are all readable by someone unfamiliar with rvOS. This means the core abstractions work.

---

## 9. Priority Action Items

### Immediate (fix this week)

1. **Add `Window::create()` wrapper to `lib/rvos`** — Eliminates the single most repeated boilerplate pattern (4 apps × 40 lines). Include double-buffer management and `Framebuffer` integration. (Sections 2a, 2d, 4)

### Soon (next sprint)

2. **Extend `define_protocol!` to generate client stubs** — Would clean up dbg (10 stubs), shell (sysinfo), and make new service clients trivial to write. (Section 2b, 4)

3. **Add streaming response iterator** — Small addition to `lib/rvos/src/channel.rs`. Would simplify shell's sysinfo loop and any future multi-message protocols. (Section 4)

4. **Add event `Reactor` wrapper** — Encapsulate `poll_add` + `sys_block` + ready-handle iteration. Would simplify dbg, nc, and all poll-loop servers. (Section 4)

### Backlog (when convenient)

5. **Unify error types** — `SysError`/`RecvError`/`RpcError` should compose via `From` impls or a unified `AppError`. (Section 5)

6. **Add `PacketCodec` trait for net-stack** — Replace manual byte-offset header parsing with typed structs. (Section 4)

7. **Clean up nc's relay duplication** — TCP and UDP relay loops are 80% identical. Factor into a generic relay with a socket-type parameter. (Section 2c)

8. **Reconcile std PAL with lib/rvos** — std PAL's `connect_to_service()` returns raw `usize`; lib/rvos returns `RawChannel`. Should be consistent. (Section 5)

### From Review 7 (status)

- ~~Item 1: SYS_KILL inconsistency~~ — DONE (commit d67b1b8)
- ~~Item 5: process_spawn panic~~ — DONE (already fixed)
- ~~Item 6: SHM creation panic~~ — DONE (already fixed)
- ~~Items 7–10: ktest coverage~~ — DONE (commit d67b1b8)
- ~~Item 14: named service table exhaustion~~ — DONE (commit 587d32d)
- Item 2: Single-client service design — Still open (Bugs 0024, 0026 filed)
- Item 3: Packet validation in net-stack — Partially done (commit dbbaeca)
