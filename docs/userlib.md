# rvos: User-Space System Library

This document specifies the design of `rvos`, a Rust crate providing safe,
idiomatic wrappers around rvOS kernel syscalls for user-space programs.

---

## 1. Crate Name: `rvos`

### Rationale

The crate wraps rvOS kernel objects (channels, shared memory, process control)
and provides the primary API surface for user-mode programs. It is *not*
limited to IPC -- it will grow to cover every syscall and kernel object type.

This is the idiomatic wrapper crate, not a raw FFI binding layer. Raw syscall
wrappers live in a private `mod raw` inside this crate. This mirrors how
`fuchsia-zircon`, `nix`, and `sel4` provide safe, ergonomic APIs while hiding
the raw syscall machinery internally.

Naming survey of comparable OS projects:

| OS       | Raw syscalls         | Idiomatic wrappers       |
|----------|----------------------|--------------------------|
| Fuchsia  | `fuchsia-zircon-sys` | `fuchsia-zircon`         |
| Redox    | `redox_syscall`      | `libredox`               |
| Linux    | `libc`               | `nix`, `rustix`          |
| seL4     | `sel4-sys`           | `sel4`                   |
| **rvOS** | **`mod raw` (private)** | **`rvos`**            |

Candidates considered:

- **`rvos-ipc`** -- too narrow; shared memory, mmap, and process control are
  not IPC.
- **`rvos-rt`** -- already taken by the runtime crate (entry point, memcpy).
- **`rvos-zircon`** -- confusing; rvOS is not Zircon.
- **`rvos-api`** -- vague and doesn't follow Rust ecosystem conventions.
- **`rvos-sys`** -- the `*-sys` convention implies raw FFI bindings (like
  `fuchsia-zircon-sys`, `libc`, `windows-sys`). Since this crate provides
  RAII types, typed channels, and service discovery -- not raw bindings --
  the `-sys` suffix would be misleading.
- **`rvos`** -- clean, short, and correctly positioned as the idiomatic
  wrapper. Matches `fuchsia-zircon`, `nix`, and `sel4` in the comparison
  table above.

The crate lives at `lib/rvos/` alongside the existing `lib/rvos-wire/`.

### Crate Properties

```toml
[package]
name = "rvos"
version = "0.1.0"
edition = "2021"

[dependencies]
rvos-wire = { path = "../rvos-wire" }
```

- `#![no_std]` -- usable from both `no_std` (bare-metal user programs) and
  `std` (programs using the rvOS Rust std port) contexts.
- Re-exports `rvos_wire` types for convenience so callers do not need to
  depend on `rvos-wire` directly.

---

## 2. Error Types

### Current Problem

The kernel ABI returns `usize::MAX` for errors, `1` for "empty" on
non-blocking recv, and `0` for success. User code currently checks these
magic values manually:

```rust
// Today: easy to forget, easy to mis-check
let ret = sys_chan_send(handle, &msg);
// What if ret is usize::MAX? We just ignore it.
```

### Design

```rust
/// Errors returned by rvOS syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// The handle was invalid, closed, or of the wrong type.
    InvalidHandle,
    /// The pointer passed to the kernel was invalid.
    BadAddress,
    /// Resource exhaustion (handle table full, no free channels, OOM).
    NoResources,
    /// The channel is closed/deactivated.
    ChannelClosed,
    /// Generic/unspecified kernel error.
    Unknown,
}

/// Result type used throughout rvos.
pub type SysResult<T> = Result<T, SysError>;
```

The raw syscall layer translates `usize::MAX` to `Err(SysError)`. As the
kernel ABI gains richer error codes in the future, `SysError` variants can
be extended without breaking existing matches (callers should use `_`
catch-all arms).

---

## 3. Raw Syscall Layer

The crate includes a public `raw` module containing the inline-assembly
syscall wrappers and syscall number constants. These are the *only* place
`unsafe` and `asm!` appear. The module is public so that advanced users
can issue syscalls directly when the high-level API doesn't cover their
use case.

```rust
pub mod raw {
    // Syscall numbers (matching kernel/src/arch/trap.rs)
    pub const SYS_EXIT: usize = 93;
    pub const SYS_YIELD: usize = 124;
    pub const SYS_GETPID: usize = 172;
    pub const SYS_CHAN_CREATE: usize = 200;
    pub const SYS_CHAN_SEND: usize = 201;
    pub const SYS_CHAN_RECV: usize = 202;
    pub const SYS_CHAN_CLOSE: usize = 203;
    pub const SYS_CHAN_RECV_BLOCKING: usize = 204;
    pub const SYS_SHM_CREATE: usize = 205;
    pub const SYS_SHM_DUP_RO: usize = 206;
    pub const SYS_MUNMAP: usize = 215;
    pub const SYS_MMAP: usize = 222;

    pub fn syscall1(num: usize, a0: usize) -> usize { ... }
    pub fn syscall2(num: usize, a0: usize, a1: usize) -> (usize, usize) { ... }
}
```

All public API functions are safe wrappers that call into `raw`.

---

## 4. Message Type

### Current Problem

The `Message` struct is currently copy-pasted into every user program
(`user/shell/src/syscall.rs`). Its layout must exactly match the kernel's
`#[repr(C)]` definition.

### Design

`rvos` provides the canonical user-space `Message` definition:

```rust
/// Sentinel value meaning "no capability attached".
pub const NO_CAP: usize = usize::MAX;

/// Maximum message payload size.
pub const MAX_MSG_SIZE: usize = 64;

/// Fixed-size IPC message matching the kernel ABI layout.
#[repr(C)]
pub struct Message {
    data: [u8; MAX_MSG_SIZE],
    len: usize,
    sender_pid: usize,
    cap: usize,
}
```

Key design decisions:

- **Fields are private.** Access is through methods, allowing validation
  (e.g., `len` never exceeds `MAX_MSG_SIZE`).
- `sender_pid` has only a getter (the kernel overwrites it on send anyway).
- `cap` is accessed through typed methods that return `Option<RawHandle>`.

### Message API

```rust
impl Message {
    /// Create a new empty message.
    pub fn new() -> Self;

    /// The payload bytes (only the first `self.len()` bytes are valid).
    pub fn payload(&self) -> &[u8];

    /// The number of valid payload bytes.
    pub fn len(&self) -> usize;

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool;

    /// Mutable access to the full data buffer (for building payloads).
    pub fn data_mut(&mut self) -> &mut [u8; MAX_MSG_SIZE];

    /// Set the valid payload length.
    pub fn set_len(&mut self, len: usize);

    /// The PID of the sender (set by the kernel, read-only).
    pub fn sender_pid(&self) -> usize;

    /// The capability handle attached to this message, if any.
    pub fn cap(&self) -> Option<RawHandle>;

    /// Attach a capability handle to this message.
    pub fn set_cap(&mut self, handle: RawHandle);

    /// Clear any attached capability.
    pub fn clear_cap(&mut self);

    /// Create a message from a byte slice payload.
    pub fn from_bytes(payload: &[u8]) -> Self;

    /// Create a message from a string payload.
    pub fn from_str(s: &str) -> Self;

    /// Convenience: get a Writer over the data buffer (for rvos-wire).
    pub fn writer(&mut self) -> rvos_wire::Writer<'_>;

    /// Convenience: get a Reader over the valid payload (for rvos-wire).
    pub fn reader(&self) -> rvos_wire::Reader<'_>;
}
```

The `writer()` and `reader()` methods integrate directly with `rvos-wire`,
eliminating the manual `Writer::new(&mut msg.data)` boilerplate.

**Important:** After using `writer()`, the caller must call `set_len()` with
the writer's final position. A helper method handles this pattern:

```rust
impl Message {
    /// Build a message by serializing into the payload with a closure.
    /// Sets `len` automatically from the writer position.
    pub fn build(f: impl FnOnce(&mut rvos_wire::Writer) -> Result<(), rvos_wire::WireError>)
        -> Result<Self, rvos_wire::WireError>
    {
        let mut msg = Message::new();
        let mut w = msg.writer();
        f(&mut w)?;
        let pos = w.position();
        msg.set_len(pos);
        Ok(msg)
    }
}
```

---

## 5. Handle Abstraction

### RawHandle

A `RawHandle` is a newtype over `usize` representing a local handle index
in the process's handle table.

```rust
/// A raw kernel handle (local index into the process handle table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawHandle(usize);

impl RawHandle {
    /// Create a RawHandle from a raw index.
    ///
    /// # Safety
    /// The caller must ensure the index refers to a valid handle.
    pub unsafe fn from_raw(index: usize) -> Self;

    /// Get the raw index.
    pub fn as_raw(&self) -> usize;
}
```

`RawHandle` is a low-level type. Users will typically interact with the
higher-level `Channel` type (and later `ShmRegion`).

### The Handle Trait

All RAII handle wrappers implement a common trait:

```rust
/// Trait for types that own a kernel handle.
pub trait Handle {
    /// The underlying raw handle.
    fn raw_handle(&self) -> RawHandle;

    /// Consume self and return the raw handle without closing it.
    /// Use this when transferring a handle via IPC capability passing.
    fn into_raw(self) -> RawHandle;
}
```

The `Handle` trait is object-safe and can be used in generic contexts for
capability passing.

---

## 6. Channel Type

The `Channel` is the primary IPC type -- an RAII wrapper that closes its
handle on `Drop`.

### Definition

```rust
/// An owned channel endpoint.
///
/// Closing happens automatically when the Channel is dropped.
/// To transfer ownership via IPC, use `.into_raw()` to prevent
/// the drop from closing the handle.
pub struct Channel {
    handle: RawHandle,
}

impl Handle for Channel {
    fn raw_handle(&self) -> RawHandle { self.handle }
    fn into_raw(self) -> RawHandle {
        let h = self.handle;
        core::mem::forget(self);
        h
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        raw::syscall1(SYS_CHAN_CLOSE, self.handle.as_raw());
    }
}
```

### Construction

```rust
impl Channel {
    /// Create a new channel pair. Returns two endpoints (a, b).
    pub fn create_pair() -> SysResult<(Channel, Channel)>;

    /// Wrap an existing raw handle as a Channel.
    ///
    /// # Safety
    /// The handle must be a valid channel endpoint. The Channel takes
    /// ownership and will close the handle on drop.
    pub unsafe fn from_raw(handle: RawHandle) -> Self;
}
```

### Sending

```rust
impl Channel {
    /// Send a message on this channel.
    pub fn send(&self, msg: &Message) -> SysResult<()>;

    /// Send a message with an attached capability.
    /// The handle is consumed (transferred to the receiver).
    pub fn send_with_cap(&self, msg: &Message, cap: impl Handle) -> SysResult<()>;
}
```

`send_with_cap` calls `cap.into_raw()` to extract the raw handle, sets
`msg.cap`, and sends. If the send fails, the capability handle is lost
(the kernel closed the channel, so the handle is invalid anyway). This
matches Fuchsia semantics where a failed send with a handle still consumes
the handle.

### Receiving

```rust
impl Channel {
    /// Non-blocking receive. Returns `Ok(None)` if no message available.
    pub fn recv(&self) -> SysResult<Option<Message>>;

    /// Blocking receive. Suspends the process until a message arrives.
    pub fn recv_blocking(&self) -> SysResult<Message>;
}
```

### Typed Send/Recv (rvos-wire Integration)

The key ergonomic improvement: send and receive typed Rust values directly.

```rust
impl Channel {
    /// Serialize a value and send it as a message.
    pub fn send_typed<T: rvos_wire::Serialize>(&self, val: &T) -> SysResult<()> {
        let msg = Message::build(|w| val.serialize(w))
            .map_err(|_| SysError::NoResources)?;
        self.send(&msg)
    }

    /// Receive a message and deserialize it into a typed value.
    /// Blocking.
    pub fn recv_typed<'a, T: rvos_wire::Deserialize<'a>>(&self)
        -> SysResult<T>
    {
        // Note: this requires careful lifetime handling.
        // See "Lifetime Considerations" below.
    }

    /// Receive a message and deserialize it, returning both the
    /// deserialized value and the raw message (for capability access).
    pub fn recv_msg_typed<T: for<'a> rvos_wire::Deserialize<'a>>(&self)
        -> SysResult<(T, Message)>
    {
        let msg = self.recv_blocking()?;
        let val = rvos_wire::from_bytes(msg.payload())
            .map_err(|_| SysError::Unknown)?;
        Ok((val, msg))
    }
}
```

### Lifetime Considerations

`rvos_wire::Deserialize<'a>` borrows from the input buffer. For types that
borrow (like `&str`), the caller needs the message to outlive the
deserialized value. `recv_msg_typed` returns both the message and the value,
letting the caller manage lifetimes.

For owned types (like `u32`, structs containing only owned fields), the
`for<'a>` bound works cleanly.

---

## 7. Service Discovery

### Current Problem

Every user program reimplements the same boilerplate:

```rust
fn request_service(name: &[u8]) -> usize {
    let mut msg = Message::new();
    msg.data[..name.len()].copy_from_slice(name);
    msg.len = name.len();
    sys_chan_send(0, &msg);
    sys_chan_recv_blocking(0, &mut msg);
    msg.cap
}
```

This is error-prone: callers must remember to use handle 0, manually pack
the name, and extract `msg.cap` without any error checking.

### Design

```rust
/// The well-known boot channel (handle 0), used for service discovery.
pub fn boot_channel() -> &'static Channel {
    // Returns a Channel wrapping RawHandle(0).
    // This Channel must NOT be dropped (handle 0 is permanent).
    // Implemented via a leaked static or a special non-closing wrapper.
}

/// Request a service channel from the init server.
///
/// Sends the service name on the boot channel (handle 0) and blocks
/// until the init server responds with a channel capability.
///
/// Returns a Channel connected to the requested service.
pub fn connect_to_service(name: &str) -> SysResult<Channel> {
    let boot = boot_channel();
    let msg = Message::from_str(name);
    boot.send(&msg)?;
    let resp = boot.recv_blocking()?;
    match resp.cap() {
        Some(handle) => Ok(unsafe { Channel::from_raw(handle) }),
        None => Err(SysError::Unknown),  // "unknown" service
    }
}
```

### BootChannel Type

Since the boot channel must not be closed on drop, it uses a separate type:

```rust
/// A non-owning reference to a channel. Does not close on drop.
pub struct BootChannel {
    handle: RawHandle,
}

impl BootChannel {
    /// Send a message.
    pub fn send(&self, msg: &Message) -> SysResult<()>;

    /// Blocking receive.
    pub fn recv_blocking(&self) -> SysResult<Message>;
}

/// Get a reference to the boot channel (handle 0).
pub fn boot_channel() -> BootChannel {
    BootChannel { handle: RawHandle(0) }
}
```

This is simpler than trying to make `Channel` optionally non-closing. The
boot channel is a special case that warrants its own type.

### Usage

```rust
use rvos::{connect_to_service, Channel};

// Before (28 lines of boilerplate in shell.rs):
let sysinfo_handle = request_service(b"sysinfo");
let mut msg = Message::new();
msg.data[0] = b'P'; msg.data[1] = b'S'; msg.len = 2;
sys_chan_send(sysinfo_handle, &msg);
// ...
sys_chan_close(sysinfo_handle);

// After:
let sysinfo = connect_to_service("sysinfo")?;
sysinfo.send(&Message::from_str("PS"))?;
// ... read responses ...
// sysinfo closed automatically on drop
```

---

## 8. Process Control

Wrappers for non-IPC syscalls.

```rust
/// Terminate the calling process.
pub fn exit(code: usize) -> ! {
    raw::syscall1(SYS_EXIT, code);
    unreachable!()
}

/// Yield the CPU to the scheduler.
pub fn yield_now() {
    raw::syscall1(SYS_YIELD, 0);
}

/// Return the PID of the calling process.
pub fn getpid() -> usize {
    raw::syscall1(SYS_GETPID, 0)
}
```

---

## 9. Memory Mapping

```rust
/// Map anonymous zeroed pages into the calling process.
///
/// Returns a pointer to the mapped region.
pub fn mmap_anonymous(length: usize) -> SysResult<*mut u8> {
    let addr = raw::syscall2(SYS_MMAP, 0, length).0;
    if addr == usize::MAX {
        Err(SysError::NoResources)
    } else {
        Ok(addr as *mut u8)
    }
}

/// Unmap previously mapped pages.
pub fn munmap(addr: *mut u8, length: usize) -> SysResult<()> {
    let ret = raw::syscall2(SYS_MUNMAP, addr as usize, length).0;
    if ret == usize::MAX {
        Err(SysError::Unknown)
    } else {
        Ok(())
    }
}
```

---

## 10. Future: Shared Memory

The crate is designed to accommodate the shared memory extension (see
`docs/shared-memory.md`) when it is implemented. The planned API:

```rust
/// An owned shared memory region handle.
pub struct ShmRegion {
    handle: RawHandle,
}

impl Handle for ShmRegion {
    fn raw_handle(&self) -> RawHandle { self.handle }
    fn into_raw(self) -> RawHandle {
        let h = self.handle;
        core::mem::forget(self);
        h
    }
}

impl Drop for ShmRegion {
    fn drop(&mut self) {
        // SYS_CHAN_CLOSE works for SHM handles too
        raw::syscall1(SYS_CHAN_CLOSE, self.handle.as_raw());
    }
}

impl ShmRegion {
    /// Create a new shared memory region of the given size.
    pub fn create(size: usize) -> SysResult<Self>;

    /// Create a read-only duplicate of this handle.
    pub fn dup_read_only(&self) -> SysResult<ShmRegion>;

    /// Map this region into the calling process's address space.
    pub fn map(&self, length: usize) -> SysResult<MappedShm>;
}

/// An RAII guard for a mapped shared memory region.
/// Unmaps on drop.
pub struct MappedShm {
    ptr: *mut u8,
    len: usize,
}

impl MappedShm {
    pub fn as_ptr(&self) -> *const u8;
    pub fn as_mut_ptr(&self) -> *mut u8;
    pub fn len(&self) -> usize;
    pub fn as_slice(&self) -> &[u8];
    pub fn as_mut_slice(&mut self) -> &mut [u8];
}

impl Drop for MappedShm {
    fn drop(&mut self) {
        munmap(self.ptr, self.len).ok();
    }
}
```

The `Handle` trait is what makes this extensible: both `Channel` and
`ShmRegion` implement `Handle`, so `send_with_cap` works with either type.

---

## 11. Module Structure

```
lib/rvos/
  Cargo.toml
  src/
    lib.rs          -- re-exports, crate-level docs
    raw.rs          -- inline asm syscall wrappers + syscall numbers (public)
    error.rs        -- SysError, SysResult
    message.rs      -- Message type, NO_CAP, MAX_MSG_SIZE
    handle.rs       -- RawHandle, Handle trait
    channel.rs      -- Channel, BootChannel
    service.rs      -- connect_to_service(), boot_channel()
    process.rs      -- exit(), yield_now(), getpid()
    memory.rs       -- mmap_anonymous(), munmap()
```

### Public API Surface (lib.rs)

```rust
#![no_std]

pub mod raw;
pub mod error;
pub mod message;
pub mod handle;
pub mod channel;
pub mod service;
pub mod process;
pub mod memory;

// Convenience re-exports at crate root
pub use error::{SysError, SysResult};
pub use message::{Message, NO_CAP, MAX_MSG_SIZE};
pub use handle::{RawHandle, Handle};
pub use channel::Channel;
pub use service::connect_to_service;

// Re-export rvos-wire for convenience
pub use rvos_wire;
```

---

## 12. Usage Examples

### Example 1: Shell ps Command (Before and After)

**Before** (current code in `shell.rs`):

```rust
fn cmd_ps() {
    let sysinfo_handle = request_service(b"sysinfo");
    let mut msg = Message::new();
    msg.data[0] = b'P'; msg.data[1] = b'S'; msg.len = 2;
    syscall::sys_chan_send(sysinfo_handle, &msg);
    loop {
        let mut resp = Message::new();
        syscall::sys_chan_recv_blocking(sysinfo_handle, &mut resp);
        if resp.len == 0 { break; }
        io::stdout().write_all(&resp.data[..resp.len]).ok();
    }
    io::stdout().flush().ok();
    syscall::sys_chan_close(sysinfo_handle);
}
```

**After** (using `rvos`):

```rust
use rvos::{connect_to_service, Message};

fn cmd_ps() {
    let sysinfo = connect_to_service("sysinfo").unwrap();
    sysinfo.send(&Message::from_str("PS")).unwrap();
    loop {
        let resp = sysinfo.recv_blocking().unwrap();
        if resp.is_empty() { break; }
        io::stdout().write_all(resp.payload()).ok();
    }
    io::stdout().flush().ok();
    // sysinfo channel closed automatically by Drop
}
```

### Example 2: Typed Math RPC (Before and After)

**Before** (current code in `shell.rs`):

```rust
fn cmd_math(op: MathOp) {
    let math_handle = request_service(b"math");
    let mut msg = Message::new();
    let mut writer = Writer::new(&mut msg.data);
    if op.serialize(&mut writer).is_err() {
        println!("Serialize error");
        syscall::sys_chan_close(math_handle);
        return;
    }
    msg.len = writer.position();
    syscall::sys_chan_send(math_handle, &msg);
    let mut resp = Message::new();
    syscall::sys_chan_recv_blocking(math_handle, &mut resp);
    let mut reader = Reader::new(&resp.data[..resp.len]);
    match MathResponse::deserialize(&mut reader) {
        Ok(r) => println!("{}", r.answer),
        Err(_) => println!("Bad response"),
    }
    syscall::sys_chan_close(math_handle);
}
```

**After** (using `rvos`):

```rust
use rvos::connect_to_service;

fn cmd_math(op: MathOp) {
    let math = connect_to_service("math").unwrap();
    math.send_typed(&op).unwrap();
    let (resp, _msg) = math.recv_msg_typed::<MathResponse>().unwrap();
    println!("{}", resp.answer);
    // math channel closed automatically by Drop
}
```

### Example 3: Capability Passing

```rust
use rvos::{Channel, Message};

// Create a channel pair for a new service connection
let (client_end, server_end) = Channel::create_pair()?;

// Send one endpoint to another process as a capability
let mut msg = Message::from_str("new-client");
some_channel.send_with_cap(&msg, server_end)?;
// server_end is consumed (moved into the message)

// client_end can now be used to talk to the service
client_end.send(&Message::from_str("hello"))?;
let resp = client_end.recv_blocking()?;
```

### Example 4: File System Client (Future)

Shows how `rvos` + `rvos-wire` work together for the filesystem
protocol (from `docs/protocols/filesystem.md`):

```rust
use rvos::{connect_to_service, Channel, Message};
use rvos_wire::{Writer, Reader};

// Connect to filesystem
let fs = connect_to_service("fs")?;

// Open a file
let msg = Message::build(|w| {
    w.write_u8(0)?;              // tag: Open
    w.write_u8(0x00)?;           // flags: plain open
    w.write_str("/etc/motd")
})?;
fs.send(&msg)?;

let resp = fs.recv_blocking()?;
let file: Channel = match resp.cap() {
    Some(h) => unsafe { Channel::from_raw(h) },
    None => return Err(/* ... */),
};

// Read from the file channel
let read_req = Message::build(|w| {
    w.write_u8(0)?;              // tag: Read
    w.write_u64(0)?;             // offset
    w.write_u32(128)             // len
})?;
file.send(&read_req)?;

loop {
    let resp = file.recv_blocking()?;
    let mut r = resp.reader();
    let _tag = r.read_u8()?;
    let chunk = r.read_bytes()?;
    if chunk.is_empty() { break; }
    // process chunk...
}
// file channel closed on drop
```

---

## 13. Migration Plan

### Phase 1: Extract

1. Create `lib/rvos/` with `Cargo.toml` and module structure.
2. Move `Message`, `NO_CAP`, and raw syscall wrappers from
   `user/shell/src/syscall.rs` into the crate.
3. Add the `Channel`, `Handle`, and error types.
4. Add `connect_to_service`.

### Phase 2: Migrate Shell

1. Replace `user/shell/src/syscall.rs` with a dependency on `rvos`.
2. Rewrite `shell.rs` to use `Channel`, `connect_to_service`, and
   typed send/recv.
3. Delete the local `syscall` module.

### Phase 3: Migrate Other Programs

1. Update `user/hello/` to use `rvos` if it needs IPC.
2. Update any future programs to depend on `rvos` from the start.

### Phase 4: Shared Memory (When Kernel Support Lands)

1. Add `ShmRegion` and `MappedShm` types.
2. Extend the `Handle` trait implementations.
3. Existing code is unaffected.

---

## 14. Design Decisions Summary

| Decision | Rationale |
|----------|-----------|
| Name `rvos` | Idiomatic wrapper (like `fuchsia-zircon`, `nix`, `sel4`); raw syscalls are private `mod raw` |
| Private `Message` fields | Prevents invalid state (e.g., `len > 64`); enables future layout changes |
| `Channel` is RAII (close on Drop) | Prevents handle leaks, the #1 bug class in manual handle management |
| `into_raw()` for cap transfer | Explicit ownership transfer; prevents use-after-close |
| `BootChannel` separate type | Handle 0 must never be closed; a non-closing type makes this unrepresentable |
| `Handle` trait | Extensible to ShmRegion, future object types; enables generic cap passing |
| `Message::build()` closure API | Eliminates the `writer` + manual `set_len` boilerplate |
| `send_typed`/`recv_msg_typed` | Brings rvos-wire integration to the channel level; eliminates 80% of IPC boilerplate |
| `#![no_std]` | Works everywhere: bare-metal user programs, std programs, and kernel-side tests |
| Re-export `rvos_wire` | Single dependency for user programs (`rvos`) instead of two |
