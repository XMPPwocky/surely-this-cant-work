# 0005: Typed Capability Serialization

**Date:** 2026-02-10
**Status:** Implemented
**Subsystem:** lib/rvos-wire, lib/rvos

## Motivation

Today, capabilities (channel handles, SHM handles) are passed as raw `usize`
values through a separate sideband array (`Message.caps[]`), completely
disconnected from the serialized data payload and the type system. This means:

1. **No type safety**: A `usize` handle tells you nothing about what protocol
   the channel speaks. You receive `(BootResponse, usize)` and must manually
   know (or trust documentation) that the usize is a filesystem channel, a
   process handle, etc.

2. **Separate plumbing**: Every RPC method that transfers a capability needs
   special `[+cap]` annotations in `define_protocol!`, separate
   `send_with_cap` / `recv_with_cap_blocking` methods, and manual cap array
   management. Capabilities can't be fields in `define_message!` structs.

3. **Error-prone**: It's easy to forget to include a cap, pass caps in the
   wrong order, or mismatch the cap type with the response.

This feature makes capabilities first-class serializable types. A
`ChannelCap<Req, Resp>` can appear as a field in any `define_message!`
struct, and the framework handles the sideband plumbing transparently:

```rust
define_message! {
    pub struct SpawnResponse {
        status: u32,
        process: ChannelCap<ProcessReq, ProcessResp>,  // Strongly typed!
    }
}
```

The serialized representation on the wire is a `u8` index into the sideband
caps array. The type parameters exist only at compile time — zero runtime
overhead.

## Design

### Overview

We introduce `ChannelCap<S, R>`, a typed channel capability wrapper in
`rvos-wire` that implements `Serialize` and `Deserialize`. On the wire, a
`ChannelCap` serializes as a single `u8` — the index into the message's
capability sideband array. During serialization, the raw handle is deposited
into the `Writer`'s cap accumulator; during deserialization, the index is
read and the handle is pulled from the `Reader`'s cap array.

The name `ChannelCap` (rather than generic `Cap`) leaves room for other
capability types like `ShmCap` in the future.

`Writer` and `Reader` are extended with internal cap arrays. The existing
`Writer::new()` / `Reader::new()` constructors initialize empty cap arrays,
so all existing code continues to work unchanged. New methods
(`push_cap`, `read_cap`, `caps()`, `cap_count()`, `Reader::with_caps()`)
provide the cap sideband mechanism.

`ChannelCap<S, R>` is **move-only** (not Copy, not Clone). It stores the
resolved handle after deserialization. Consuming it via `into_channel()`
transfers ownership to a `Channel<S, R>` (which has `Drop`). Move semantics
prevent accidental double-use of a handle.

Because `ChannelCap` is not Copy, `define_message!` needs a new `owned`
struct/enum arm that does not derive Copy/Clone.

**No sentinels.** Serializing a `ChannelCap` when the Writer's cap sideband
is full is a `WireError::CapOverflow`. Deserializing a `ChannelCap` when
the Reader doesn't have enough caps is also `WireError::CapOverflow`. There
is no silent NO_CAP fallback — missing caps are always hard errors.

### The `ChannelCap<S, R>` Type

Lives in `rvos-wire`:

```rust
use core::marker::PhantomData;

/// A typed channel capability handle for wire serialization.
///
/// `S` is the message type this cap's channel sends; `R` is what it receives.
/// On the wire, serializes as a u8 index into the message's caps sideband.
///
/// `ChannelCap` is move-only — it cannot be copied or cloned. This prevents
/// accidental double-ownership of the underlying handle. Use
/// `into_channel()` (in lib/rvos) to convert into an RAII `Channel<S, R>`.
#[derive(Debug)]
pub struct ChannelCap<S, R> {
    handle: usize,
    _phantom: PhantomData<fn(S) -> R>,
}

impl<S, R> ChannelCap<S, R> {
    pub fn new(handle: usize) -> Self {
        Self { handle, _phantom: PhantomData }
    }

    pub fn raw(&self) -> usize {
        self.handle
    }
}

impl<S, R> Serialize for ChannelCap<S, R> {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        let idx = w.push_cap(self.handle)?;
        w.write_u8(idx)
    }
}

impl<'a, S, R> Deserialize<'a> for ChannelCap<S, R> {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        let idx = r.read_u8()?;
        let handle = r.read_cap(idx)?;
        Ok(ChannelCap::new(handle))
    }
}
```

### Untyped Variant

For cases where you need to pass a channel capability without knowing its
protocol (rare, but exists in some boot channel patterns):

```rust
/// Untyped channel capability. Prefer `ChannelCap<S, R>` when the protocol
/// is known.
///
/// This is its own type (not a type alias for `ChannelCap<(), ()>`) so that
/// it can have its own Serialize/Deserialize impls and conversion methods
/// without phantom type parameter noise.
#[derive(Debug)]
pub struct RawChannelCap {
    handle: usize,
}
```

`RawChannelCap` is also move-only and uses the same wire format (u8
sideband index) and the same `push_cap`/`read_cap` mechanism as
`ChannelCap<S, R>`.

### `define_message!` — New `owned` Arm

Since `ChannelCap` is not Copy, structs containing it can't use the
existing `define_message!` arms (which derive Copy). A new `owned` keyword
signals the non-Copy variant:

```rust
define_message! {
    pub owned struct OpenResp {
        status: u32,
        file: ChannelCap<FileReq, FileResp>,
    }
}
```

Generated code for `owned struct`:

```rust
#[derive(Debug)]
pub struct OpenResp {
    pub status: u32,
    pub file: ChannelCap<FileReq, FileResp>,
}

// Serialize and Deserialize impls identical to the regular struct arm —
// field-by-field serialization in declaration order.
```

Differences from the regular struct arm:
- Derives only `Debug` (not Clone, Copy, PartialEq, Eq)
- Otherwise identical Serialize/Deserialize code generation

Similarly, `owned enum` for enum variants containing capabilities:

```rust
define_message! {
    pub owned enum BootResponse {
        Ok(0) { process: ChannelCap<ProcessReq, ProcessResp> },
        Error(1) { code: u32 },
    }
}
```

### Writer Changes

```rust
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    caps: [Option<usize>; MAX_CAPS],  // NEW
    cap_count: usize,                  // NEW
}

impl<'a> Writer<'a> {
    /// Create a new writer. Cap sideband is initially empty.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0, caps: [None; MAX_CAPS], cap_count: 0 }
    }

    /// Push a capability handle into the sideband. Returns the index.
    /// Fails with `CapOverflow` if all 4 sideband slots are occupied.
    pub fn push_cap(&mut self, handle: usize) -> Result<u8, WireError> {
        if self.cap_count >= MAX_CAPS {
            return Err(WireError::CapOverflow);
        }
        let idx = self.cap_count as u8;
        self.caps[self.cap_count] = Some(handle);
        self.cap_count += 1;
        Ok(idx)
    }

    /// Get the number of caps accumulated.
    pub fn cap_count(&self) -> usize {
        self.cap_count
    }

    /// Copy accumulated caps into a raw array for the transport layer.
    /// Returns the number of caps written.
    pub fn copy_caps_to(&self, out: &mut [usize; MAX_CAPS]) -> usize {
        for i in 0..self.cap_count {
            out[i] = self.caps[i].unwrap();  // safe: [0..cap_count) always Some
        }
        self.cap_count
    }

    // ... all existing methods unchanged ...
}
```

### Reader Changes

```rust
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    caps: [Option<usize>; MAX_CAPS],  // NEW
}

impl<'a> Reader<'a> {
    /// Create a reader without capabilities (backward-compatible).
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, caps: [None; MAX_CAPS] }
    }

    /// Create a reader with a caps sideband from a received message.
    pub fn with_caps(buf: &'a [u8], caps: &[usize]) -> Self {
        let mut r = Self::new(buf);
        for (i, &c) in caps.iter().enumerate().take(MAX_CAPS) {
            r.caps[i] = Some(c);
        }
        r
    }

    /// Read a capability by sideband index.
    /// Returns `CapOverflow` if the index doesn't correspond to a
    /// capability that was actually provided.
    pub fn read_cap(&mut self, index: u8) -> Result<usize, WireError> {
        let i = index as usize;
        if i >= MAX_CAPS {
            return Err(WireError::CapOverflow);
        }
        self.caps[i].ok_or(WireError::CapOverflow)
    }

    // ... all existing methods unchanged ...
}
```

Note: Reader no longer needs a separate `cap_count` field. The `Option`
type carries presence information directly — `Some(handle)` means the cap
was provided, `None` means it wasn't.

### New WireError Variant

```rust
pub enum WireError {
    // ... existing variants ...
    /// Capability sideband index out of bounds (too many caps or invalid index).
    CapOverflow,
}
```

### Convenience Functions

New cap-aware versions alongside the existing ones:

```rust
/// Serialize a value into a buffer, returning (bytes_written, cap_count).
/// Caps are written into the provided array.
pub fn to_bytes_with_caps<T: Serialize>(
    val: &T,
    buf: &mut [u8],
    caps: &mut [usize; MAX_CAPS],
) -> Result<(usize, usize), WireError> {
    let mut w = Writer::new(buf);
    val.serialize(&mut w)?;
    let cap_count = w.copy_caps_to(caps);
    Ok((w.position(), cap_count))
}

/// Deserialize a value from a buffer with a caps sideband.
pub fn from_bytes_with_caps<'a, T: Deserialize<'a>>(
    buf: &'a [u8],
    caps: &[usize],
) -> Result<T, WireError> {
    let mut r = Reader::with_caps(buf, caps);
    T::deserialize(&mut r)
}
```

The existing `to_bytes` / `from_bytes` remain unchanged (empty cap arrays).

### RPC Helper Changes

The existing `rpc_call`, `rpc_call_with_cap`, `rpc_recv`, `rpc_reply`
functions are updated to use cap-aware Writer/Reader internally:

```rust
pub fn rpc_call<'buf, T, Req, Resp>(
    transport: &mut T, req: &Req, buf: &'buf mut [u8],
) -> Result<Resp, RpcError>
where T: Transport, Req: Serialize, Resp: Deserialize<'buf>,
{
    let mut send_buf = [0u8; MAX_MSG_SIZE];
    let mut w = Writer::new(&mut send_buf);
    req.serialize(&mut w).map_err(RpcError::Wire)?;
    let mut send_caps = [0usize; MAX_CAPS];
    w.copy_caps_to(&mut send_caps);
    transport.send(&send_buf[..w.position()], &send_caps[..w.cap_count()])?;

    let mut recv_caps = [0usize; MAX_CAPS];
    let (len, cap_count) = transport.recv(buf, &mut recv_caps)?;
    let mut r = Reader::with_caps(&buf[..len], &recv_caps[..cap_count]);
    Resp::deserialize(&mut r).map_err(RpcError::Wire)
}
```

The `rpc_call_with_cap` variant can remain for backward compat (it appends
an explicit cap alongside any that come from serialization), but new code
should prefer embedding `ChannelCap<S, R>` in the message type instead.

### User-Space Integration (lib/rvos)

`Channel<S, R>` gets conversion methods to/from the wire type:

```rust
impl<S, R> Channel<S, R> {
    /// Create a ChannelCap (wire representation) from this Channel.
    /// Does NOT consume the Channel — the caller is responsible for
    /// ensuring the handle remains valid for the message recipient.
    pub fn as_cap(&self) -> ChannelCap<S, R> {
        ChannelCap::new(self.raw_handle())
    }

    /// Create a Channel from a received ChannelCap (takes RAII ownership).
    pub fn from_cap(cap: ChannelCap<S, R>) -> Self {
        Channel::from_raw_handle(cap.raw())
    }
}
```

And `ChannelCap` gets the symmetric conversion:

```rust
impl<S, R> ChannelCap<S, R> {
    /// Convert into an RAII Channel (user-space only).
    /// The returned Channel takes ownership of the handle and will
    /// close it on drop.
    pub fn into_channel(self) -> Channel<S, R> {
        Channel::from_raw_handle(self.handle)
    }
}
```

Note: `into_channel()` lives in `lib/rvos` (not in `rvos-wire`) since it
depends on the `Channel` type. This is implemented as a method on
`ChannelCap` via a trait extension or a free function in `lib/rvos`.

`Channel<S, R>::send()` and `recv_blocking()` are updated to use cap-aware
serialization so that any `ChannelCap<S, R>` fields in the message type are
automatically transferred via the sideband:

```rust
impl<S: Serialize, R> Channel<S, R> {
    pub fn send(&self, val: &S) -> SysResult<()> {
        let mut msg = Message::new();
        let mut w = rvos_wire::Writer::new(&mut msg.data);
        val.serialize(&mut w).map_err(|_| SysError::BadAddress)?;
        msg.len = w.position();
        msg.cap_count = w.copy_caps_to(&mut msg.caps);
        self.inner.send(&msg)
    }
}

impl<S, R: DeserializeOwned> Channel<S, R> {
    pub fn recv_blocking(&self) -> SysResult<R> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        rvos_wire::from_bytes_with_caps(&msg.data[..msg.len], &msg.caps[..msg.cap_count])
            .map_err(|_| SysError::BadAddress)
    }
}
```

### Interface Changes Summary

**New public API in rvos-wire:**
- `ChannelCap<S, R>` type (Serialize, Deserialize, Debug — move-only)
- `RawChannelCap` type (Serialize, Deserialize, Debug — move-only)
- `Writer::push_cap(handle) -> Result<u8, WireError>`
- `Writer::cap_count() -> usize`
- `Writer::copy_caps_to(&self, &mut [usize; MAX_CAPS]) -> usize`
- `Reader::with_caps(buf, &[usize]) -> Self`
- `Reader::read_cap(index) -> Result<usize, WireError>`
- `define_message!` `owned struct` and `owned enum` arms (non-Copy)
- `WireError::CapOverflow`
- `to_bytes_with_caps()`, `from_bytes_with_caps()`

**Changed in rvos-wire:**
- `Writer` struct: two new fields (backward-compatible, initialized empty)
- `Reader` struct: two new fields (backward-compatible, initialized empty)
- `rpc_call`, `rpc_call_with_cap`, `rpc_recv`, `rpc_reply`: use cap-aware Writer/Reader

**New in lib/rvos:**
- `Channel::as_cap() -> ChannelCap<S, R>`
- `Channel::from_cap(ChannelCap<S, R>) -> Self`
- `ChannelCap::into_channel() -> Channel<S, R>` (via extension trait or free fn)

**Changed in lib/rvos:**
- `Channel::send()`: uses Writer directly (instead of `to_bytes`) to capture caps
- `Channel::recv_blocking()`: uses `from_bytes_with_caps` to provide caps
- Same for `recv_with_cap_blocking`, `try_recv`, `try_recv_with_cap`

### Internal Changes

**Writer/Reader struct layouts change** — these are stack-allocated and only
used locally, so there are no ABI concerns. The cap arrays add
`4 * size_of::<Option<usize>>() + size_of::<usize>() = 72 bytes` to Writer
on rv64 (from `[Option<usize>; 4]` + `usize` count). Reader adds
`4 * size_of::<Option<usize>>() = 64 bytes` (no separate count, uses
`Option` for presence).

### Resource Limits

No new limits. ChannelCap<S, R> is bounded by the existing `MAX_CAPS = 4` per
message. If serialization tries to push more than 4 caps, `push_cap`
returns `WireError::CapOverflow`.

### Example: Before and After

**Before (untyped, manual cap plumbing):**
```rust
// Protocol definition
define_protocol! {
    pub protocol Fs => FsClient, FsHandler, fs_dispatch {
        type Request<'a> = FsReq;
        type Response = FsResp;
        rpc open as Open(path: &str) -> FsResp [+cap];  // raw usize
    }
}
// Usage
let (resp, cap_handle) = client.open("/etc/hosts")?;
// cap_handle is usize — what type of channel is this? Hope you guessed right!
let file_chan: Channel<FileReq, FileResp> = Channel::from_raw_handle(cap_handle);
```

**After (typed, automatic):**
```rust
// Message definition
define_message! {
    pub struct OpenResp {
        status: u32,
        file: ChannelCap<FileReq, FileResp>,  // type is explicit!
    }
}
// Usage
let resp: OpenResp = channel.recv_blocking()?;
let file_chan = resp.file.into_channel();  // type-safe, RAII
```

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Writer struct: add caps/cap_count fields | rvos-wire/src/lib.rs | Low — fields initialized empty, all existing `Writer::new()` callers unchanged |
| Reader struct: add caps/cap_count fields | rvos-wire/src/lib.rs | Low — same reasoning |
| New ChannelCap<S,R> type + Serialize/Deserialize | rvos-wire/src/lib.rs | Low — purely additive |
| New WireError::CapOverflow variant | rvos-wire/src/lib.rs | Low — additive, but existing `match` on WireError need `_` arm (check: kernel error handling in trap.rs, transport.rs) |
| RPC helpers use cap-aware Writer/Reader | rvos-wire/src/lib.rs (rpc_call, rpc_call_with_cap, rpc_recv, rpc_reply) | Medium — behavior change: caps from serialization now flow through transport. Must verify no double-counting with explicit cap args |
| Channel::send() uses Writer directly | lib/rvos/src/channel.rs | Medium — send() now captures embedded caps automatically |
| Channel::recv_*() use Reader::with_caps | lib/rvos/src/channel.rs | Medium — recv now provides caps to deserializer |
| rvos-wire tests | rvos-wire/src/lib.rs | Low — new tests added, existing tests pass |
| Existing protocols (boot, fs, gpu, etc.) | lib/rvos-proto/ | None — no migration in this phase |
| Kernel transport | kernel/src/ipc/transport.rs | None — already passes caps through Transport trait |
| define_message! macro: new `owned` arms | rvos-wire/src/lib.rs | Low — additive macro arms, existing arms unchanged |
| define_protocol! macro | rvos-wire/src/lib.rs | None — no changes in this phase |

### WireError match sites to check:

Anywhere that matches on WireError variants needs to handle the new
CapOverflow variant. Grep for `WireError::` and `WireError` matches:

- `lib/rvos-wire/src/lib.rs` — tests and internal (will be updated)
- `lib/rvos/src/channel.rs` — uses `.map_err(|_| SysError::BadAddress)` (OK, wildcard)
- `kernel/src/services/*.rs` — uses `.map_err(RpcError::Wire)` (OK, wraps)
- Any user code matching WireError directly (unlikely, but grep to confirm)

## Acceptance Criteria

- [ ] `Writer` and `Reader` carry cap sidebands; `Writer::new()` / `Reader::new()` backward-compatible
- [ ] `ChannelCap<S, R>` type exists in rvos-wire with Serialize/Deserialize impls
- [ ] `ChannelCap<S, R>` can be used as a field in `define_message!` structs
- [ ] `WireError::CapOverflow` returned when cap sideband is exhausted (>4 caps) or invalid index
- [ ] `to_bytes_with_caps` / `from_bytes_with_caps` convenience functions work
- [ ] RPC helpers (`rpc_call`, `rpc_call_with_cap`, `rpc_recv`, `rpc_reply`) use cap-aware serialization
- [ ] `Channel::from_cap()` / `Channel::as_cap()` / `ChannelCap::into_channel()` conversion methods exist
- [ ] `Channel::send()` automatically transfers embedded caps via sideband
- [ ] `Channel::recv_blocking()` (and variants) provide caps to deserializer
- [ ] Round-trip test: serialize a struct containing `Cap<A, B>`, verify cap handle preserved
- [ ] Existing rvos-wire tests still pass (no regressions)
- [ ] `make clippy` clean
- [ ] `make build` succeeds
- [ ] System boots and reaches shell (`make run`)
- [ ] `make bench` shows no significant regression

## Deferred

| Item | Rationale |
|------|-----------|
| Migrate existing protocols to use ChannelCap<S,R> | Incremental — each protocol can migrate independently. This feature provides the mechanism; migration is a separate effort. |
| ShmCap type | SHM handles get their own `ShmCap` type using the same sideband mechanism. The `ChannelCap` naming leaves room for this. |
| ChannelCap<S,R> in define_protocol! | Replace `[+cap]` annotation with typed ChannelCap fields in request/response types. Requires protocol macro changes. |
| Kernel-side ChannelCap usage | Kernel services could benefit from typed caps too, but kernel uses raw endpoints. Defer until kernel service patterns are clearer. |

## Implementation Notes

### Files modified

- **lib/rvos-wire/src/lib.rs**: Added `WireError::CapOverflow`, cap sideband to
  `Writer` (`push_cap`, `cap_count`, `copy_caps_to`) and `Reader` (`with_caps`,
  `read_cap`), `ChannelCap<S, R>` and `RawChannelCap` types with
  Serialize/Deserialize, `to_bytes_with_caps`/`from_bytes_with_caps` convenience
  functions, `owned struct`/`owned enum` arms in `define_message!`, and updated
  all 4 RPC helpers (`rpc_call`, `rpc_call_with_cap`, `rpc_recv`, `rpc_reply`)
  to use cap-aware Writer/Reader.
- **lib/rvos/src/channel.rs**: Added `Channel::from_cap()` and
  `Channel::as_cap()`, updated `send`/`send_with_cap` to use
  `to_bytes_with_caps` (captures embedded caps), updated all recv methods to use
  `from_bytes_with_caps`.

### Key design decisions

- `ChannelCap` is move-only (Debug only, no Copy/Clone) — prevents double-ownership.
- Cap sideband uses `[Option<usize>; MAX_CAPS]` internally — no sentinel values.
- Serialize pushes handle via `Writer::push_cap` and writes `u8` index; deserialize
  reads index and resolves via `Reader::read_cap`. Handle is resolved eagerly.
- `CapOverflow` error on both serialize (sideband full) and deserialize (missing cap).

## Verification

- `make clippy` — clean (0 warnings on project code)
- `cargo test -p rvos-wire` — 44 tests pass (35 existing + 9 new ChannelCap tests)
- `make build` — kernel + all user-space crates compile clean
- `make run` — system boots to shell prompt, all services start normally
