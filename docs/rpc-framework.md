# rvOS RPC Framework

Machine-readable protocol definitions and type-safe RPC for rvOS IPC.

## Overview

The RPC framework consists of four layers:

| Crate | Purpose |
|-------|---------|
| `rvos-wire` | `define_message!` macro, `Transport` trait, RPC helpers |
| `rvos-proto` | Canonical protocol definitions (math, fs, ...) |
| `rvos` | `UserTransport` (user-space IPC via syscalls) |
| `kernel` | `KernelTransport` (kernel-side IPC via `channel_send/recv_blocking`) |

## `define_message!` Macro

Generates structs/enums with `Serialize` and `Deserialize` implementations.

### Struct Form

```rust
use rvos_wire::define_message;

define_message! {
    /// A 2D point.
    pub struct Point { x: u32, y: u32 }
}
```

Generates:
- `pub struct Point { pub x: u32, pub y: u32 }` with `#[derive(Debug, Clone, Copy, PartialEq, Eq)]`
- `Serialize` impl: writes fields in declaration order
- `Deserialize` impl: reads fields in declaration order

Wire format: `[x: 4 bytes LE][y: 4 bytes LE]` — no tag byte, no padding.

### Enum Form

```rust
define_message! {
    /// Math operation request.
    pub enum MathRequest {
        /// Add two numbers.
        Add(0) { a: u32, b: u32 },
        /// Multiply two numbers.
        Mul(1) { a: u32, b: u32 },
        /// Subtract b from a.
        Sub(2) { a: u32, b: u32 },
    }
}
```

Each variant has an **explicit u8 tag** in parentheses. Variants use named fields.

Generates:
- `pub enum MathRequest { Add { a: u32, b: u32 }, Mul { ... }, Sub { ... } }`
- `Serialize` impl: writes tag byte, then fields
- `Deserialize` impl: reads tag byte, matches, reads fields

Wire format for `Add { a: 3, b: 4 }`: `[0x00][03 00 00 00][04 00 00 00]`

### Unit Variants (Empty Fields)

```rust
define_message! {
    pub enum FsError {
        NotFound(1) {},
        AlreadyExists(2) {},
        Io(7) {},
    }
}
```

Empty `{}` means no fields — only the tag byte is serialized.

### Lifetime-Parameterized Form (Borrowed Fields)

For zero-copy deserialization of strings and byte slices:

```rust
define_message! {
    pub enum FsRequest<'a> {
        Open(0) { flags: u8, path: &'a str },
        Delete(1) { path: &'a str },
    }
}
```

The lifetime parameter `'a` ties borrowed fields to the underlying buffer,
enabling zero-copy deserialization. Both `&'a str` and `&'a [u8]` are supported.

Wire format for `&str` / `&[u8]`: `[len: u16 LE][bytes...]`

### Supported Field Types

| Type | Wire format |
|------|-------------|
| `bool` | 1 byte (0 or 1) |
| `u8`, `i8` | 1 byte |
| `u16`, `i16` | 2 bytes LE |
| `u32`, `i32` | 4 bytes LE |
| `u64`, `i64` | 8 bytes LE |
| `usize`, `isize` | 8 bytes LE (as u64/i64) |
| `&str` | u16 length + UTF-8 bytes |
| `&[u8]` | u16 length + raw bytes |
| Any type with `Serialize`/`Deserialize` | Nested (e.g., `OpenFlags` inside `FsRequest`) |

### Nesting

`define_message!` types can be used as fields in other `define_message!` types:

```rust
define_message! {
    pub struct OpenFlags { bits: u8 }
}

define_message! {
    pub enum FsRequest<'a> {
        Open(0) { flags: OpenFlags, path: &'a str },
    }
}
```

## Transport Trait

```rust
pub trait Transport {
    fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError>;
}
```

- `send`: serialize and send bytes with an optional capability (`NO_CAP` = none)
- `recv`: receive into buffer, returns `(bytes_received, cap)`

### Implementations

**User-space** (`rvos::UserTransport`):
```rust
let mut t = UserTransport::new(handle);
```
Uses `sys_chan_send_blocking` / `sys_chan_recv_blocking`.

**Kernel-side** (`kernel::ipc::transport::KernelTransport`):
```rust
let mut t = KernelTransport::new(endpoint, my_pid);
```
Uses `channel_send_blocking` / `channel_recv_blocking`.

## RPC Helpers

All helpers use a caller-provided `buf: &mut [u8]` as scratch space for
deserialization — no hidden allocations.

### Client Side

```rust
// Simple request-response (no capabilities)
let resp: MathResponse = rpc_call(&mut transport, &req, &mut buf)?;

// With capability passthrough
let (resp, cap): (Resp, usize) = rpc_call_with_cap(&mut transport, &req, send_cap, &mut buf)?;
```

### Server Side

```rust
// Receive and deserialize a request
let (req, cap): (MathRequest, usize) = rpc_recv(&mut transport, &mut buf)?;

// Serialize and send a response
rpc_reply(&mut transport, &response, NO_CAP)?;
```

## Constants

```rust
pub const NO_CAP: usize = usize::MAX;   // "no capability" sentinel
pub const MAX_MSG_SIZE: usize = 1024;    // max message payload
```

## Error Types

```rust
pub enum RpcError {
    ChannelClosed,       // channel was closed
    Wire(WireError),     // serialization/deserialization error
    Protocol,            // unexpected response format
    Transport(usize),    // raw syscall error code
}
```

## `define_protocol!` Macro

Generates typed client stubs, server handler traits, and dispatch functions from
a protocol definition. Layered on top of `define_message!` types.

### Syntax

```rust
use rvos_wire::define_protocol;

define_protocol! {
    /// Math service protocol.
    pub protocol Math => MathClient, MathHandler, math_dispatch {
        type Request = MathRequest;
        type Response = MathResponse;

        rpc add as Add(a: u32, b: u32) -> MathResponse;
        rpc mul as Mul(a: u32, b: u32) -> MathResponse;
        rpc sub as Sub(a: u32, b: u32) -> MathResponse;
    }
}
```

The `=> ClientName, HandlerName, dispatch_fn` syntax provides the names of the
generated items explicitly (since `macro_rules!` cannot concatenate identifiers).

Each `rpc` line maps to one variant of the Request enum. The `as Variant` syntax
provides the enum variant name.

### Generated Items

For the protocol above:

- **`MathClient<T: Transport>`** -- client struct with typed methods (`add()`, `mul()`, `sub()`)
- **`MathHandler`** -- trait with one method per `rpc` line
- **`math_dispatch<T, H>()`** -- free function that receives a request, dispatches to
  the handler, and sends the response

### Capability Annotation `[+cap]`

Append `[+cap]` to a method to indicate it carries a capability:

```rust
rpc open as Open(flags: OpenFlags, path: &str) -> FsResponse [+cap];
```

- Client method returns `Result<(Response, usize), RpcError>` (the `usize` is the received cap)
- Without `[+cap]`, client method returns `Result<Response, RpcError>`
- The handler trait always returns `(Response, usize)` so handlers can attach caps on any method

### Lifetime-Parameterized Types

For protocols with borrowed request/response types:

```rust
define_protocol! {
    pub protocol FsControl => FsControlClient, FsControlHandler, fs_control_dispatch {
        type Request<'a> = FsRequest;
        type Response = FsResponse;

        rpc open as Open(flags: OpenFlags, path: &str) -> FsResponse [+cap];
        rpc delete as Delete(path: &str) -> FsResponse;
    }
}
```

The lifetime on `type Request<'a>` / `type Response<'a>` tells the macro the type
has a lifetime parameter, but the type name itself is always a bare identifier.

## Example: Math Service

### Protocol Definition (`rvos-proto/src/math.rs`)

```rust
use rvos_wire::{define_message, define_protocol};

define_message! {
    pub enum MathRequest {
        Add(0) { a: u32, b: u32 },
        Mul(1) { a: u32, b: u32 },
        Sub(2) { a: u32, b: u32 },
    }
}

define_message! {
    pub struct MathResponse { answer: u32 }
}

define_protocol! {
    pub protocol Math => MathClient, MathHandler, math_dispatch {
        type Request = MathRequest;
        type Response = MathResponse;

        rpc add as Add(a: u32, b: u32) -> MathResponse;
        rpc mul as Mul(a: u32, b: u32) -> MathResponse;
        rpc sub as Sub(a: u32, b: u32) -> MathResponse;
    }
}
```

### Client (user-space shell)

```rust
use rvos::UserTransport;
use rvos_proto::math::MathClient;

let math_handle = request_service(b"math");
let mut client = MathClient::new(UserTransport::new(math_handle));
match client.add(3, 4) {
    Ok(resp) => println!("{}", resp.answer), // 7
    Err(_) => println!("Bad response"),
}
raw::sys_chan_close(math_handle);
```

### Server (kernel task)

```rust
use rvos_proto::math::{MathResponse, MathHandler, math_dispatch};
use rvos_wire::NO_CAP;

struct MathImpl;

impl MathHandler for MathImpl {
    fn add(&mut self, a: u32, b: u32) -> (MathResponse, usize) {
        (MathResponse { answer: a.wrapping_add(b) }, NO_CAP)
    }
    fn mul(&mut self, a: u32, b: u32) -> (MathResponse, usize) {
        (MathResponse { answer: a.wrapping_mul(b) }, NO_CAP)
    }
    fn sub(&mut self, a: u32, b: u32) -> (MathResponse, usize) {
        (MathResponse { answer: a.wrapping_sub(b) }, NO_CAP)
    }
}

// In the service loop:
let mut handler = MathImpl;
loop {
    let client = ipc::OwnedEndpoint::new(ipc::accept_client(control_ep, my_pid));
    let mut transport = KernelTransport::new(client.raw(), my_pid);
    let _ = math_dispatch(&mut transport, &mut handler);
}
```

## Adding a New Protocol

1. Create `lib/rvos-proto/src/myproto.rs` with `define_message!` types
2. Add a `define_protocol!` block referencing those message types
3. Add `pub mod myproto;` to `lib/rvos-proto/src/lib.rs`
4. **Client**: import `{Name}Client`, create with `{Name}Client::new(transport)`, call typed methods
5. **Server**: implement `{Name}Handler`, call `{name}_dispatch(&mut transport, &mut handler)` in the event loop
