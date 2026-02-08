//! rvos-wire: Minimal binary serialization for rvOS IPC
//!
//! Zero-allocation, `no_std`, no `unsafe` binary serialization.
//! Serializes into `&mut [u8]` buffers, deserializes from `&[u8]`.

#![no_std]

/// Serialization/deserialization errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Attempted to write past end of buffer.
    BufferOverflow,
    /// Attempted to read past end of buffer.
    BufferUnderflow,
    /// Unknown enum variant tag.
    InvalidTag(u8),
    /// String contained invalid UTF-8.
    InvalidUtf8,
    /// Bool byte was not 0 or 1.
    InvalidBool(u8),
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// A cursor for serializing values into a byte buffer.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let end = self.pos + bytes.len();
        if end > self.buf.len() {
            return Err(WireError::BufferOverflow);
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub fn write_bool(&mut self, v: bool) -> Result<(), WireError> {
        self.put(&[v as u8])
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), WireError> {
        self.put(&[v])
    }

    pub fn write_u16(&mut self, v: u16) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_i8(&mut self, v: i8) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_i16(&mut self, v: i16) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_i32(&mut self, v: i32) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_i64(&mut self, v: i64) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_usize(&mut self, v: usize) -> Result<(), WireError> {
        self.write_u64(v as u64)
    }

    pub fn write_isize(&mut self, v: isize) -> Result<(), WireError> {
        self.write_i64(v as i64)
    }

    pub fn write_f32(&mut self, v: f32) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_f64(&mut self, v: f64) -> Result<(), WireError> {
        self.put(&v.to_le_bytes())
    }

    pub fn write_bytes(&mut self, v: &[u8]) -> Result<(), WireError> {
        let len = v.len() as u16;
        self.write_u16(len)?;
        self.put(v)
    }

    pub fn write_str(&mut self, v: &str) -> Result<(), WireError> {
        self.write_bytes(v.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A cursor for deserializing values from a byte buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(WireError::BufferUnderflow);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn read_bool(&mut self) -> Result<bool, WireError> {
        let b = self.read_u8()?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(WireError::InvalidBool(other)),
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        let s = self.take(1)?;
        Ok(s[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, WireError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn read_i8(&mut self) -> Result<i8, WireError> {
        let s = self.take(1)?;
        Ok(i8::from_le_bytes([s[0]]))
    }

    pub fn read_i16(&mut self) -> Result<i16, WireError> {
        let s = self.take(2)?;
        Ok(i16::from_le_bytes([s[0], s[1]]))
    }

    pub fn read_i32(&mut self) -> Result<i32, WireError> {
        let s = self.take(4)?;
        Ok(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_i64(&mut self) -> Result<i64, WireError> {
        let s = self.take(8)?;
        Ok(i64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn read_usize(&mut self) -> Result<usize, WireError> {
        Ok(self.read_u64()? as usize)
    }

    pub fn read_isize(&mut self) -> Result<isize, WireError> {
        Ok(self.read_i64()? as isize)
    }

    pub fn read_f32(&mut self) -> Result<f32, WireError> {
        let s = self.take(4)?;
        Ok(f32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_f64(&mut self) -> Result<f64, WireError> {
        let s = self.take(8)?;
        Ok(f64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.read_u16()? as usize;
        self.take(len)
    }

    pub fn read_str(&mut self) -> Result<&'a str, WireError> {
        let bytes = self.read_bytes()?;
        core::str::from_utf8(bytes).map_err(|_| WireError::InvalidUtf8)
    }
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Serialize a value into a Writer.
pub trait Serialize {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError>;
}

/// Deserialize a value from a Reader.
pub trait Deserialize<'a>: Sized {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError>;
}

// ---------------------------------------------------------------------------
// Blanket impls: primitives
// ---------------------------------------------------------------------------

impl Serialize for bool {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_bool(*self)
    }
}
impl<'a> Deserialize<'a> for bool {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_bool()
    }
}

impl Serialize for u8 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u8(*self)
    }
}
impl<'a> Deserialize<'a> for u8 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u8()
    }
}

impl Serialize for u16 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u16(*self)
    }
}
impl<'a> Deserialize<'a> for u16 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u16()
    }
}

impl Serialize for u32 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u32(*self)
    }
}
impl<'a> Deserialize<'a> for u32 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u32()
    }
}

impl Serialize for u64 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_u64(*self)
    }
}
impl<'a> Deserialize<'a> for u64 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u64()
    }
}

impl Serialize for i8 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_i8(*self)
    }
}
impl<'a> Deserialize<'a> for i8 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i8()
    }
}

impl Serialize for i16 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_i16(*self)
    }
}
impl<'a> Deserialize<'a> for i16 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i16()
    }
}

impl Serialize for i32 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_i32(*self)
    }
}
impl<'a> Deserialize<'a> for i32 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i32()
    }
}

impl Serialize for i64 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_i64(*self)
    }
}
impl<'a> Deserialize<'a> for i64 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i64()
    }
}

impl Serialize for usize {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_usize(*self)
    }
}
impl<'a> Deserialize<'a> for usize {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_usize()
    }
}

impl Serialize for isize {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_isize(*self)
    }
}
impl<'a> Deserialize<'a> for isize {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_isize()
    }
}

impl Serialize for f32 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_f32(*self)
    }
}
impl<'a> Deserialize<'a> for f32 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_f32()
    }
}

impl Serialize for f64 {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_f64(*self)
    }
}
impl<'a> Deserialize<'a> for f64 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_f64()
    }
}

// &[u8] and &str: Serialize + Deserialize (zero-copy borrows)
impl Serialize for [u8] {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_bytes(self)
    }
}

impl<'a> Deserialize<'a> for &'a [u8] {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_bytes()
    }
}

impl Serialize for str {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.write_str(self)
    }
}

impl<'a> Deserialize<'a> for &'a str {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_str()
    }
}

// Option<T>
impl<T: Serialize> Serialize for Option<T> {
    fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        match self {
            None => w.write_u8(0),
            Some(v) => {
                w.write_u8(1)?;
                v.serialize(w)
            }
        }
    }
}

impl<'a, T: Deserialize<'a>> Deserialize<'a> for Option<T> {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        match r.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::deserialize(r)?)),
            t => Err(WireError::InvalidTag(t)),
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Serialize a value into a buffer. Returns the number of bytes written.
pub fn to_bytes<T: Serialize>(val: &T, buf: &mut [u8]) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    val.serialize(&mut w)?;
    Ok(w.position())
}

/// Deserialize a value from a buffer.
pub fn from_bytes<'a, T: Deserialize<'a>>(buf: &'a [u8]) -> Result<T, WireError> {
    let mut r = Reader::new(buf);
    T::deserialize(&mut r)
}

// ---------------------------------------------------------------------------
// Transport trait and RPC helpers
// ---------------------------------------------------------------------------

/// Sentinel value meaning "no capability attached".
pub const NO_CAP: usize = usize::MAX;

/// Maximum message payload size in bytes.
pub const MAX_MSG_SIZE: usize = 1024;

/// Errors from RPC operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    /// The underlying channel was closed.
    ChannelClosed,
    /// Serialization/deserialization error.
    Wire(WireError),
    /// The response had an unexpected variant or format.
    Protocol,
    /// Raw transport/syscall error code.
    Transport(usize),
}

/// A shared memory region handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmHandle(pub usize);

/// Abstraction over kernel-side and user-side IPC transports.
///
/// Implementors wrap a channel endpoint and provide send/recv.
pub trait Transport: Sized {
    /// Send `data` bytes with an optional capability.
    /// Use `cap = NO_CAP` when no capability is attached.
    fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError>;

    /// Receive into `buf`. Returns `(bytes_received, cap)`.
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError>;

    /// Create a new transport for a child capability received on this transport.
    fn from_cap(&self, cap: usize) -> Self;
}

/// Send a request and receive a response (no capabilities).
///
/// Serializes `req`, sends it, waits for a response, and deserializes it.
pub fn rpc_call<'buf, T, Req, Resp>(
    transport: &mut T,
    req: &Req,
    buf: &'buf mut [u8],
) -> Result<Resp, RpcError>
where
    T: Transport,
    Req: Serialize,
    Resp: Deserialize<'buf>,
{
    // Serialize the request into a scratch area
    let mut send_buf = [0u8; MAX_MSG_SIZE];
    let n = to_bytes(req, &mut send_buf).map_err(RpcError::Wire)?;
    transport.send(&send_buf[..n], NO_CAP)?;

    // Receive the response
    let (len, _cap) = transport.recv(buf)?;
    let resp = from_bytes::<Resp>(&buf[..len]).map_err(RpcError::Wire)?;
    Ok(resp)
}

/// Send a request with a capability and receive a response with a capability.
///
/// Like `rpc_call` but passes `cap` on send and returns the received cap.
pub fn rpc_call_with_cap<'buf, T, Req, Resp>(
    transport: &mut T,
    req: &Req,
    cap: usize,
    buf: &'buf mut [u8],
) -> Result<(Resp, usize), RpcError>
where
    T: Transport,
    Req: Serialize,
    Resp: Deserialize<'buf>,
{
    let mut send_buf = [0u8; MAX_MSG_SIZE];
    let n = to_bytes(req, &mut send_buf).map_err(RpcError::Wire)?;
    transport.send(&send_buf[..n], cap)?;

    let (len, recv_cap) = transport.recv(buf)?;
    let resp = from_bytes::<Resp>(&buf[..len]).map_err(RpcError::Wire)?;
    Ok((resp, recv_cap))
}

/// Receive and deserialize a request (server side).
///
/// Returns `(request, cap)` where cap is the capability from the message.
pub fn rpc_recv<'buf, T, Req>(
    transport: &mut T,
    buf: &'buf mut [u8],
) -> Result<(Req, usize), RpcError>
where
    T: Transport,
    Req: Deserialize<'buf>,
{
    let (len, cap) = transport.recv(buf)?;
    let req = from_bytes::<Req>(&buf[..len]).map_err(RpcError::Wire)?;
    Ok((req, cap))
}

/// Serialize and send a response (server side).
pub fn rpc_reply<T, Resp>(
    transport: &mut T,
    resp: &Resp,
    cap: usize,
) -> Result<(), RpcError>
where
    T: Transport,
    Resp: Serialize,
{
    let mut send_buf = [0u8; MAX_MSG_SIZE];
    let n = to_bytes(resp, &mut send_buf).map_err(RpcError::Wire)?;
    transport.send(&send_buf[..n], cap)
}

// ---------------------------------------------------------------------------
// define_message! macro
// ---------------------------------------------------------------------------

/// Generate message structs/enums with `Serialize` and `Deserialize` impls.
///
/// # Struct form
/// ```ignore
/// define_message! {
///     pub struct Point { x: u32, y: u32 }
/// }
/// ```
///
/// # Enum form (with explicit u8 tags)
/// ```ignore
/// define_message! {
///     pub enum Shape {
///         Circle(0) { radius: u32 },
///         Rect(1) { w: u32, h: u32 },
///         Empty(2) {},
///     }
/// }
/// ```
///
/// # Lifetime-parameterized enum (for borrowed fields)
/// ```ignore
/// define_message! {
///     pub enum FsRequest<'a> {
///         Open(0) { flags: u8, path: &'a str },
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_message {
    // ── Struct form (no lifetime) ────────────────────────────────
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($field:ident : $fty:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis struct $name {
            $(pub $field: $fty),*
        }

        impl $crate::Serialize for $name {
            fn serialize(&self, w: &mut $crate::Writer<'_>) -> Result<(), $crate::WireError> {
                $(self.$field.serialize(w)?;)*
                Ok(())
            }
        }

        impl<'__de> $crate::Deserialize<'__de> for $name {
            fn deserialize(r: &mut $crate::Reader<'__de>) -> Result<Self, $crate::WireError> {
                Ok(Self {
                    $($field: <$fty as $crate::Deserialize<'__de>>::deserialize(r)?),*
                })
            }
        }
    };

    // ── Enum form (no lifetime) ──────────────────────────────────
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident ($tag:expr) { $($field:ident : $fty:ty),* $(,)? }
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                $variant { $($field: $fty),* }
            ),*
        }

        impl $crate::Serialize for $name {
            fn serialize(&self, w: &mut $crate::Writer<'_>) -> Result<(), $crate::WireError> {
                match self {
                    $(
                        $name::$variant { $($field),* } => {
                            w.write_u8($tag)?;
                            $($field.serialize(w)?;)*
                            Ok(())
                        }
                    ),*
                }
            }
        }

        impl<'__de> $crate::Deserialize<'__de> for $name {
            fn deserialize(r: &mut $crate::Reader<'__de>) -> Result<Self, $crate::WireError> {
                let tag = r.read_u8()?;
                match tag {
                    $(
                        $tag => {
                            $(let $field = <$fty as $crate::Deserialize<'__de>>::deserialize(r)?;)*
                            Ok($name::$variant { $($field),* })
                        }
                    ),*
                    _ => Err($crate::WireError::InvalidTag(tag)),
                }
            }
        }
    };

    // ── Enum form (with lifetime) ────────────────────────────────
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident <$lt:lifetime> {
            $(
                $(#[$vmeta:meta])*
                $variant:ident ($tag:expr) { $($field:ident : $fty:ty),* $(,)? }
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $name<$lt> {
            $(
                $(#[$vmeta])*
                $variant { $($field: $fty),* }
            ),*
        }

        impl<$lt> $crate::Serialize for $name<$lt> {
            fn serialize(&self, w: &mut $crate::Writer<'_>) -> Result<(), $crate::WireError> {
                match self {
                    $(
                        $name::$variant { $($field),* } => {
                            w.write_u8($tag)?;
                            $($field.serialize(w)?;)*
                            Ok(())
                        }
                    ),*
                }
            }
        }

        impl<$lt> $crate::Deserialize<$lt> for $name<$lt> {
            fn deserialize(r: &mut $crate::Reader<$lt>) -> Result<Self, $crate::WireError> {
                let tag = r.read_u8()?;
                match tag {
                    $(
                        $tag => {
                            $(let $field = <$fty as $crate::Deserialize<$lt>>::deserialize(r)?;)*
                            Ok($name::$variant { $($field),* })
                        }
                    ),*
                    _ => Err($crate::WireError::InvalidTag(tag)),
                }
            }
        }
    };

    // ── Struct form (with lifetime) ──────────────────────────────
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident <$lt:lifetime> {
            $($field:ident : $fty:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        $vis struct $name<$lt> {
            $(pub $field: $fty),*
        }

        impl<$lt> $crate::Serialize for $name<$lt> {
            fn serialize(&self, w: &mut $crate::Writer<'_>) -> Result<(), $crate::WireError> {
                $(self.$field.serialize(w)?;)*
                Ok(())
            }
        }

        impl<$lt> $crate::Deserialize<$lt> for $name<$lt> {
            fn deserialize(r: &mut $crate::Reader<$lt>) -> Result<Self, $crate::WireError> {
                Ok(Self {
                    $($field: <$fty as $crate::Deserialize<$lt>>::deserialize(r)?),*
                })
            }
        }
    };
}

// ---------------------------------------------------------------------------
// define_protocol! macro
// ---------------------------------------------------------------------------

/// Generate a typed RPC client, server handler trait, and dispatch function
/// from a protocol definition.
///
/// # Syntax
///
/// ```ignore
/// define_protocol! {
///     /// Math service protocol.
///     pub protocol Math => MathClient, MathHandler, math_dispatch {
///         type Request = MathRequest;
///         type Response = MathResponse;
///
///         rpc add as Add(a: u32, b: u32) -> MathResponse;
///         rpc mul as Mul(a: u32, b: u32) -> MathResponse;
///     }
/// }
/// ```
///
/// The `=> ClientName, HandlerName, dispatch_fn` syntax provides the names
/// of the generated items explicitly (since `macro_rules!` cannot concatenate
/// or capitalize identifiers).
///
/// Each `rpc` line maps to one variant of the Request enum. The `as Variant`
/// syntax provides the enum variant name.
///
/// Append `[+cap]` to a method to indicate it carries a capability:
/// - Client method returns `Result<(Response, usize), RpcError>`
/// - Uses `rpc_call_with_cap` instead of `rpc_call`
///
/// Without `[+cap]`, client method returns `Result<Response, RpcError>`.
///
/// The handler trait always returns `(Response, usize)` so handlers can
/// attach capabilities on any method.
#[macro_export]
macro_rules! define_protocol {
    // ── Arm 1: Request without lifetime, Response without lifetime ──
    (
        $(#[$meta:meta])*
        $vis:vis protocol $name:ident =>
            $client:ident, $handler:ident, $dispatch:ident
        {
            type Request = $req_ty:ident;
            type Response = $resp_ty:ident;

            $(
                $(#[$method_meta:meta])*
                rpc $method:ident as $variant:ident ($($arg:ident : $arg_ty:ty),* $(,)?)
                    -> $ret_ty:ty $([$cap_ann:tt $cap_plus:tt])?;
            )*
        }
    ) => {
        $(#[$meta])*
        $vis struct $client<T: $crate::Transport> {
            transport: T,
            buf: [u8; $crate::MAX_MSG_SIZE],
        }

        impl<T: $crate::Transport> $client<T> {
            pub fn new(transport: T) -> Self {
                Self { transport, buf: [0u8; $crate::MAX_MSG_SIZE] }
            }

            pub fn into_inner(self) -> T {
                self.transport
            }

            $(
                $(#[$method_meta])*
                $crate::__define_protocol_client_method!(
                    $method, $variant, ($($arg : $arg_ty),*), $ret_ty, $req_ty
                    $(, [$cap_ann $cap_plus])?
                );
            )*
        }

        $vis trait $handler {
            $(
                fn $method(&mut self, $($arg: $arg_ty),*) -> ($resp_ty, usize);
            )*
        }

        $vis fn $dispatch<T: $crate::Transport, H: $handler>(
            transport: &mut T,
            handler: &mut H,
        ) -> Result<(), $crate::RpcError> {
            let mut buf = [0u8; $crate::MAX_MSG_SIZE];
            let (req, _cap) = $crate::rpc_recv(transport, &mut buf)?;
            let (resp, resp_cap) = match req {
                $(
                    $req_ty::$variant { $($arg),* } => handler.$method($($arg),*),
                )*
            };
            $crate::rpc_reply(transport, &resp, resp_cap)
        }
    };

    // ── Arm 2: Request with lifetime, Response without lifetime ──
    (
        $(#[$meta:meta])*
        $vis:vis protocol $name:ident =>
            $client:ident, $handler:ident, $dispatch:ident
        {
            type Request<$lt:lifetime> = $req_ty:ident;
            type Response = $resp_ty:ident;

            $(
                $(#[$method_meta:meta])*
                rpc $method:ident as $variant:ident ($($arg:ident : $arg_ty:ty),* $(,)?)
                    -> $ret_ty:ty $([$cap_ann:tt $cap_plus:tt])?;
            )*
        }
    ) => {
        $(#[$meta])*
        $vis struct $client<T: $crate::Transport> {
            transport: T,
            buf: [u8; $crate::MAX_MSG_SIZE],
        }

        impl<T: $crate::Transport> $client<T> {
            pub fn new(transport: T) -> Self {
                Self { transport, buf: [0u8; $crate::MAX_MSG_SIZE] }
            }

            pub fn into_inner(self) -> T {
                self.transport
            }

            $(
                $(#[$method_meta])*
                $crate::__define_protocol_client_method!(
                    $method, $variant, ($($arg : $arg_ty),*), $ret_ty, $req_ty
                    $(, [$cap_ann $cap_plus])?
                );
            )*
        }

        $vis trait $handler {
            $(
                fn $method(&mut self, $($arg: $arg_ty),*) -> ($resp_ty, usize);
            )*
        }

        $vis fn $dispatch<T: $crate::Transport, H: $handler>(
            transport: &mut T,
            handler: &mut H,
        ) -> Result<(), $crate::RpcError> {
            let mut buf = [0u8; $crate::MAX_MSG_SIZE];
            let (req, _cap) = $crate::rpc_recv(transport, &mut buf)?;
            let (resp, resp_cap) = match req {
                $(
                    $req_ty::$variant { $($arg),* } => handler.$method($($arg),*),
                )*
            };
            $crate::rpc_reply(transport, &resp, resp_cap)
        }
    };

    // ── Arm 3: Request with lifetime, Response with lifetime ──
    (
        $(#[$meta:meta])*
        $vis:vis protocol $name:ident =>
            $client:ident, $handler:ident, $dispatch:ident
        {
            type Request<$lt:lifetime> = $req_ty:ident;
            type Response<$lt2:lifetime> = $resp_ty:ident;

            $(
                $(#[$method_meta:meta])*
                rpc $method:ident as $variant:ident ($($arg:ident : $arg_ty:ty),* $(,)?)
                    -> $ret_ty:ty $([$cap_ann:tt $cap_plus:tt])?;
            )*
        }
    ) => {
        $(#[$meta])*
        $vis struct $client<T: $crate::Transport> {
            transport: T,
            buf: [u8; $crate::MAX_MSG_SIZE],
        }

        impl<T: $crate::Transport> $client<T> {
            pub fn new(transport: T) -> Self {
                Self { transport, buf: [0u8; $crate::MAX_MSG_SIZE] }
            }

            pub fn into_inner(self) -> T {
                self.transport
            }

            $(
                $(#[$method_meta])*
                $crate::__define_protocol_client_method!(
                    $method, $variant, ($($arg : $arg_ty),*), $ret_ty, $req_ty
                    $(, [$cap_ann $cap_plus])?
                );
            )*
        }

        $vis trait $handler {
            $(
                fn $method(&mut self, $($arg: $arg_ty),*) -> ($resp_ty, usize);
            )*
        }

        $vis fn $dispatch<T: $crate::Transport, H: $handler>(
            transport: &mut T,
            handler: &mut H,
        ) -> Result<(), $crate::RpcError> {
            let mut buf = [0u8; $crate::MAX_MSG_SIZE];
            let (req, _cap) = $crate::rpc_recv(transport, &mut buf)?;
            let (resp, resp_cap) = match req {
                $(
                    $req_ty::$variant { $($arg),* } => handler.$method($($arg),*),
                )*
            };
            $crate::rpc_reply(transport, &resp, resp_cap)
        }
    };

    // ── Arm 4: Request without lifetime, Response with lifetime ──
    (
        $(#[$meta:meta])*
        $vis:vis protocol $name:ident =>
            $client:ident, $handler:ident, $dispatch:ident
        {
            type Request = $req_ty:ty;
            type Response<$lt:lifetime> = $resp_ty:ident;

            $(
                $(#[$method_meta:meta])*
                rpc $method:ident as $variant:ident ($($arg:ident : $arg_ty:ty),* $(,)?)
                    -> $ret_ty:ty $([$cap_ann:tt $cap_plus:tt])?;
            )*
        }
    ) => {
        $(#[$meta])*
        $vis struct $client<T: $crate::Transport> {
            transport: T,
            buf: [u8; $crate::MAX_MSG_SIZE],
        }

        impl<T: $crate::Transport> $client<T> {
            pub fn new(transport: T) -> Self {
                Self { transport, buf: [0u8; $crate::MAX_MSG_SIZE] }
            }

            pub fn into_inner(self) -> T {
                self.transport
            }

            $(
                $(#[$method_meta])*
                $crate::__define_protocol_client_method!(
                    $method, $variant, ($($arg : $arg_ty),*), $ret_ty, $req_ty
                    $(, [$cap_ann $cap_plus])?
                );
            )*
        }

        $vis trait $handler {
            $(
                fn $method(&mut self, $($arg: $arg_ty),*) -> ($resp_ty, usize);
            )*
        }

        $vis fn $dispatch<T: $crate::Transport, H: $handler>(
            transport: &mut T,
            handler: &mut H,
        ) -> Result<(), $crate::RpcError> {
            let mut buf = [0u8; $crate::MAX_MSG_SIZE];
            let (req, _cap) = $crate::rpc_recv(transport, &mut buf)?;
            let (resp, resp_cap) = match req {
                $(
                    $req_ty::$variant { $($arg),* } => handler.$method($($arg),*),
                )*
            };
            $crate::rpc_reply(transport, &resp, resp_cap)
        }
    };
}

// ── Internal: single client method, dispatch by annotation ──
#[doc(hidden)]
#[macro_export]
macro_rules! __define_protocol_client_method {
    // With [+cap] — raw untyped capability
    ($method:ident, $variant:ident, ($($arg:ident : $arg_ty:ty),*), $ret_ty:ty, $req_ty:ident, [+ cap]) => {
        pub fn $method(&mut self, $($arg: $arg_ty),*) -> Result<($ret_ty, usize), $crate::RpcError> {
            let req = $req_ty::$variant { $($arg),* };
            $crate::rpc_call_with_cap(&mut self.transport, &req, $crate::NO_CAP, &mut self.buf)
        }
    };
    // With [-> shm] — shared memory handle
    ($method:ident, $variant:ident, ($($arg:ident : $arg_ty:ty),*), $ret_ty:ty, $req_ty:ident, [-> shm]) => {
        pub fn $method(&mut self, $($arg: $arg_ty),*) -> Result<($ret_ty, $crate::ShmHandle), $crate::RpcError> {
            let req = $req_ty::$variant { $($arg),* };
            let (resp, cap) = $crate::rpc_call_with_cap(
                &mut self.transport, &req, $crate::NO_CAP, &mut self.buf)?;
            Ok((resp, $crate::ShmHandle(cap)))
        }
    };
    // With [-> ClientType] — typed channel capability
    ($method:ident, $variant:ident, ($($arg:ident : $arg_ty:ty),*), $ret_ty:ty, $req_ty:ident, [-> $child:ident]) => {
        pub fn $method(&mut self, $($arg: $arg_ty),*) -> Result<($ret_ty, $child<T>), $crate::RpcError> {
            let req = $req_ty::$variant { $($arg),* };
            let (resp, cap) = $crate::rpc_call_with_cap(
                &mut self.transport, &req, $crate::NO_CAP, &mut self.buf)?;
            let child = $child::new(self.transport.from_cap(cap));
            Ok((resp, child))
        }
    };
    // Without annotation — no capability
    ($method:ident, $variant:ident, ($($arg:ident : $arg_ty:ty),*), $ret_ty:ty, $req_ty:ident) => {
        pub fn $method(&mut self, $($arg: $arg_ty),*) -> Result<$ret_ty, $crate::RpcError> {
            let req = $req_ty::$variant { $($arg),* };
            $crate::rpc_call(&mut self.transport, &req, &mut self.buf)
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // 1. Bool round-trip
    #[test]
    fn test_bool_round_trip() {
        let mut buf = [0u8; 2];
        let mut w = Writer::new(&mut buf);
        w.write_bool(true).unwrap();
        w.write_bool(false).unwrap();

        let mut r = Reader::new(&buf);
        assert_eq!(r.read_bool().unwrap(), true);
        assert_eq!(r.read_bool().unwrap(), false);
    }

    // 2. Integer round-trips
    #[test]
    fn test_integer_round_trips() {
        let mut buf = [0u8; 128];

        let mut w = Writer::new(&mut buf);
        w.write_u8(0).unwrap();
        w.write_u8(u8::MAX).unwrap();
        w.write_u16(0).unwrap();
        w.write_u16(u16::MAX).unwrap();
        w.write_u32(0).unwrap();
        w.write_u32(u32::MAX).unwrap();
        w.write_u64(0).unwrap();
        w.write_u64(u64::MAX).unwrap();
        w.write_i8(i8::MIN).unwrap();
        w.write_i8(i8::MAX).unwrap();
        w.write_i16(i16::MIN).unwrap();
        w.write_i16(i16::MAX).unwrap();
        w.write_i32(i32::MIN).unwrap();
        w.write_i32(i32::MAX).unwrap();
        w.write_i64(i64::MIN).unwrap();
        w.write_i64(i64::MAX).unwrap();
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(r.read_u8().unwrap(), 0);
        assert_eq!(r.read_u8().unwrap(), u8::MAX);
        assert_eq!(r.read_u16().unwrap(), 0);
        assert_eq!(r.read_u16().unwrap(), u16::MAX);
        assert_eq!(r.read_u32().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), u32::MAX);
        assert_eq!(r.read_u64().unwrap(), 0);
        assert_eq!(r.read_u64().unwrap(), u64::MAX);
        assert_eq!(r.read_i8().unwrap(), i8::MIN);
        assert_eq!(r.read_i8().unwrap(), i8::MAX);
        assert_eq!(r.read_i16().unwrap(), i16::MIN);
        assert_eq!(r.read_i16().unwrap(), i16::MAX);
        assert_eq!(r.read_i32().unwrap(), i32::MIN);
        assert_eq!(r.read_i32().unwrap(), i32::MAX);
        assert_eq!(r.read_i64().unwrap(), i64::MIN);
        assert_eq!(r.read_i64().unwrap(), i64::MAX);
    }

    // 3. Float round-trips
    #[test]
    fn test_float_round_trips() {
        let mut buf = [0u8; 64];

        let mut w = Writer::new(&mut buf);
        w.write_f32(0.0).unwrap();
        w.write_f32(1.0).unwrap();
        w.write_f32(-1.0).unwrap();
        w.write_f32(core::f32::consts::PI).unwrap();
        w.write_f64(0.0).unwrap();
        w.write_f64(1.0).unwrap();
        w.write_f64(-1.0).unwrap();
        w.write_f64(core::f64::consts::PI).unwrap();
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(r.read_f32().unwrap(), 0.0f32);
        assert_eq!(r.read_f32().unwrap(), 1.0f32);
        assert_eq!(r.read_f32().unwrap(), -1.0f32);
        assert_eq!(r.read_f32().unwrap(), core::f32::consts::PI);
        assert_eq!(r.read_f64().unwrap(), 0.0f64);
        assert_eq!(r.read_f64().unwrap(), 1.0f64);
        assert_eq!(r.read_f64().unwrap(), -1.0f64);
        assert_eq!(r.read_f64().unwrap(), core::f64::consts::PI);
    }

    // 4. usize round-trip
    #[test]
    fn test_usize_round_trip() {
        let mut buf = [0u8; 32];

        let mut w = Writer::new(&mut buf);
        w.write_usize(0).unwrap();
        w.write_usize(12345678).unwrap();
        w.write_isize(-42).unwrap();
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(r.read_usize().unwrap(), 0);
        assert_eq!(r.read_usize().unwrap(), 12345678);
        assert_eq!(r.read_isize().unwrap(), -42);
    }

    // 5. Bytes round-trip
    #[test]
    fn test_bytes_round_trip() {
        let mut buf = [0u8; 64];

        let mut w = Writer::new(&mut buf);
        w.write_bytes(&[]).unwrap();
        w.write_bytes(&[1, 2, 3]).unwrap();
        w.write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(r.read_bytes().unwrap(), &[]);
        assert_eq!(r.read_bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(r.read_bytes().unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // 6. String round-trip
    #[test]
    fn test_str_round_trip() {
        let mut buf = [0u8; 64];

        let mut w = Writer::new(&mut buf);
        w.write_str("").unwrap();
        w.write_str("hello").unwrap();
        w.write_str("日本語").unwrap(); // multi-byte UTF-8
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(r.read_str().unwrap(), "");
        assert_eq!(r.read_str().unwrap(), "hello");
        assert_eq!(r.read_str().unwrap(), "日本語");
    }

    // 7. Option round-trip
    #[test]
    fn test_option_round_trip() {
        let mut buf = [0u8; 32];

        let none: Option<u32> = None;
        let some: Option<u32> = Some(42);

        let n = to_bytes(&none, &mut buf).unwrap();
        assert_eq!(n, 1);
        let result: Option<u32> = from_bytes(&buf[..n]).unwrap();
        assert_eq!(result, None);

        let n = to_bytes(&some, &mut buf).unwrap();
        assert_eq!(n, 5); // 1 tag + 4 u32
        let result: Option<u32> = from_bytes(&buf[..n]).unwrap();
        assert_eq!(result, Some(42));
    }

    // 8. Struct round-trip
    #[test]
    fn test_struct_round_trip() {
        struct Point {
            x: i32,
            y: i32,
            label: u8,
        }

        impl Serialize for Point {
            fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                w.write_i32(self.x)?;
                w.write_i32(self.y)?;
                w.write_u8(self.label)
            }
        }

        impl<'a> Deserialize<'a> for Point {
            fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
                Ok(Self {
                    x: r.read_i32()?,
                    y: r.read_i32()?,
                    label: r.read_u8()?,
                })
            }
        }

        let p = Point {
            x: -100,
            y: 200,
            label: 7,
        };

        let mut buf = [0u8; 32];
        let n = to_bytes(&p, &mut buf).unwrap();
        assert_eq!(n, 9); // 4 + 4 + 1

        let p2: Point = from_bytes(&buf[..n]).unwrap();
        assert_eq!(p2.x, -100);
        assert_eq!(p2.y, 200);
        assert_eq!(p2.label, 7);
    }

    // 9. Enum round-trip
    #[test]
    fn test_enum_round_trip() {
        #[derive(Debug, PartialEq)]
        enum Shape {
            Circle(u32),       // variant 0
            Rect(u32, u32),    // variant 1
            Empty,             // variant 2
        }

        impl Serialize for Shape {
            fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                match self {
                    Shape::Circle(r) => {
                        w.write_u8(0)?;
                        w.write_u32(*r)
                    }
                    Shape::Rect(w_val, h) => {
                        w.write_u8(1)?;
                        w.write_u32(*w_val)?;
                        w.write_u32(*h)
                    }
                    Shape::Empty => w.write_u8(2),
                }
            }
        }

        impl<'a> Deserialize<'a> for Shape {
            fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
                match r.read_u8()? {
                    0 => Ok(Shape::Circle(r.read_u32()?)),
                    1 => Ok(Shape::Rect(r.read_u32()?, r.read_u32()?)),
                    2 => Ok(Shape::Empty),
                    t => Err(WireError::InvalidTag(t)),
                }
            }
        }

        let shapes = [
            Shape::Circle(10),
            Shape::Rect(3, 4),
            Shape::Empty,
        ];

        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        for s in &shapes {
            s.serialize(&mut w).unwrap();
        }
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(Shape::deserialize(&mut r).unwrap(), Shape::Circle(10));
        assert_eq!(Shape::deserialize(&mut r).unwrap(), Shape::Rect(3, 4));
        assert_eq!(Shape::deserialize(&mut r).unwrap(), Shape::Empty);
    }

    // 10. Nested round-trip
    #[test]
    fn test_nested_round_trip() {
        #[derive(Debug, PartialEq)]
        enum Status {
            Ok,
            Error(u32),
        }

        impl Serialize for Status {
            fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                match self {
                    Status::Ok => w.write_u8(0),
                    Status::Error(code) => {
                        w.write_u8(1)?;
                        w.write_u32(*code)
                    }
                }
            }
        }

        impl<'a> Deserialize<'a> for Status {
            fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
                match r.read_u8()? {
                    0 => Ok(Status::Ok),
                    1 => Ok(Status::Error(r.read_u32()?)),
                    t => Err(WireError::InvalidTag(t)),
                }
            }
        }

        #[derive(Debug, PartialEq)]
        struct Response {
            status: Status,
            count: Option<u16>,
        }

        impl Serialize for Response {
            fn serialize(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
                self.status.serialize(w)?;
                self.count.serialize(w)
            }
        }

        impl<'a> Deserialize<'a> for Response {
            fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
                Ok(Self {
                    status: Status::deserialize(r)?,
                    count: Option::<u16>::deserialize(r)?,
                })
            }
        }

        let resp = Response {
            status: Status::Error(404),
            count: Some(3),
        };

        let mut buf = [0u8; 32];
        let n = to_bytes(&resp, &mut buf).unwrap();
        let resp2: Response = from_bytes(&buf[..n]).unwrap();
        assert_eq!(resp, resp2);

        let resp_none = Response {
            status: Status::Ok,
            count: None,
        };
        let n = to_bytes(&resp_none, &mut buf).unwrap();
        let resp3: Response = from_bytes(&buf[..n]).unwrap();
        assert_eq!(resp_none, resp3);
    }

    // 11. Buffer overflow
    #[test]
    fn test_buffer_overflow() {
        let mut buf = [0u8; 3];
        let mut w = Writer::new(&mut buf);
        w.write_u16(1).unwrap(); // 2 bytes, ok
        assert_eq!(w.write_u16(2), Err(WireError::BufferOverflow)); // 2 more, overflow
    }

    // 12. Buffer underflow
    #[test]
    fn test_buffer_underflow() {
        let buf = [0u8; 1];
        let mut r = Reader::new(&buf);
        r.read_u8().unwrap(); // ok
        assert_eq!(r.read_u8(), Err(WireError::BufferUnderflow));
    }

    // 13. Invalid bool
    #[test]
    fn test_invalid_bool() {
        let buf = [2u8];
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_bool(), Err(WireError::InvalidBool(2)));
    }

    // 14. Invalid enum tag
    #[test]
    fn test_invalid_enum_tag() {
        // Test via Option<u8> which uses 0/1 tags
        let buf = [5u8]; // invalid tag for Option
        let mut r = Reader::new(&buf);
        let result: Result<Option<u8>, _> = Option::<u8>::deserialize(&mut r);
        assert_eq!(result, Err(WireError::InvalidTag(5)));
    }

    // 15. Invalid UTF-8
    #[test]
    fn test_invalid_utf8() {
        // Manually write a "string" with invalid UTF-8
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        // Write length prefix 3, then invalid bytes
        w.write_u16(3).unwrap();
        w.write_u8(0xFF).unwrap();
        w.write_u8(0xFE).unwrap();
        w.write_u8(0xFD).unwrap();

        let mut r = Reader::new(&buf[..5]);
        assert_eq!(r.read_str(), Err(WireError::InvalidUtf8));
    }

    // 16. Exact bytes — verify no padding
    #[test]
    fn test_exact_bytes() {
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);

        w.write_u8(0x42).unwrap();
        w.write_u16(0x1234).unwrap();
        w.write_u32(0xDEADBEEF).unwrap();
        let written = w.position();

        assert_eq!(written, 7);
        // u8: 0x42
        assert_eq!(buf[0], 0x42);
        // u16 LE: 0x1234 -> [0x34, 0x12]
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0x12);
        // u32 LE: 0xDEADBEEF -> [0xEF, 0xBE, 0xAD, 0xDE]
        assert_eq!(buf[3], 0xEF);
        assert_eq!(buf[4], 0xBE);
        assert_eq!(buf[5], 0xAD);
        assert_eq!(buf[6], 0xDE);
    }

    // 17. Zero-copy borrow
    #[test]
    fn test_zero_copy_borrow() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.write_bytes(&[10, 20, 30]).unwrap();
        w.write_str("hi").unwrap();
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        let bytes = r.read_bytes().unwrap();
        let s = r.read_str().unwrap();

        // Verify the returned slices point into the original buffer
        assert_eq!(bytes, &[10, 20, 30]);
        assert_eq!(s, "hi");

        // Verify they're actual borrows from buf (pointer check)
        let buf_range = buf.as_ptr_range();
        assert!(buf_range.contains(&(bytes.as_ptr())));
        assert!(buf_range.contains(&(s.as_ptr())));
    }

    // 18. Convenience functions
    #[test]
    fn test_convenience_functions() {
        let mut buf = [0u8; 16];
        let val: u32 = 0xCAFEBABE;
        let n = to_bytes(&val, &mut buf).unwrap();
        assert_eq!(n, 4);
        let result: u32 = from_bytes(&buf[..n]).unwrap();
        assert_eq!(result, 0xCAFEBABE);
    }

    // 19. Multiple values sequentially
    #[test]
    fn test_multiple_values() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);

        true.serialize(&mut w).unwrap();
        42u16.serialize(&mut w).unwrap();
        (-1i32).serialize(&mut w).unwrap();
        let written = w.position();

        let mut r = Reader::new(&buf[..written]);
        assert_eq!(bool::deserialize(&mut r).unwrap(), true);
        assert_eq!(u16::deserialize(&mut r).unwrap(), 42);
        assert_eq!(i32::deserialize(&mut r).unwrap(), -1);
    }

    // 20. Position tracking
    #[test]
    fn test_position_tracking() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        assert_eq!(w.position(), 0);
        assert_eq!(w.remaining(), 32);

        w.write_u8(1).unwrap();
        assert_eq!(w.position(), 1);
        assert_eq!(w.remaining(), 31);

        w.write_u32(2).unwrap();
        assert_eq!(w.position(), 5);
        assert_eq!(w.remaining(), 27);

        w.write_u64(3).unwrap();
        assert_eq!(w.position(), 13);
        assert_eq!(w.remaining(), 19);

        let mut r = Reader::new(&buf[..13]);
        assert_eq!(r.position(), 0);
        assert_eq!(r.remaining(), 13);

        r.read_u8().unwrap();
        assert_eq!(r.position(), 1);
        assert_eq!(r.remaining(), 12);

        r.read_u32().unwrap();
        assert_eq!(r.position(), 5);
        assert_eq!(r.remaining(), 8);

        r.read_u64().unwrap();
        assert_eq!(r.position(), 13);
        assert_eq!(r.remaining(), 0);
    }

    // --- Tests for new Deserialize impls ---

    // 21. Deserialize &str
    #[test]
    fn test_deserialize_str() {
        let mut buf = [0u8; 64];
        // Serialize via str (unsized), then deserialize back to &str
        let mut w = Writer::new(&mut buf);
        "hello world".serialize(&mut w).unwrap();
        let n = w.position();
        let s: &str = from_bytes(&buf[..n]).unwrap();
        assert_eq!(s, "hello world");
    }

    // 22. Deserialize &[u8]
    #[test]
    fn test_deserialize_bytes() {
        let mut buf = [0u8; 64];
        let data: &[u8] = &[1, 2, 3, 4, 5];
        let mut w = Writer::new(&mut buf);
        data.serialize(&mut w).unwrap();
        let n = w.position();
        let result: &[u8] = from_bytes(&buf[..n]).unwrap();
        assert_eq!(result, &[1, 2, 3, 4, 5]);
    }

    // --- Tests for define_message! macro ---

    // 23. define_message! struct
    #[test]
    fn test_define_message_struct() {
        define_message! {
            pub struct Point { x: u32, y: u32 }
        }

        let p = Point { x: 10, y: 20 };
        let mut buf = [0u8; 32];
        let n = to_bytes(&p, &mut buf).unwrap();
        assert_eq!(n, 8); // 4 + 4

        let p2: Point = from_bytes(&buf[..n]).unwrap();
        assert_eq!(p2.x, 10);
        assert_eq!(p2.y, 20);
    }

    // 24. define_message! enum with multiple variants
    #[test]
    fn test_define_message_enum() {
        define_message! {
            pub enum Shape {
                Circle(0) { radius: u32 },
                Rect(1) { w: u32, h: u32 },
            }
        }

        let circle = Shape::Circle { radius: 5 };
        let mut buf = [0u8; 32];
        let n = to_bytes(&circle, &mut buf).unwrap();
        assert_eq!(n, 5); // 1 tag + 4

        let s: Shape = from_bytes(&buf[..n]).unwrap();
        match s {
            Shape::Circle { radius } => assert_eq!(radius, 5),
            _ => panic!("wrong variant"),
        }

        let rect = Shape::Rect { w: 3, h: 4 };
        let n = to_bytes(&rect, &mut buf).unwrap();
        let s: Shape = from_bytes(&buf[..n]).unwrap();
        match s {
            Shape::Rect { w, h } => { assert_eq!(w, 3); assert_eq!(h, 4); }
            _ => panic!("wrong variant"),
        }
    }

    // 25. define_message! unit variant (empty fields)
    #[test]
    fn test_define_message_unit_variant() {
        define_message! {
            pub enum Status {
                Ok(0) {},
                Error(1) { code: u32 },
            }
        }

        let ok = Status::Ok {};
        let mut buf = [0u8; 32];
        let n = to_bytes(&ok, &mut buf).unwrap();
        assert_eq!(n, 1); // just the tag

        let s: Status = from_bytes(&buf[..n]).unwrap();
        match s {
            Status::Ok {} => {}
            _ => panic!("wrong variant"),
        }

        let err = Status::Error { code: 404 };
        let n = to_bytes(&err, &mut buf).unwrap();
        let s: Status = from_bytes(&buf[..n]).unwrap();
        match s {
            Status::Error { code } => assert_eq!(code, 404),
            _ => panic!("wrong variant"),
        }
    }

    // 26. define_message! with borrowed fields
    #[test]
    fn test_define_message_borrowed() {
        define_message! {
            pub enum Cmd<'a> {
                Open(0) { flags: u8, path: &'a str },
                Data(1) { chunk: &'a [u8] },
            }
        }

        let open = Cmd::Open { flags: 3, path: "/foo" };
        let mut buf = [0u8; 64];
        let n = to_bytes(&open, &mut buf).unwrap();
        // 1 tag + 1 flags + 2 len + 4 path = 8
        assert_eq!(n, 8);

        let cmd: Cmd = from_bytes(&buf[..n]).unwrap();
        match cmd {
            Cmd::Open { flags, path } => {
                assert_eq!(flags, 3);
                assert_eq!(path, "/foo");
            }
            _ => panic!("wrong variant"),
        }

        let data = Cmd::Data { chunk: &[10, 20, 30] };
        let n = to_bytes(&data, &mut buf).unwrap();
        let cmd: Cmd = from_bytes(&buf[..n]).unwrap();
        match cmd {
            Cmd::Data { chunk } => assert_eq!(chunk, &[10, 20, 30]),
            _ => panic!("wrong variant"),
        }
    }

    // 27. define_message! invalid tag returns error
    #[test]
    fn test_define_message_invalid_tag() {
        define_message! {
            pub enum Op {
                Add(0) { a: u32, b: u32 },
            }
        }

        let buf = [99u8]; // invalid tag
        let result: Result<Op, _> = from_bytes(&buf);
        assert_eq!(result, Err(WireError::InvalidTag(99)));
    }

    // --- Tests for RPC helpers ---

    // 28. MockTransport + rpc_call roundtrip
    #[test]
    fn test_rpc_roundtrip() {
        define_message! {
            pub enum MathReq {
                Add(0) { a: u32, b: u32 },
            }
        }

        define_message! {
            pub struct MathResp { answer: u32 }
        }

        // MockTransport stores sent data and returns pre-loaded response
        struct MockTransport {
            sent_buf: [u8; MAX_MSG_SIZE],
            sent_len: usize,
            sent_cap: usize,
            recv_buf: [u8; MAX_MSG_SIZE],
            recv_len: usize,
            recv_cap: usize,
        }

        impl Transport for MockTransport {
            fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError> {
                self.sent_buf[..data.len()].copy_from_slice(data);
                self.sent_len = data.len();
                self.sent_cap = cap;
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.recv_len].copy_from_slice(&self.recv_buf[..self.recv_len]);
                Ok((self.recv_len, self.recv_cap))
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    sent_buf: [0u8; MAX_MSG_SIZE],
                    sent_len: 0,
                    sent_cap: 0,
                    recv_buf: [0u8; MAX_MSG_SIZE],
                    recv_len: 0,
                    recv_cap: NO_CAP,
                }
            }
        }

        // Pre-compute the response bytes
        let resp = MathResp { answer: 42 };
        let mut recv_buf = [0u8; MAX_MSG_SIZE];
        let resp_len = to_bytes(&resp, &mut recv_buf).unwrap();

        let mut transport = MockTransport {
            sent_buf: [0u8; MAX_MSG_SIZE],
            sent_len: 0,
            sent_cap: 0,
            recv_buf,
            recv_len: resp_len,
            recv_cap: NO_CAP,
        };

        let req = MathReq::Add { a: 3, b: 4 };
        let mut buf = [0u8; MAX_MSG_SIZE];
        let result: MathResp = rpc_call(&mut transport, &req, &mut buf).unwrap();
        assert_eq!(result.answer, 42);

        // Verify the request was serialized correctly
        let sent_req: MathReq = from_bytes(&transport.sent_buf[..transport.sent_len]).unwrap();
        match sent_req {
            MathReq::Add { a, b } => { assert_eq!(a, 3); assert_eq!(b, 4); }
            _ => panic!("wrong variant sent"),
        }
    }

    // 29. RPC with capability passthrough
    #[test]
    fn test_rpc_with_cap() {
        define_message! {
            pub struct Ping { val: u32 }
        }
        define_message! {
            pub struct Pong { val: u32 }
        }

        struct CapTransport {
            recv_buf: [u8; 32],
            recv_len: usize,
            recv_cap: usize,
            last_cap: usize,
        }

        impl Transport for CapTransport {
            fn send(&mut self, _data: &[u8], cap: usize) -> Result<(), RpcError> {
                self.last_cap = cap;
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.recv_len].copy_from_slice(&self.recv_buf[..self.recv_len]);
                Ok((self.recv_len, self.recv_cap))
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    recv_buf: [0u8; 32],
                    recv_len: 0,
                    recv_cap: NO_CAP,
                    last_cap: 0,
                }
            }
        }

        let mut recv_buf = [0u8; 32];
        let resp = Pong { val: 99 };
        let resp_len = to_bytes(&resp, &mut recv_buf).unwrap();

        let mut transport = CapTransport {
            recv_buf,
            recv_len: resp_len,
            recv_cap: 42,
            last_cap: 0,
        };

        let req = Ping { val: 1 };
        let mut buf = [0u8; MAX_MSG_SIZE];
        let (result, cap): (Pong, usize) =
            rpc_call_with_cap(&mut transport, &req, 7, &mut buf).unwrap();

        assert_eq!(result.val, 99);
        assert_eq!(cap, 42);         // received cap
        assert_eq!(transport.last_cap, 7); // sent cap
    }

    // 30. rpc_recv + rpc_reply server-side roundtrip
    #[test]
    fn test_rpc_recv_reply() {
        define_message! {
            pub struct Req { x: u32 }
        }
        define_message! {
            pub struct Resp { y: u32 }
        }

        struct BufTransport {
            data: [u8; MAX_MSG_SIZE],
            len: usize,
            cap: usize,
        }

        impl Transport for BufTransport {
            fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError> {
                self.data[..data.len()].copy_from_slice(data);
                self.len = data.len();
                self.cap = cap;
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.len].copy_from_slice(&self.data[..self.len]);
                Ok((self.len, self.cap))
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    data: [0u8; MAX_MSG_SIZE],
                    len: 0,
                    cap: NO_CAP,
                }
            }
        }

        // Simulate client sending a request
        let req = Req { x: 10 };
        let mut data = [0u8; MAX_MSG_SIZE];
        let req_len = to_bytes(&req, &mut data).unwrap();

        let mut transport = BufTransport {
            data,
            len: req_len,
            cap: NO_CAP,
        };

        // Server receives
        let mut buf = [0u8; MAX_MSG_SIZE];
        let (received, _cap): (Req, _) = rpc_recv(&mut transport, &mut buf).unwrap();
        assert_eq!(received.x, 10);

        // Server replies
        let resp = Resp { y: 20 };
        rpc_reply(&mut transport, &resp, NO_CAP).unwrap();

        // Verify reply was stored
        let reply: Resp = from_bytes(&transport.data[..transport.len]).unwrap();
        assert_eq!(reply.y, 20);
    }

    // --- Tests for define_protocol! macro ---

    // 31. define_protocol! client sends correct request
    #[test]
    fn test_define_protocol_client() {
        define_message! {
            pub enum CalcReq {
                Add(0) { a: u32, b: u32 },
                Neg(1) { a: u32 },
            }
        }

        define_message! {
            pub struct CalcResp { result: u32 }
        }

        // MockTransport captures sent request and returns pre-loaded response
        struct MockTransport {
            sent_buf: [u8; MAX_MSG_SIZE],
            sent_len: usize,
            recv_buf: [u8; MAX_MSG_SIZE],
            recv_len: usize,
        }

        impl Transport for MockTransport {
            fn send(&mut self, data: &[u8], _cap: usize) -> Result<(), RpcError> {
                self.sent_buf[..data.len()].copy_from_slice(data);
                self.sent_len = data.len();
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.recv_len].copy_from_slice(&self.recv_buf[..self.recv_len]);
                Ok((self.recv_len, NO_CAP))
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    sent_buf: [0u8; MAX_MSG_SIZE],
                    sent_len: 0,
                    recv_buf: [0u8; MAX_MSG_SIZE],
                    recv_len: 0,
                }
            }
        }

        define_protocol! {
            pub protocol Calc => CalcClient, CalcHandler, calc_dispatch {
                type Request = CalcReq;
                type Response = CalcResp;

                rpc add as Add(a: u32, b: u32) -> CalcResp;
                rpc neg as Neg(a: u32) -> CalcResp;
            }
        }

        // Pre-load a response
        let resp = CalcResp { result: 7 };
        let mut recv_buf = [0u8; MAX_MSG_SIZE];
        let recv_len = to_bytes(&resp, &mut recv_buf).unwrap();

        let transport = MockTransport {
            sent_buf: [0u8; MAX_MSG_SIZE],
            sent_len: 0,
            recv_buf,
            recv_len,
        };

        let mut client = CalcClient::new(transport);
        let result = client.add(3, 4).unwrap();
        assert_eq!(result.result, 7);

        // Verify the request was serialized correctly
        let sent_req: CalcReq = from_bytes(
            &client.transport.sent_buf[..client.transport.sent_len]
        ).unwrap();
        match sent_req {
            CalcReq::Add { a, b } => { assert_eq!(a, 3); assert_eq!(b, 4); }
            _ => panic!("wrong variant sent"),
        }
    }

    // 32. define_protocol! handler dispatch roundtrip
    #[test]
    fn test_define_protocol_handler_dispatch() {
        define_message! {
            pub enum OpReq {
                Double(0) { val: u32 },
                Inc(1) { val: u32 },
            }
        }

        define_message! {
            pub struct OpResp { out: u32 }
        }

        define_protocol! {
            pub protocol Op => OpClient, OpHandler, op_dispatch {
                type Request = OpReq;
                type Response = OpResp;

                rpc double as Double(val: u32) -> OpResp;
                rpc inc as Inc(val: u32) -> OpResp;
            }
        }

        struct OpImpl;
        impl OpHandler for OpImpl {
            fn double(&mut self, val: u32) -> (OpResp, usize) {
                (OpResp { out: val * 2 }, NO_CAP)
            }
            fn inc(&mut self, val: u32) -> (OpResp, usize) {
                (OpResp { out: val + 1 }, NO_CAP)
            }
        }

        // Loopback transport: recv returns request, send captures response
        struct LoopbackTransport {
            req_buf: [u8; MAX_MSG_SIZE],
            req_len: usize,
            resp_buf: [u8; MAX_MSG_SIZE],
            resp_len: usize,
            resp_cap: usize,
        }

        impl Transport for LoopbackTransport {
            fn send(&mut self, data: &[u8], cap: usize) -> Result<(), RpcError> {
                self.resp_buf[..data.len()].copy_from_slice(data);
                self.resp_len = data.len();
                self.resp_cap = cap;
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.req_len].copy_from_slice(&self.req_buf[..self.req_len]);
                Ok((self.req_len, NO_CAP))
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    req_buf: [0u8; MAX_MSG_SIZE],
                    req_len: 0,
                    resp_buf: [0u8; MAX_MSG_SIZE],
                    resp_len: 0,
                    resp_cap: 0,
                }
            }
        }

        // Serialize a request
        let req = OpReq::Double { val: 21 };
        let mut req_buf = [0u8; MAX_MSG_SIZE];
        let req_len = to_bytes(&req, &mut req_buf).unwrap();

        let mut transport = LoopbackTransport {
            req_buf,
            req_len,
            resp_buf: [0u8; MAX_MSG_SIZE],
            resp_len: 0,
            resp_cap: 0,
        };

        let mut handler = OpImpl;
        op_dispatch(&mut transport, &mut handler).unwrap();

        // Verify the response
        let resp: OpResp = from_bytes(&transport.resp_buf[..transport.resp_len]).unwrap();
        assert_eq!(resp.out, 42);
        assert_eq!(transport.resp_cap, NO_CAP);
    }

    // 33. define_protocol! with [+cap] annotation
    #[test]
    fn test_define_protocol_cap() {
        define_message! {
            pub enum FileReq {
                Open(0) { flags: u8 },
            }
        }

        define_message! {
            pub struct FileResp { ok: u8 }
        }

        define_protocol! {
            pub protocol File => FileClient, FileHandler, file_dispatch {
                type Request = FileReq;
                type Response = FileResp;

                rpc open as Open(flags: u8) -> FileResp [+cap];
            }
        }

        // MockTransport returns response with a capability
        struct MockTransport {
            recv_buf: [u8; MAX_MSG_SIZE],
            recv_len: usize,
        }

        impl Transport for MockTransport {
            fn send(&mut self, _data: &[u8], _cap: usize) -> Result<(), RpcError> {
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.recv_len].copy_from_slice(&self.recv_buf[..self.recv_len]);
                Ok((self.recv_len, 42)) // cap = 42
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    recv_buf: [0u8; MAX_MSG_SIZE],
                    recv_len: 0,
                }
            }
        }

        let resp = FileResp { ok: 1 };
        let mut recv_buf = [0u8; MAX_MSG_SIZE];
        let recv_len = to_bytes(&resp, &mut recv_buf).unwrap();

        let transport = MockTransport { recv_buf, recv_len };
        let mut client = FileClient::new(transport);

        // [+cap] method returns (Response, cap)
        let (result, cap) = client.open(0x01).unwrap();
        assert_eq!(result.ok, 1);
        assert_eq!(cap, 42);
    }

    // 34. define_protocol! with [-> ChildClient] typed capability
    #[test]
    fn test_define_protocol_typed_cap() {
        define_message! {
            pub enum ParentReq {
                Connect(0) { name: u8 },
            }
        }

        define_message! {
            pub struct ParentResp { ok: u8 }
        }

        define_message! {
            pub enum ChildReq {
                Ping(0) { val: u32 },
            }
        }

        define_message! {
            pub struct ChildResp { val: u32 }
        }

        // Child protocol (defined first so ChildClient exists)
        define_protocol! {
            pub protocol Child => ChildClient, ChildHandler, child_dispatch {
                type Request = ChildReq;
                type Response = ChildResp;

                rpc ping as Ping(val: u32) -> ChildResp;
            }
        }

        // MockTransport that tracks from_cap calls
        struct MockTransport {
            handle: usize,
            recv_buf: [u8; MAX_MSG_SIZE],
            recv_len: usize,
            recv_cap: usize,
        }

        impl Transport for MockTransport {
            fn send(&mut self, _data: &[u8], _cap: usize) -> Result<(), RpcError> {
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.recv_len].copy_from_slice(&self.recv_buf[..self.recv_len]);
                Ok((self.recv_len, self.recv_cap))
            }
            fn from_cap(&self, cap: usize) -> Self {
                Self {
                    handle: cap,
                    recv_buf: [0u8; MAX_MSG_SIZE],
                    recv_len: 0,
                    recv_cap: NO_CAP,
                }
            }
        }

        // Parent protocol uses [-> ChildClient]
        define_protocol! {
            pub protocol Parent => ParentClient, ParentHandler, parent_dispatch {
                type Request = ParentReq;
                type Response = ParentResp;

                rpc connect as Connect(name: u8) -> ParentResp [-> ChildClient];
            }
        }

        let resp = ParentResp { ok: 1 };
        let mut recv_buf = [0u8; MAX_MSG_SIZE];
        let recv_len = to_bytes(&resp, &mut recv_buf).unwrap();

        let transport = MockTransport {
            handle: 0,
            recv_buf,
            recv_len,
            recv_cap: 99, // the child cap
        };

        let mut client = ParentClient::new(transport);
        let (result, child) = client.connect(5).unwrap();
        assert_eq!(result.ok, 1);
        // Verify the child was created via from_cap with cap=99
        assert_eq!(child.transport.handle, 99);
    }

    // 35. define_protocol! with [-> shm] shared memory handle
    #[test]
    fn test_define_protocol_shm() {
        define_message! {
            pub enum BufReq {
                Create(0) { size: u32 },
            }
        }

        define_message! {
            pub struct BufResp { ok: u8 }
        }

        struct MockTransport {
            recv_buf: [u8; MAX_MSG_SIZE],
            recv_len: usize,
            recv_cap: usize,
        }

        impl Transport for MockTransport {
            fn send(&mut self, _data: &[u8], _cap: usize) -> Result<(), RpcError> {
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, usize), RpcError> {
                buf[..self.recv_len].copy_from_slice(&self.recv_buf[..self.recv_len]);
                Ok((self.recv_len, self.recv_cap))
            }
            fn from_cap(&self, _cap: usize) -> Self {
                Self {
                    recv_buf: [0u8; MAX_MSG_SIZE],
                    recv_len: 0,
                    recv_cap: NO_CAP,
                }
            }
        }

        define_protocol! {
            pub protocol Buf => BufClient, BufHandler, buf_dispatch {
                type Request = BufReq;
                type Response = BufResp;

                rpc create as Create(size: u32) -> BufResp [-> shm];
            }
        }

        let resp = BufResp { ok: 1 };
        let mut recv_buf = [0u8; MAX_MSG_SIZE];
        let recv_len = to_bytes(&resp, &mut recv_buf).unwrap();

        let transport = MockTransport {
            recv_buf,
            recv_len,
            recv_cap: 77,
        };

        let mut client = BufClient::new(transport);
        let (result, shm) = client.create(4096).unwrap();
        assert_eq!(result.ok, 1);
        assert_eq!(shm, ShmHandle(77));
    }
}
