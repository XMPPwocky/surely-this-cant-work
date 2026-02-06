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
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError>;
}

/// Deserialize a value from a Reader.
pub trait Deserialize<'a>: Sized {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError>;
}

// ---------------------------------------------------------------------------
// Blanket impls: primitives
// ---------------------------------------------------------------------------

impl Serialize for bool {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_bool(*self)
    }
}
impl<'a> Deserialize<'a> for bool {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_bool()
    }
}

impl Serialize for u8 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_u8(*self)
    }
}
impl<'a> Deserialize<'a> for u8 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u8()
    }
}

impl Serialize for u16 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_u16(*self)
    }
}
impl<'a> Deserialize<'a> for u16 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u16()
    }
}

impl Serialize for u32 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_u32(*self)
    }
}
impl<'a> Deserialize<'a> for u32 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u32()
    }
}

impl Serialize for u64 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_u64(*self)
    }
}
impl<'a> Deserialize<'a> for u64 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_u64()
    }
}

impl Serialize for i8 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_i8(*self)
    }
}
impl<'a> Deserialize<'a> for i8 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i8()
    }
}

impl Serialize for i16 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_i16(*self)
    }
}
impl<'a> Deserialize<'a> for i16 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i16()
    }
}

impl Serialize for i32 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_i32(*self)
    }
}
impl<'a> Deserialize<'a> for i32 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i32()
    }
}

impl Serialize for i64 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_i64(*self)
    }
}
impl<'a> Deserialize<'a> for i64 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_i64()
    }
}

impl Serialize for usize {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_usize(*self)
    }
}
impl<'a> Deserialize<'a> for usize {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_usize()
    }
}

impl Serialize for isize {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_isize(*self)
    }
}
impl<'a> Deserialize<'a> for isize {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_isize()
    }
}

impl Serialize for f32 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_f32(*self)
    }
}
impl<'a> Deserialize<'a> for f32 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_f32()
    }
}

impl Serialize for f64 {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_f64(*self)
    }
}
impl<'a> Deserialize<'a> for f64 {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        r.read_f64()
    }
}

// &[u8] and &str: Serialize only (deserialization returns borrows via Reader methods)
impl Serialize for [u8] {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_bytes(self)
    }
}

impl Serialize for str {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_str(self)
    }
}

// Option<T>
impl<T: Serialize> Serialize for Option<T> {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
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
            fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
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
            fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
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
            fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
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
            fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
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
}
