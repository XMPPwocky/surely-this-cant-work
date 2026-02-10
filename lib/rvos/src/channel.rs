//! RAII channel handles — both raw (untyped) and typed.

use core::marker::PhantomData;

use crate::error::{SysError, SysResult};
use crate::message::Message;
use crate::raw;

// ---------------------------------------------------------------------------
// RawChannel — untyped byte-level IPC
// ---------------------------------------------------------------------------

/// Low-level untyped IPC channel handle. Closes the handle on drop.
///
/// Prefer `Channel<S, R>` for type-safe, serialization-aware IPC.
/// Use `RawChannel` only when you need to operate at the raw `Message` level
/// (e.g. multiplexing heterogeneous protocols on a single endpoint).
pub struct RawChannel {
    handle: usize,
}

impl RawChannel {
    /// Create a new bidirectional channel pair.
    pub fn create_pair() -> SysResult<(RawChannel, RawChannel)> {
        let (a, b) = raw::sys_chan_create();
        if a == usize::MAX {
            return Err(SysError::NoResources);
        }
        Ok((RawChannel { handle: a }, RawChannel { handle: b }))
    }

    /// Wrap a raw handle into a RawChannel (takes ownership).
    pub fn from_raw_handle(handle: usize) -> Self {
        RawChannel { handle }
    }

    /// Get the raw handle value.
    pub fn raw_handle(&self) -> usize {
        self.handle
    }

    /// Consume the RawChannel without closing the handle.
    pub fn into_raw_handle(self) -> usize {
        let h = self.handle;
        core::mem::forget(self);
        h
    }

    /// Send a message on this channel (blocking).
    pub fn send(&self, msg: &Message) -> SysResult<()> {
        let ret = raw::sys_chan_send_blocking(self.handle, msg);
        SysError::from_code(ret)
    }

    /// Blocking receive on this channel.
    pub fn recv_blocking(&self, msg: &mut Message) -> SysResult<()> {
        let ret = raw::sys_chan_recv_blocking(self.handle, msg);
        SysError::from_code(ret)
    }

    /// Non-blocking receive. Returns 0 on success, nonzero on empty/error.
    pub fn try_recv(&self, msg: &mut Message) -> usize {
        raw::sys_chan_recv(self.handle, msg)
    }

    /// Register this channel for poll-based wakeup.
    pub fn poll_add(&self) {
        raw::sys_chan_poll_add(self.handle);
    }
}

impl Drop for RawChannel {
    fn drop(&mut self) {
        raw::syscall1(raw::SYS_CHAN_CLOSE, self.handle);
    }
}

// ---------------------------------------------------------------------------
// Channel<S, R> — typed, serialization-aware IPC
// ---------------------------------------------------------------------------

/// A typed IPC channel that sends messages of type `S` and receives type `R`.
///
/// Both endpoints of a channel pair carry inverse type parameters:
/// if one side is `Channel<A, B>`, the other is `Channel<B, A>`.
///
/// Use `channel_pair::<A, B>()` to create a matched pair.
pub struct Channel<S, R> {
    inner: RawChannel,
    _phantom: PhantomData<fn(S) -> R>,
}

impl<S, R> Channel<S, R> {
    /// Wrap a raw handle into a typed channel (takes ownership).
    pub fn from_raw_handle(handle: usize) -> Self {
        Channel { inner: RawChannel::from_raw_handle(handle), _phantom: PhantomData }
    }

    /// Get the raw handle value.
    pub fn raw_handle(&self) -> usize {
        self.inner.raw_handle()
    }

    /// Consume the channel without closing the handle.
    pub fn into_raw_handle(self) -> usize {
        self.inner.into_raw_handle()
    }

    /// Access the underlying `RawChannel`.
    pub fn as_raw(&self) -> &RawChannel {
        &self.inner
    }

    /// Register this channel for poll-based wakeup.
    pub fn poll_add(&self) {
        self.inner.poll_add();
    }
}

impl<S: rvos_wire::Serialize, R> Channel<S, R> {
    /// Send a typed message (blocking).
    pub fn send(&self, val: &S) -> SysResult<()> {
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(val, &mut msg.data)
            .map_err(|_| SysError::BadAddress)?;
        self.inner.send(&msg)
    }

    /// Send a typed message with a capability handle attached (blocking).
    pub fn send_with_cap(&self, val: &S, cap: usize) -> SysResult<()> {
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(val, &mut msg.data)
            .map_err(|_| SysError::BadAddress)?;
        msg.set_cap(cap);
        self.inner.send(&msg)
    }
}

impl<S, R: rvos_wire::DeserializeOwned> Channel<S, R> {
    /// Blocking receive, returning the deserialized value.
    pub fn recv_blocking(&self) -> SysResult<R> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        rvos_wire::from_bytes::<R>(&msg.data[..msg.len])
            .map_err(|_| SysError::BadAddress)
    }

    /// Blocking receive, returning the deserialized value and first capability.
    pub fn recv_with_cap_blocking(&self) -> SysResult<(R, usize)> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        let val = rvos_wire::from_bytes::<R>(&msg.data[..msg.len])
            .map_err(|_| SysError::BadAddress)?;
        Ok((val, msg.cap()))
    }

    /// Blocking receive, returning the deserialized value and all capabilities.
    pub fn recv_with_caps_blocking(&self) -> SysResult<(R, [usize; crate::message::MAX_CAPS], usize)> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        let val = rvos_wire::from_bytes::<R>(&msg.data[..msg.len])
            .map_err(|_| SysError::BadAddress)?;
        Ok((val, msg.caps, msg.cap_count))
    }

    /// Non-blocking receive. Returns `None` if no message is available.
    pub fn try_recv(&self) -> Option<R> {
        let mut msg = Message::new();
        if self.inner.try_recv(&mut msg) != 0 { return None; }
        rvos_wire::from_bytes::<R>(&msg.data[..msg.len]).ok()
    }

    /// Non-blocking receive with capability. Returns `None` if no message is available.
    pub fn try_recv_with_cap(&self) -> Option<(R, usize)> {
        let mut msg = Message::new();
        if self.inner.try_recv(&mut msg) != 0 { return None; }
        let val = rvos_wire::from_bytes::<R>(&msg.data[..msg.len]).ok()?;
        Some((val, msg.cap()))
    }
}

/// Create a bidirectional typed channel pair.
///
/// Returns `(Channel<A, B>, Channel<B, A>)` — side A sends `A` and
/// receives `B`; side B sends `B` and receives `A`.
pub fn channel_pair<A, B>() -> SysResult<(Channel<A, B>, Channel<B, A>)> {
    let (a, b) = RawChannel::create_pair()?;
    Ok((
        Channel { inner: a, _phantom: PhantomData },
        Channel { inner: b, _phantom: PhantomData },
    ))
}
