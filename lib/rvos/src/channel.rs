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

    /// Create a Channel from a received [`ChannelCap`](rvos_wire::ChannelCap)
    /// (takes RAII ownership of the handle).
    pub fn from_cap(cap: rvos_wire::ChannelCap<S, R>) -> Self {
        Channel::from_raw_handle(cap.raw())
    }

    /// Create a [`ChannelCap`](rvos_wire::ChannelCap) wire representation
    /// from this Channel.
    ///
    /// Does NOT consume the Channel — the caller is responsible for ensuring
    /// the handle remains valid for the message recipient (typically by
    /// sending it immediately and not closing this Channel until the
    /// recipient has received it).
    pub fn as_cap(&self) -> rvos_wire::ChannelCap<S, R> {
        rvos_wire::ChannelCap::new(self.raw_handle())
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
    ///
    /// Any [`ChannelCap`](rvos_wire::ChannelCap) fields in `val` are
    /// automatically transferred via the message's capability sideband.
    pub fn send(&self, val: &S) -> SysResult<()> {
        let mut msg = Message::new();
        let (data_len, cap_count) =
            rvos_wire::to_bytes_with_caps(val, &mut msg.data, &mut msg.caps)
                .map_err(|_| SysError::BadAddress)?;
        msg.len = data_len;
        msg.cap_count = cap_count;
        self.inner.send(&msg)
    }

    /// Send a typed message with an explicit capability handle attached
    /// (blocking).
    ///
    /// The explicit `cap` is appended after any caps embedded in `val`.
    /// Prefer embedding [`ChannelCap`](rvos_wire::ChannelCap) fields in the
    /// message type instead.
    pub fn send_with_cap(&self, val: &S, cap: usize) -> SysResult<()> {
        let mut msg = Message::new();
        let (data_len, cap_count) =
            rvos_wire::to_bytes_with_caps(val, &mut msg.data, &mut msg.caps)
                .map_err(|_| SysError::BadAddress)?;
        msg.len = data_len;
        msg.cap_count = cap_count;
        if cap_count < crate::message::MAX_CAPS {
            msg.caps[cap_count] = cap;
            msg.cap_count = cap_count + 1;
        }
        self.inner.send(&msg)
    }
}

impl<S, R: rvos_wire::DeserializeOwned> Channel<S, R> {
    /// Blocking receive, returning the deserialized value.
    ///
    /// Any [`ChannelCap`](rvos_wire::ChannelCap) fields in the result are
    /// populated from the message's capability sideband.
    pub fn recv_blocking(&self) -> SysResult<R> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        rvos_wire::from_bytes_with_caps::<R>(&msg.data[..msg.len], &msg.caps[..msg.cap_count])
            .map_err(|_| SysError::BadAddress)
    }

    /// Blocking receive, returning the deserialized value and the last
    /// explicit capability (after any caps consumed by [`ChannelCap`] fields).
    pub fn recv_with_cap_blocking(&self) -> SysResult<(R, usize)> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        let val = rvos_wire::from_bytes_with_caps::<R>(
            &msg.data[..msg.len], &msg.caps[..msg.cap_count])
            .map_err(|_| SysError::BadAddress)?;
        let cap = if msg.cap_count > 0 { msg.caps[msg.cap_count - 1] } else { crate::raw::NO_CAP };
        Ok((val, cap))
    }

    /// Blocking receive, returning the deserialized value and all capabilities.
    pub fn recv_with_caps_blocking(&self) -> SysResult<(R, [usize; crate::message::MAX_CAPS], usize)> {
        let mut msg = Message::new();
        self.inner.recv_blocking(&mut msg)?;
        let val = rvos_wire::from_bytes_with_caps::<R>(
            &msg.data[..msg.len], &msg.caps[..msg.cap_count])
            .map_err(|_| SysError::BadAddress)?;
        Ok((val, msg.caps, msg.cap_count))
    }

    /// Non-blocking receive. Returns `None` if no message is available.
    pub fn try_recv(&self) -> Option<R> {
        let mut msg = Message::new();
        if self.inner.try_recv(&mut msg) != 0 { return None; }
        rvos_wire::from_bytes_with_caps::<R>(&msg.data[..msg.len], &msg.caps[..msg.cap_count]).ok()
    }

    /// Non-blocking receive with capability. Returns `None` if no message is available.
    pub fn try_recv_with_cap(&self) -> Option<(R, usize)> {
        let mut msg = Message::new();
        if self.inner.try_recv(&mut msg) != 0 { return None; }
        let val = rvos_wire::from_bytes_with_caps::<R>(
            &msg.data[..msg.len], &msg.caps[..msg.cap_count]).ok()?;
        let cap = if msg.cap_count > 0 { msg.caps[msg.cap_count - 1] } else { crate::raw::NO_CAP };
        Some((val, cap))
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
