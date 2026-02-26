//! RAII channel handles — both raw (untyped) and typed.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::error::{RecvError, SysError, SysResult};
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
    #[must_use]
    pub fn try_recv(&self, msg: &mut Message) -> usize {
        raw::sys_chan_recv(self.handle, msg)
    }

    /// Non-blocking send. Returns 0 on success, nonzero on full/error.
    pub fn try_send(&self, msg: &Message) -> SysResult<()> {
        let ret = raw::sys_chan_send(self.handle, msg);
        SysError::from_code(ret)
    }

    /// Non-blocking receive with three-way status.
    ///
    /// On `Ok(())`, the message has been written to `msg`.
    /// On `Err(RecvError::Empty)`, no message was available.
    /// On `Err(RecvError::Closed)`, the peer closed the channel.
    pub fn try_recv_status(&self, msg: &mut Message) -> Result<(), RecvError> {
        match raw::sys_chan_recv(self.handle, msg) {
            0 => Ok(()),
            2 => Err(RecvError::Closed),
            _ => Err(RecvError::Empty),
        }
    }

    /// Register this channel for poll-based wakeup.
    pub fn poll_add(&self) {
        raw::sys_chan_poll_add(self.handle);
    }

    /// Receive a stream of messages, calling `f` for each non-sentinel message.
    ///
    /// Blocks until a zero-length sentinel message arrives or the channel closes.
    /// Used for streaming responses (e.g. sysinfo commands that send data in chunks).
    pub fn recv_stream_raw(&self, mut f: impl FnMut(&Message)) {
        let mut msg = Message::new();
        loop {
            let ret = raw::sys_chan_recv_blocking(self.handle, &mut msg);
            if ret != 0 || msg.len == 0 {
                break;
            }
            f(&msg);
        }
    }

    /// Receive a stream of messages and collect all data bytes into a Vec.
    ///
    /// Blocks until a zero-length sentinel arrives. Returns the concatenated
    /// data from all chunks.
    pub fn recv_stream_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.recv_stream_raw(|msg| {
            out.extend_from_slice(&msg.data[..msg.len]);
        });
        out
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
/// `S` and `R` implement [`MessageType`](rvos_wire::MessageType), which maps
/// a borrow lifetime to the concrete message type via a GAT.  For owned
/// types (e.g. `FsResponse`), the type itself serves as the `MessageType`
/// through a blanket impl.  For borrowed types (e.g. `FsRequest<'a>`),
/// `define_message!` generates a zero-sized companion (e.g. `FsRequestMsg`).
///
/// The channel embeds an internal receive buffer.  The `try_recv` and
/// `recv_blocking` methods deserialize into `R::Msg<'a>` where `'a` is
/// borrowed from `&'a mut self`, so the returned value can reference
/// zero-copy data (like `&str` path fields) directly from the buffer.
/// The `&mut self` borrow naturally prevents a second recv until the
/// caller is done with the previous message.
///
/// Both endpoints of a channel pair carry inverse type parameters:
/// if one side is `Channel<A, B>`, the other is `Channel<B, A>`.
///
/// Use `channel_pair::<A, B>()` to create a matched pair.
pub struct Channel<S, R> {
    inner: RawChannel,
    recv_buf: Box<Message>,
    _phantom: PhantomData<(S, R)>,
}

impl<S, R> Channel<S, R> {
    /// Wrap a raw handle into a typed channel (takes ownership).
    pub fn from_raw_handle(handle: usize) -> Self {
        Channel {
            inner: RawChannel::from_raw_handle(handle),
            recv_buf: Message::boxed(),
            _phantom: PhantomData,
        }
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

// ---------------------------------------------------------------------------
// Send — requires S: MessageType (GAT-based)
// ---------------------------------------------------------------------------
//
// These methods use the `MessageType` GAT so that `Channel<FileResponseMsg, _>`
// can call `send(&FileResponse<'a> { .. })` — the borrowed message type is
// resolved via `S::Msg<'_>`.  For owned types (e.g. `Channel<FsResponse, _>`),
// the blanket impl maps `FsResponse::Msg<'a> = FsResponse`, so the call-site
// signature is unchanged: `send(&FsResponse { .. })`.

impl<S: rvos_wire::MessageType, R> Channel<S, R> {
    /// Send a typed message (blocking).
    ///
    /// Any [`ChannelCap`](rvos_wire::ChannelCap) fields in `val` are
    /// automatically transferred via the message's capability sideband.
    pub fn send(&self, val: &S::Msg<'_>) -> SysResult<()> {
        let mut msg = Message::boxed();
        let (data_len, cap_count) =
            rvos_wire::to_bytes_with_caps(val, &mut msg.data, &mut msg.caps)
                .map_err(|_| SysError::BadAddress)?;
        msg.len = data_len;
        msg.cap_count = cap_count;
        self.inner.send(&msg)
    }

    /// Non-blocking send. Returns `Err` if channel is full or closed.
    ///
    /// Any [`ChannelCap`](rvos_wire::ChannelCap) fields in `val` are
    /// automatically transferred via the message's capability sideband.
    pub fn try_send(&self, val: &S::Msg<'_>) -> SysResult<()> {
        let mut msg = Message::boxed();
        let (data_len, cap_count) =
            rvos_wire::to_bytes_with_caps(val, &mut msg.data, &mut msg.caps)
                .map_err(|_| SysError::BadAddress)?;
        msg.len = data_len;
        msg.cap_count = cap_count;
        self.inner.try_send(&msg)
    }

    /// Send a typed message with an explicit capability handle attached
    /// (blocking).
    ///
    /// The explicit `cap` is appended after any caps embedded in `val`.
    ///
    /// **Deprecated:** Embed [`ChannelCap`](rvos_wire::ChannelCap) fields in
    /// the message type instead.
    #[deprecated(note = "embed ChannelCap fields in the message type instead")]
    pub fn send_with_cap(&self, val: &S::Msg<'_>, cap: usize) -> SysResult<()> {
        let mut msg = Message::boxed();
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

// ---------------------------------------------------------------------------
// Recv — requires R: MessageType (GAT-based)
// ---------------------------------------------------------------------------
//
// These methods use the channel's internal `recv_buf` and return
// `R::Msg<'a>` borrowing from `&'a mut self`.  For owned message types
// (where `R::Msg<'a> = R`), the value doesn't actually borrow anything
// and can be moved freely.  For borrowed types (like `FsRequest<'a>`),
// the returned value holds references into `self.recv_buf.data` — the
// `&mut self` borrow prevents calling recv again until it's dropped.

impl<S, R: rvos_wire::MessageType> Channel<S, R> {
    /// Non-blocking receive.
    ///
    /// Returns the deserialized message on success, `Err(RecvError::Empty)`
    /// if no message is available, or `Err(RecvError::Closed)` if the peer
    /// closed the channel.
    ///
    /// The returned value may borrow from the channel's internal receive
    /// buffer (for zero-copy message types like `FsRequest<'a>`).  The
    /// `&mut self` borrow prevents a second recv until the caller is done
    /// processing the message.
    pub fn try_recv<'a>(&'a mut self) -> Result<R::Msg<'a>, RecvError> {
        match raw::sys_chan_recv(self.inner.raw_handle(), &mut self.recv_buf) {
            0 => self.decode_recv_buf(),
            1 => Err(RecvError::Empty),
            2 => Err(RecvError::Closed),
            code => Err(RecvError::Syscall(SysError::Unknown(code))),
        }
    }

    /// Blocking receive.
    ///
    /// Blocks until a message arrives, then deserializes and returns it.
    /// Returns `Err(RecvError::Closed)` if the peer closed the channel,
    /// or `Err(RecvError::Syscall(..))` on other errors.
    ///
    /// The returned value may borrow from the channel's internal receive
    /// buffer.  See [`try_recv`](Self::try_recv) for details.
    pub fn recv_blocking<'a>(&'a mut self) -> Result<R::Msg<'a>, RecvError> {
        let ret = raw::sys_chan_recv_blocking(self.inner.raw_handle(), &mut self.recv_buf);
        match ret {
            0 => self.decode_recv_buf(),
            2 => Err(RecvError::Closed),
            code => Err(RecvError::Syscall(SysError::Unknown(code))),
        }
    }

    /// Decode the contents of `recv_buf` into `R::Msg<'a>`.
    ///
    /// On decode failure, returns `Err(RecvError::Decode(..))` — the caller
    /// should log the error and close the channel.
    fn decode_recv_buf<'a>(&'a self) -> Result<R::Msg<'a>, RecvError> {
        rvos_wire::from_bytes_with_caps(
            &self.recv_buf.data[..self.recv_buf.len],
            &self.recv_buf.caps[..self.recv_buf.cap_count],
        ).map_err(RecvError::Decode)
    }

    /// Blocking receive of next message. Returns `None` on channel close
    /// or decode error.
    ///
    /// The returned message may borrow from the channel's internal buffer
    /// (for zero-copy message types like `FsRequest<'a>`). The `&mut self`
    /// borrow prevents a second call until the caller is done with the
    /// previous message.
    ///
    /// Usage:
    /// ```ignore
    /// while let Some(req) = channel.next_message() {
    ///     match req { ... }
    /// }
    /// ```
    pub fn next_message(&mut self) -> Option<R::Msg<'_>> {
        match self.recv_blocking() {
            Ok(msg) => Some(msg),
            Err(_) => None,
        }
    }

    /// Non-blocking drain: returns next available message, or `None` if
    /// the channel is empty or closed.
    ///
    /// Usage:
    /// ```ignore
    /// while let Some(event) = channel.try_next_message() {
    ///     handle(event);
    /// }
    /// ```
    pub fn try_next_message(&mut self) -> Option<R::Msg<'_>> {
        match self.try_recv() {
            Ok(msg) => Some(msg),
            Err(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Deprecated recv methods (sideband cap APIs)
// ---------------------------------------------------------------------------

impl<S, R: rvos_wire::DeserializeOwned> Channel<S, R> {
    /// Blocking receive, returning the deserialized value and the last
    /// explicit capability (after any caps consumed by [`ChannelCap`] fields).
    ///
    /// **Deprecated:** Embed [`ChannelCap`](rvos_wire::ChannelCap) fields in
    /// the message type instead.
    #[deprecated(note = "embed ChannelCap fields in the message type instead")]
    pub fn recv_with_cap_blocking(&self) -> SysResult<(R, usize)> {
        let mut msg = Message::boxed();
        self.inner.recv_blocking(&mut msg)?;
        let val = rvos_wire::from_bytes_with_caps::<R>(
            &msg.data[..msg.len], &msg.caps[..msg.cap_count])
            .map_err(|_| SysError::BadAddress)?;
        let cap = if msg.cap_count > 0 { msg.caps[msg.cap_count - 1] } else { crate::raw::NO_CAP };
        Ok((val, cap))
    }

    /// Blocking receive, returning the deserialized value and all capabilities.
    ///
    /// **Deprecated:** Embed [`ChannelCap`](rvos_wire::ChannelCap) fields in
    /// the message type instead.
    #[deprecated(note = "embed ChannelCap fields in the message type instead")]
    pub fn recv_with_caps_blocking(&self) -> SysResult<(R, [usize; crate::message::MAX_CAPS], usize)> {
        let mut msg = Message::boxed();
        self.inner.recv_blocking(&mut msg)?;
        let val = rvos_wire::from_bytes_with_caps::<R>(
            &msg.data[..msg.len], &msg.caps[..msg.cap_count])
            .map_err(|_| SysError::BadAddress)?;
        Ok((val, msg.caps, msg.cap_count))
    }

    /// Non-blocking receive with capability. Returns `None` if no message is available.
    ///
    /// **Deprecated:** Embed [`ChannelCap`](rvos_wire::ChannelCap) fields in
    /// the message type instead.
    #[deprecated(note = "embed ChannelCap fields in the message type instead")]
    pub fn try_recv_with_cap(&self) -> Option<(R, usize)> {
        let mut msg = Message::boxed();
        if self.inner.try_recv(&mut msg) != 0 { return None; }
        let val = rvos_wire::from_bytes_with_caps::<R>(
            &msg.data[..msg.len], &msg.caps[..msg.cap_count]).ok()?;
        let cap = if msg.cap_count > 0 { msg.caps[msg.cap_count - 1] } else { crate::raw::NO_CAP };
        Some((val, cap))
    }
}

// ---------------------------------------------------------------------------
// channel_pair
// ---------------------------------------------------------------------------

/// Create a bidirectional typed channel pair.
///
/// Returns `(Channel<A, B>, Channel<B, A>)` — side A sends `A` and
/// receives `B`; side B sends `B` and receives `A`.
pub fn channel_pair<A, B>() -> SysResult<(Channel<A, B>, Channel<B, A>)> {
    let (a, b) = RawChannel::create_pair()?;
    Ok((
        Channel { inner: a, recv_buf: Message::boxed(), _phantom: PhantomData },
        Channel { inner: b, recv_buf: Message::boxed(), _phantom: PhantomData },
    ))
}
