pub mod transport;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use crate::sync::SpinLock;
use crate::mm::address::PhysPageNum;
use crate::mm::heap::{IpcAlloc, IPC_ALLOC};

/// Maximum message payload size in bytes
pub const MAX_MSG_SIZE: usize = 1024;
/// Maximum number of bidirectional channels
const MAX_CHANNELS: usize = 64;
/// Maximum number of shared memory regions
const MAX_SHM_REGIONS: usize = 32;
/// Maximum number of messages queued per endpoint before backpressure kicks in
pub const MAX_QUEUE_DEPTH: usize = 64;

/// Sentinel value meaning "no capability attached" (user-space ABI)
pub const NO_CAP: usize = usize::MAX;

/// Errors returned by channel send operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The channel has been closed/deactivated.
    ChannelClosed,
    /// The destination queue has reached MAX_QUEUE_DEPTH.
    QueueFull,
}

// ============================================================
// RAII Types
// ============================================================

/// RAII wrapper for a channel endpoint. Clone = inc_ref, Drop = close.
pub struct OwnedEndpoint(usize);

impl core::fmt::Debug for OwnedEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("OwnedEndpoint").field(&self.0).finish()
    }
}

impl OwnedEndpoint {
    /// Wrap a raw endpoint ID. Caller must already own one reference.
    ///
    /// # Safety
    /// The caller must hold exactly one un-managed reference count for this
    /// endpoint (e.g. from `channel_create_pair`). Constructing two
    /// `OwnedEndpoint`s from the same raw ID without an intervening inc_ref
    /// is a double-free bug.
    pub unsafe fn from_raw(raw_ep: usize) -> Self {
        OwnedEndpoint(raw_ep)
    }

    /// Consume without calling Drop. For permanent endpoints stored in
    /// AtomicUsize (service control channels).
    pub fn into_raw(self) -> usize {
        let raw = self.0;
        core::mem::forget(self);
        raw
    }

    /// Borrow the raw endpoint ID for operations (send, recv, is_active).
    pub fn raw(&self) -> usize {
        self.0
    }

    /// Create a new owned reference from a raw endpoint ID by incrementing
    /// the ref count. The raw ID must refer to an active endpoint.
    pub fn clone_from_raw(raw_ep: usize) -> Self {
        channel_inc_ref(raw_ep);
        OwnedEndpoint(raw_ep)
    }

    /// Non-blocking send. Returns the woken PID (or 0) on success.
    #[allow(dead_code, clippy::result_large_err)] // mirrors channel_send; will be used as more services convert
    pub fn send(&self, msg: Message) -> Result<usize, (SendError, Message)> {
        channel_send(self.0, msg)
    }

    /// Blocking send. Suspends `pid` if the queue is full.
    pub fn send_blocking(&self, msg: Message, pid: usize) -> Result<(), SendError> {
        channel_send_blocking(self.0, msg, pid)
    }

    /// Blocking receive. Suspends `pid` until a message arrives.
    /// Returns `None` if the channel is closed.
    pub fn recv_blocking(&self, pid: usize) -> Option<Message> {
        channel_recv_blocking(self.0, pid)
    }

    /// Check whether this endpoint's channel is still active.
    pub fn is_active(&self) -> bool {
        channel_is_active(self.0)
    }
}

impl Clone for OwnedEndpoint {
    fn clone(&self) -> Self {
        channel_inc_ref(self.0);
        OwnedEndpoint(self.0)
    }
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        channel_close(self.0);
    }
}

/// RAII wrapper for a shared memory region. Clone = inc_ref, Drop = dec_ref.
pub struct OwnedShm(usize);

impl core::fmt::Debug for OwnedShm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("OwnedShm").field(&self.0).finish()
    }
}

impl OwnedShm {
    /// Wrap a raw SHM ID. Caller must already own one reference.
    ///
    /// # Safety
    /// Same contract as `OwnedEndpoint::from_raw`.
    pub unsafe fn from_raw(id: usize) -> Self {
        OwnedShm(id)
    }

    /// Consume without calling Drop.
    #[allow(dead_code)]
    pub fn into_raw(self) -> usize {
        let id = self.0;
        core::mem::forget(self);
        id
    }

    /// Borrow the raw SHM ID.
    pub fn raw(&self) -> usize {
        self.0
    }

    /// Create a new owned reference from a raw SHM ID by incrementing
    /// the ref count.
    pub fn clone_from_raw(id: usize) -> Self {
        shm_inc_ref(id);
        OwnedShm(id)
    }
}

impl Clone for OwnedShm {
    fn clone(&self) -> Self {
        shm_inc_ref(self.0);
        OwnedShm(self.0)
    }
}

impl Drop for OwnedShm {
    fn drop(&mut self) {
        shm_dec_ref(self.0);
    }
}

/// A capability slot in a kernel Message.
pub enum Cap {
    None,
    Channel(OwnedEndpoint),
    Shm { owned: OwnedShm, rw: bool },
}

impl Cap {
    #[allow(dead_code)]
    pub fn is_none(&self) -> bool {
        matches!(self, Cap::None)
    }

    /// Take the cap out, replacing with None.
    pub fn take(&mut self) -> Cap {
        core::mem::replace(self, Cap::None)
    }
}

impl Clone for Cap {
    fn clone(&self) -> Self {
        match self {
            Cap::None => Cap::None,
            Cap::Channel(ep) => Cap::Channel(ep.clone()),
            Cap::Shm { owned, rw } => Cap::Shm { owned: owned.clone(), rw: *rw },
        }
    }
}

// ============================================================
// Message
// ============================================================

/// Maximum number of capabilities per message.
pub const MAX_CAPS: usize = 4;

/// A fixed-size message with optional RAII capabilities.
///
/// Not Copy or Clone — caps hold RAII types. The `VecDeque<Message>` queue
/// uses move semantics (push_back moves in, pop_front moves out).
pub struct Message {
    pub data: [u8; MAX_MSG_SIZE],
    pub len: usize,
    pub sender_pid: usize,
    pub caps: [Cap; MAX_CAPS],
    pub cap_count: usize,
}

// Compile-time assertion: MAX_MSG_SIZE must match all other definitions.
const _: () = assert!(MAX_MSG_SIZE == 1024);

impl Message {
    pub fn new() -> Self {
        Message {
            data: [0u8; MAX_MSG_SIZE],
            len: 0,
            sender_pid: 0,
            caps: [const { Cap::None }; MAX_CAPS],
            cap_count: 0,
        }
    }

    #[allow(dead_code)]
    pub fn from_str(s: &str, sender: usize) -> Self {
        let mut msg = Message::new();
        msg.sender_pid = sender;
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(MAX_MSG_SIZE);
        msg.data[..copy_len].copy_from_slice(&bytes[..copy_len]);
        msg.len = copy_len;
        msg
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.data[..self.len]).unwrap_or("???")
    }
}

// ============================================================
// Channel internals
// ============================================================

/// Bidirectional channel with two queues.
///
/// Global endpoint IDs: ep_a = 2*channel_index, ep_b = 2*channel_index + 1
///
/// send(ep_a) pushes to queue_b (delivers to B's recv)
/// send(ep_b) pushes to queue_a (delivers to A's recv)
/// recv(ep_a) pops from queue_a
/// recv(ep_b) pops from queue_b
struct Channel {
    queue_a: VecDeque<Message, IpcAlloc>, // messages waiting for endpoint A to recv
    queue_b: VecDeque<Message, IpcAlloc>, // messages waiting for endpoint B to recv
    blocked_a: usize, // PID blocked on recv(ep_a), 0 = none
    blocked_b: usize, // PID blocked on recv(ep_b), 0 = none
    send_blocked_a: usize, // PID blocked on send(ep_a) due to full queue, 0 = none
    send_blocked_b: usize, // PID blocked on send(ep_b) due to full queue, 0 = none
    ref_count_a: usize, // number of handles referencing endpoint A across all processes
    ref_count_b: usize, // number of handles referencing endpoint B across all processes
    active: bool,
    // Per-channel statistics: messages and bytes delivered to each queue
    msgs_a: u64,  // messages delivered to queue_a (from B→A sends)
    bytes_a: u64, // bytes delivered to queue_a
    msgs_b: u64,  // messages delivered to queue_b (from A→B sends)
    bytes_b: u64, // bytes delivered to queue_b
}

impl Channel {
    fn new() -> Self {
        Channel {
            queue_a: VecDeque::new_in(IPC_ALLOC),
            queue_b: VecDeque::new_in(IPC_ALLOC),
            blocked_a: 0,
            blocked_b: 0,
            send_blocked_a: 0,
            send_blocked_b: 0,
            ref_count_a: 1,
            ref_count_b: 1,
            active: true,
            msgs_a: 0,
            bytes_a: 0,
            msgs_b: 0,
            bytes_b: 0,
        }
    }
}

struct ChannelManager {
    channels: Vec<Option<Channel>>,
}

impl ChannelManager {
    const fn new() -> Self {
        ChannelManager {
            channels: Vec::new(),
        }
    }

    fn init(&mut self) {
        self.channels = Vec::with_capacity(MAX_CHANNELS);
        for _ in 0..MAX_CHANNELS {
            self.channels.push(None);
        }
    }
}

static CHANNELS: SpinLock<ChannelManager> = SpinLock::new(ChannelManager::new());

pub fn init() {
    CHANNELS.lock().init();
    shm_init();
}

/// Helper: endpoint ID -> (channel_index, is_b_side)
fn ep_to_channel(endpoint: usize) -> (usize, bool) {
    (endpoint / 2, endpoint & 1 == 1)
}

/// Create a bidirectional channel pair.
/// Returns Some((ep_a, ep_b)) as RAII OwnedEndpoints, or None if all
/// channel slots are exhausted.
pub fn channel_create_pair() -> Option<(OwnedEndpoint, OwnedEndpoint)> {
    let mut mgr = CHANNELS.lock();
    for (i, slot) in mgr.channels.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(Channel::new());
            crate::kstat::inc(&crate::kstat::CHANNELS_CREATED);
            // SAFETY: Channel::new() sets ref_count_a=1, ref_count_b=1,
            // so we own exactly one reference to each endpoint.
            unsafe {
                return Some((
                    OwnedEndpoint::from_raw(i * 2),
                    OwnedEndpoint::from_raw(i * 2 + 1),
                ));
            }
        }
    }
    crate::println!("[ipc] channel_create_pair: all {} slots exhausted", MAX_CHANNELS);
    None
}

/// Send a message on an endpoint (by move).
/// send(ep_a) delivers to queue_b, send(ep_b) delivers to queue_a.
///
/// On success: returns Ok(wake_pid) where wake_pid is the PID of a blocked
/// receiver to wake (0 = none). The message (with its RAII caps) is now
/// owned by the queue.
///
/// On failure: returns Err((error, msg)) — the message is returned to the
/// caller intact with all caps still owned. Dropping it auto-closes caps.
#[allow(clippy::result_large_err)]
pub fn channel_send(endpoint: usize, msg: Message) -> Result<usize, (SendError, Message)> {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if !channel.active {
            return Err((SendError::ChannelClosed, msg));
        }
        let msg_bytes = msg.len as u64;
        if is_b {
            // Sending from B side -> push to queue_a (for A to recv)
            if channel.queue_a.len() >= MAX_QUEUE_DEPTH {
                return Err((SendError::QueueFull, msg));
            }
            channel.queue_a.push_back(msg);
            channel.msgs_a += 1;
            channel.bytes_a += msg_bytes;
            crate::kstat::inc(&crate::kstat::IPC_SENDS);
            Ok(channel.blocked_a)
        } else {
            // Sending from A side -> push to queue_b (for B to recv)
            if channel.queue_b.len() >= MAX_QUEUE_DEPTH {
                return Err((SendError::QueueFull, msg));
            }
            channel.queue_b.push_back(msg);
            channel.msgs_b += 1;
            channel.bytes_b += msg_bytes;
            crate::kstat::inc(&crate::kstat::IPC_SENDS);
            Ok(channel.blocked_b)
        }
    } else {
        Err((SendError::ChannelClosed, msg))
    }
}

/// Try to receive a message (non-blocking).
/// recv(ep_a) pops from queue_a, recv(ep_b) pops from queue_b.
/// Returns (message, send_wake_pid) where send_wake_pid is the PID of a
/// process blocked waiting to send on this channel (0 = none).
pub fn channel_recv(endpoint: usize) -> (Option<Message>, usize) {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        let msg = if is_b {
            channel.queue_b.pop_front()
        } else {
            channel.queue_a.pop_front()
        };
        if msg.is_some() {
            crate::kstat::inc(&crate::kstat::IPC_RECVS);
            // A slot freed up — check if a sender was blocked on this channel.
            // send(ep_a) pushes to queue_b, so if we popped from queue_b (is_b),
            // the blocked sender is on ep_a side (send_blocked_a).
            // send(ep_b) pushes to queue_a, so if we popped from queue_a (!is_b),
            // the blocked sender is on ep_b side (send_blocked_b).
            let wake = if is_b {
                let w = channel.send_blocked_a;
                if w != 0 { channel.send_blocked_a = 0; }
                w
            } else {
                let w = channel.send_blocked_b;
                if w != 0 { channel.send_blocked_b = 0; }
                w
            };
            (msg, wake)
        } else {
            (None, 0)
        }
    } else {
        (None, 0)
    }
}

/// Record that a PID is blocked waiting to recv on this endpoint.
pub fn channel_set_blocked(endpoint: usize, pid: usize) {
    crate::kstat::inc(&crate::kstat::IPC_RECV_BLOCKS);
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if is_b {
            channel.blocked_b = pid;
        } else {
            channel.blocked_a = pid;
        }
    }
}

/// Record that a PID is blocked waiting to send on this endpoint.
/// send(ep_a) pushes to queue_b, so block is recorded as send_blocked_a.
/// send(ep_b) pushes to queue_a, so block is recorded as send_blocked_b.
pub fn channel_set_send_blocked(endpoint: usize, pid: usize) {
    crate::kstat::inc(&crate::kstat::IPC_SEND_BLOCKS);
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if is_b {
            channel.send_blocked_b = pid;
        } else {
            channel.send_blocked_a = pid;
        }
    }
}

/// Blocking send for kernel tasks. Takes the message by move.
/// Blocks the calling kernel task until the message is sent or the channel
/// is closed. On QueueFull, the message is returned from channel_send and
/// retried after blocking. On ChannelClosed, the message drops (auto-closing
/// all RAII caps).
pub fn channel_send_blocking(endpoint: usize, mut msg: Message, pid: usize) -> Result<(), SendError> {
    loop {
        match channel_send(endpoint, msg) {
            Ok(wake) => {
                if wake != 0 {
                    crate::task::wake_process(wake);
                }
                return Ok(());
            }
            Err((SendError::QueueFull, returned)) => {
                msg = returned;
                if !channel_is_active(endpoint) {
                    // msg drops here → caps auto-close
                    return Err(SendError::ChannelClosed);
                }
                channel_set_send_blocked(endpoint, pid);
                crate::task::set_block_reason(pid, crate::task::BlockReason::IpcSend(endpoint));
                crate::task::block_process(pid);
                crate::task::schedule();
            }
            Err((SendError::ChannelClosed, _dropped)) => {
                // _dropped goes out of scope → caps auto-close
                return Err(SendError::ChannelClosed);
            }
        }
    }
}

/// Blocking receive for kernel tasks. Blocks the calling kernel task until
/// a message arrives or the channel is closed (returns None on close).
pub fn channel_recv_blocking(endpoint: usize, pid: usize) -> Option<Message> {
    loop {
        let (msg, send_wake) = channel_recv(endpoint);
        if send_wake != 0 {
            crate::task::wake_process(send_wake);
        }
        if let Some(msg) = msg {
            return Some(msg);
        }
        if !channel_is_active(endpoint) {
            return None; // channel closed
        }
        channel_set_blocked(endpoint, pid);
        crate::task::set_block_reason(pid, crate::task::BlockReason::IpcRecv(endpoint));
        crate::task::block_process(pid);
        crate::task::schedule();
    }
}

/// Result of accepting a client connection from a service control channel.
#[allow(dead_code)]
pub struct AcceptedClient {
    /// The server-side endpoint for the new client channel (RAII).
    pub endpoint: OwnedEndpoint,
    /// The PID of the connecting client (from the NewConnection message).
    pub client_pid: u32,
    /// Channel role: 0 = generic, 1 = stdin, 2 = stdout.
    pub channel_role: u8,
}

/// Wait for a client endpoint from a service's control channel.
/// Blocks until a NewConnection message carrying a channel capability arrives.
/// Parses the `NewConnection { client_pid, channel_role }` payload from the message data.
pub fn accept_client(control_ep: usize, pid: usize) -> AcceptedClient {
    loop {
        match channel_recv_blocking(control_ep, pid) {
            Some(mut msg) => {
                if msg.cap_count > 0 {
                    if let Cap::Channel(ep) = msg.caps[0].take() {
                        // Parse client_pid from NewConnection message
                        let client_pid = if msg.len >= 5 {
                            u32::from_le_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]])
                        } else {
                            0
                        };
                        let channel_role = if msg.len >= 5 {
                            msg.data[4]
                        } else {
                            0
                        };
                        return AcceptedClient { endpoint: ep, client_pid, channel_role };
                    }
                }
                // Message without channel cap — ignore and keep waiting
            }
            None => {
                // Control channel closed (shouldn't happen for kernel services)
                crate::task::block_process(pid);
                crate::task::schedule();
            }
        }
    }
}

/// Clear any blocked/send-blocked registrations matching the given PID.
/// Called when a process is terminated externally to prevent stale blocked
/// registrations from interfering with future IPC operations.
pub fn channel_clear_blocked_pid(pid: usize) {
    let mut mgr = CHANNELS.lock();
    for ch in mgr.channels.iter_mut().flatten() {
        if ch.blocked_a == pid { ch.blocked_a = 0; }
        if ch.blocked_b == pid { ch.blocked_b = 0; }
        if ch.send_blocked_a == pid { ch.send_blocked_a = 0; }
        if ch.send_blocked_b == pid { ch.send_blocked_b = 0; }
    }
}

/// Check if a channel endpoint is still active.
#[must_use]
pub fn channel_is_active(endpoint: usize) -> bool {
    let (ch_idx, _) = ep_to_channel(endpoint);
    let mgr = CHANNELS.lock();
    if let Some(Some(ch)) = mgr.channels.get(ch_idx) {
        ch.active
    } else {
        false
    }
}

/// Increment the ref count for a channel endpoint.
/// Panics if the endpoint refers to an inactive or invalid channel — this
/// indicates a kernel bug (the caller should only inc_ref endpoints it owns).
///
/// Private to the ipc module — external code uses OwnedEndpoint::clone()
/// or OwnedEndpoint::clone_from_raw() instead.
fn channel_inc_ref(endpoint: usize) {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    let ch = mgr.channels.get_mut(ch_idx)
        .and_then(|slot| slot.as_mut())
        .unwrap_or_else(|| panic!("channel_inc_ref: invalid endpoint {}", endpoint));
    assert!(ch.active, "channel_inc_ref: channel {} is inactive", ch_idx);
    if is_b {
        ch.ref_count_b += 1;
    } else {
        ch.ref_count_a += 1;
    }
}

/// Close an endpoint. Decrements the endpoint's ref count. Only deactivates
/// the channel when the ref count reaches 0. Wakes any blocked peer (recv or
/// send) so it can detect the close. Frees the channel slot when both ref
/// counts are 0.
///
/// When freeing the channel, the Channel is taken out of the slot before
/// releasing the CHANNELS lock, then dropped outside the lock. This prevents
/// deadlock: dropping queued Messages drops their RAII Caps, which may call
/// channel_close recursively.
///
/// Private to the ipc module — external code drops OwnedEndpoint instead.
fn channel_close(endpoint: usize) {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    let wake_recv;
    let wake_send;
    let dropped_channel;
    if let Some(Some(ref mut ch)) = mgr.channels.get_mut(ch_idx) {
        // Decrement the appropriate ref count
        let rc = if is_b { &mut ch.ref_count_b } else { &mut ch.ref_count_a };
        if *rc > 0 {
            *rc -= 1;
        }
        let this_rc = if is_b { ch.ref_count_b } else { ch.ref_count_a };

        if this_rc > 0 {
            // Other handles still reference this endpoint; don't deactivate
            return;
        }

        // This endpoint's last handle is gone — deactivate the channel
        ch.active = false;
        crate::kstat::inc(&crate::kstat::CHANNELS_CLOSED);
        // Wake the peer blocked on recv on the other endpoint
        wake_recv = if is_b { ch.blocked_a } else { ch.blocked_b };
        if wake_recv != 0 {
            if is_b { ch.blocked_a = 0; } else { ch.blocked_b = 0; }
        }
        // Wake the peer blocked on send on the other endpoint
        wake_send = if is_b { ch.send_blocked_a } else { ch.send_blocked_b };
        if wake_send != 0 {
            if is_b { ch.send_blocked_a = 0; } else { ch.send_blocked_b = 0; }
        }

        // Take the channel out for deferred drop if both sides have zero refs.
        // Dropping inside the lock would deadlock if queued messages hold RAII
        // caps to other channels (Drop → channel_close → lock CHANNELS again).
        dropped_channel = if ch.ref_count_a == 0 && ch.ref_count_b == 0 {
            mgr.channels[ch_idx].take()
        } else {
            None
        };
    } else {
        return;
    }
    drop(mgr);
    if wake_recv != 0 {
        crate::task::wake_process(wake_recv);
    }
    if wake_send != 0 && wake_send != wake_recv {
        crate::task::wake_process(wake_send);
    }
    // Drop the channel (and its queued messages) outside the lock.
    // Message caps with OwnedEndpoints/OwnedShms will be cleaned up here.
    drop(dropped_channel);
}

// ============================================================
// Channel Statistics
// ============================================================

/// Format a summary of all active channels for display.
pub fn format_channel_stats() -> alloc::string::String {
    use core::fmt::Write;
    let mgr = CHANNELS.lock();
    let mut out = alloc::string::String::new();
    let _ = writeln!(out, "  {:>4}  {:>5}  {:>5}  {:>4}  {:>4}  {:>4}  {:>4}  {:>7}  {:>7}  {:>7}  {:>7}",
        "CH", "EP_A", "EP_B", "QA", "QB", "RC_A", "RC_B", "MSGS_A", "BYTES_A", "MSGS_B", "BYTES_B");
    let _ = writeln!(out, "  {:>4}  {:>5}  {:>5}  {:>4}  {:>4}  {:>4}  {:>4}  {:>7}  {:>7}  {:>7}  {:>7}",
        "----", "-----", "-----", "----", "----", "----", "----", "-------", "-------", "-------", "-------");
    for (i, slot) in mgr.channels.iter().enumerate() {
        if let Some(ref ch) = slot {
            if !ch.active && ch.ref_count_a == 0 && ch.ref_count_b == 0 {
                continue;
            }
            let _ = writeln!(out, "  {:>4}  {:>5}  {:>5}  {:>4}  {:>4}  {:>4}  {:>4}  {:>7}  {:>7}  {:>7}  {:>7}{}",
                i, i * 2, i * 2 + 1,
                ch.queue_a.len(), ch.queue_b.len(),
                ch.ref_count_a, ch.ref_count_b,
                ch.msgs_a, ch.bytes_a,
                ch.msgs_b, ch.bytes_b,
                if !ch.active { "  (closed)" } else { "" });
        }
    }
    out
}

// ============================================================
// Shared Memory Region Manager
// ============================================================

struct ShmRegion {
    base_ppn: PhysPageNum, // first physical page of the region
    page_count: usize,     // number of contiguous physical pages
    ref_count: usize,      // number of outstanding handles (RO + RW)
    active: bool,          // false after freed
}

struct ShmManager {
    regions: Vec<Option<ShmRegion>>,
}

impl ShmManager {
    const fn new() -> Self {
        ShmManager {
            regions: Vec::new(),
        }
    }

    fn init(&mut self) {
        self.regions = Vec::with_capacity(MAX_SHM_REGIONS);
        for _ in 0..MAX_SHM_REGIONS {
            self.regions.push(None);
        }
    }
}

static SHM_REGIONS: SpinLock<ShmManager> = SpinLock::new(ShmManager::new());

/// Initialize the SHM manager (call from ipc::init).
fn shm_init() {
    SHM_REGIONS.lock().init();
}

/// Create a new SHM region with the given number of contiguous physical pages.
/// The pages must already be allocated and zeroed.
/// Returns an OwnedShm, or None if the table is full.
pub fn shm_create(base_ppn: PhysPageNum, page_count: usize) -> Option<OwnedShm> {
    let mut mgr = SHM_REGIONS.lock();
    for (i, slot) in mgr.regions.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(ShmRegion {
                base_ppn,
                page_count,
                ref_count: 1,
                active: true,
            });
            // SAFETY: ref_count starts at 1, so we own exactly one reference.
            return Some(unsafe { OwnedShm::from_raw(i) });
        }
    }
    None
}

/// Increment the ref_count of a SHM region.
/// Panics if the SHM ID is invalid or inactive — this indicates a kernel bug.
///
/// Private to the ipc module — external code uses OwnedShm::clone() instead.
fn shm_inc_ref(shm_id: usize) {
    let mut mgr = SHM_REGIONS.lock();
    let region = mgr.regions.get_mut(shm_id)
        .and_then(|slot| slot.as_mut())
        .unwrap_or_else(|| panic!("shm_inc_ref: invalid shm_id {}", shm_id));
    assert!(region.active, "shm_inc_ref: shm_id {} is inactive", shm_id);
    region.ref_count += 1;
}

/// Decrement the ref_count of a SHM region. If it reaches 0, free the physical
/// frames and mark the region as inactive.
/// Panics if the SHM ID is invalid or inactive — this indicates a kernel bug.
///
/// Private to the ipc module — external code drops OwnedShm instead.
fn shm_dec_ref(shm_id: usize) {
    let mut mgr = SHM_REGIONS.lock();
    let region = mgr.regions.get_mut(shm_id)
        .and_then(|slot| slot.as_mut())
        .unwrap_or_else(|| panic!("shm_dec_ref: invalid shm_id {}", shm_id));
    assert!(region.active, "shm_dec_ref: shm_id {} is inactive", shm_id);
    assert!(region.ref_count > 0, "shm_dec_ref: underflow on shm_id {}", shm_id);
    region.ref_count -= 1;
    if region.ref_count == 0 {
        // Free physical frames
        let base = region.base_ppn;
        let count = region.page_count;
        region.active = false;
        mgr.regions[shm_id] = None;
        // Drop lock before dealloc (frame allocator has its own lock)
        drop(mgr);
        for i in 0..count {
            crate::mm::frame::frame_dealloc(PhysPageNum(base.0 + i));
        }
    }
}

/// Get the base PPN and page count of a SHM region. Returns None if invalid.
pub fn shm_get_info(shm_id: usize) -> Option<(PhysPageNum, usize)> {
    let mgr = SHM_REGIONS.lock();
    if let Some(Some(ref region)) = mgr.regions.get(shm_id) {
        if region.active {
            return Some((region.base_ppn, region.page_count));
        }
    }
    None
}
