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

/// Sentinel value meaning "no capability attached"
pub const NO_CAP: usize = usize::MAX;

/// Errors returned by channel send operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The channel has been closed/deactivated.
    ChannelClosed,
    /// The destination queue has reached MAX_QUEUE_DEPTH.
    QueueFull,
}

// Internal capability encoding in message queue (bits 63..62)
// 00 = no capability (NO_CAP)
// 01 = channel endpoint
// 10 = shared memory (RW)
// 11 = shared memory (RO)
const CAP_TAG_CHANNEL: usize = 0b01 << 62;
const CAP_TAG_SHM_RW: usize = 0b10 << 62;
const CAP_TAG_SHM_RO: usize = 0b11 << 62;
const CAP_TAG_MASK: usize = 0b11 << 62;
const CAP_ID_MASK: usize = !(0b11 << 62);

/// Encode a channel endpoint capability for the message queue.
pub fn encode_cap_channel(global_ep: usize) -> usize {
    CAP_TAG_CHANNEL | (global_ep & CAP_ID_MASK)
}

/// Encode a SHM capability for the message queue.
pub fn encode_cap_shm(global_shm_id: usize, rw: bool) -> usize {
    let tag = if rw { CAP_TAG_SHM_RW } else { CAP_TAG_SHM_RO };
    tag | (global_shm_id & CAP_ID_MASK)
}

/// Decoded capability from message queue.
pub enum DecodedCap {
    None,
    Channel(usize),           // global endpoint ID
    Shm { id: usize, rw: bool }, // global SHM ID + permission
}

/// Decode a capability from the message queue.
pub fn decode_cap(encoded: usize) -> DecodedCap {
    if encoded == NO_CAP {
        return DecodedCap::None;
    }
    let tag = encoded & CAP_TAG_MASK;
    let id = encoded & CAP_ID_MASK;
    match tag {
        CAP_TAG_CHANNEL => DecodedCap::Channel(id),
        CAP_TAG_SHM_RW => DecodedCap::Shm { id, rw: true },
        CAP_TAG_SHM_RO => DecodedCap::Shm { id, rw: false },
        _ => DecodedCap::None, // tag 00 with non-MAX value, treat as none
    }
}

/// Convenience: decode an encoded cap as a channel endpoint ID.
/// Used by kernel-internal services that receive caps through message queues.
pub fn decode_cap_channel(encoded: usize) -> Option<usize> {
    match decode_cap(encoded) {
        DecodedCap::Channel(ep) => Some(ep),
        _ => None,
    }
}

/// A fixed-size message with optional capability
#[derive(Clone)]
#[repr(C)]
pub struct Message {
    pub data: [u8; MAX_MSG_SIZE],
    pub len: usize,
    pub sender_pid: usize,
    pub cap: usize, // NO_CAP = none, otherwise global endpoint ID
}

impl Message {
    pub fn new() -> Self {
        Message {
            data: [0u8; MAX_MSG_SIZE],
            len: 0,
            sender_pid: 0,
            cap: NO_CAP,
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
/// Returns Some((ep_a, ep_b)) — two global endpoint IDs, or None if all
/// channel slots are exhausted.
pub fn channel_create_pair() -> Option<(usize, usize)> {
    let mut mgr = CHANNELS.lock();
    for (i, slot) in mgr.channels.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(Channel::new());
            return Some((i * 2, i * 2 + 1));
        }
    }
    crate::println!("[ipc] channel_create_pair: all {} slots exhausted", MAX_CHANNELS);
    None
}

/// Send a message on an endpoint.
/// send(ep_a) delivers to queue_b, send(ep_b) delivers to queue_a.
/// Returns Ok(wake_pid) where wake_pid is the PID of a blocked receiver to wake (0 = none).
///
/// The blocked field is NOT cleared here — it persists until the receiver
/// re-registers via poll_add or the channel is closed.  This ensures that
/// rapid-fire sends (e.g., client sends request, server is still in its
/// event loop and hasn't re-registered yet) still trigger a wake.  Redundant
/// wakes are harmless: wake_process on a Ready/Running process just sets
/// wakeup_pending.
pub fn channel_send(endpoint: usize, msg: Message) -> Result<usize, SendError> {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if !channel.active {
            return Err(SendError::ChannelClosed);
        }
        if is_b {
            // Sending from B side -> push to queue_a (for A to recv)
            if channel.queue_a.len() >= MAX_QUEUE_DEPTH {
                return Err(SendError::QueueFull);
            }
            channel.queue_a.push_back(msg);
            Ok(channel.blocked_a)
        } else {
            // Sending from A side -> push to queue_b (for B to recv)
            if channel.queue_b.len() >= MAX_QUEUE_DEPTH {
                return Err(SendError::QueueFull);
            }
            channel.queue_b.push_back(msg);
            Ok(channel.blocked_b)
        }
    } else {
        Err(SendError::ChannelClosed)
    }
}

/// Send by reference (for syscall path). Returns Ok(wake_pid) or Err(SendError).
/// See channel_send for why blocked is not cleared here.
pub fn channel_send_ref(endpoint: usize, msg: &Message) -> Result<usize, SendError> {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    let result = if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if !channel.active {
            Err(SendError::ChannelClosed)
        } else if is_b {
            if channel.queue_a.len() >= MAX_QUEUE_DEPTH {
                Err(SendError::QueueFull)
            } else {
                channel.queue_a.push_back(msg.clone());
                Ok(channel.blocked_a)
            }
        } else {
            if channel.queue_b.len() >= MAX_QUEUE_DEPTH {
                Err(SendError::QueueFull)
            } else {
                channel.queue_b.push_back(msg.clone());
                Ok(channel.blocked_b)
            }
        }
    } else {
        Err(SendError::ChannelClosed)
    };
    result
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

/// Blocking send for kernel tasks. Blocks the calling kernel task until the
/// message is sent or the channel is closed. Returns Ok(()) on success, or
/// Err(SendError::ChannelClosed) if the channel closed before sending.
pub fn channel_send_blocking(endpoint: usize, msg: &Message, pid: usize) -> Result<(), SendError> {
    loop {
        match channel_send_ref(endpoint, msg) {
            Ok(wake) => {
                if wake != 0 {
                    crate::task::wake_process(wake);
                }
                return Ok(());
            }
            Err(SendError::QueueFull) => {
                if !channel_is_active(endpoint) {
                    return Err(SendError::ChannelClosed);
                }
                channel_set_send_blocked(endpoint, pid);
                crate::task::block_process(pid);
                crate::task::schedule();
            }
            Err(e) => return Err(e),
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
        crate::task::block_process(pid);
        crate::task::schedule();
    }
}

/// Result of accepting a client connection from a service control channel.
pub struct AcceptedClient {
    /// The server-side endpoint for the new client channel.
    pub endpoint: usize,
    /// The PID of the connecting client (from the NewConnection message).
    pub client_pid: u32,
}

/// Wait for a client endpoint from a service's control channel.
/// Blocks until a NewConnection message carrying a channel capability arrives.
/// Parses the `NewConnection { client_pid }` payload from the message data.
pub fn accept_client(control_ep: usize, pid: usize) -> AcceptedClient {
    loop {
        match channel_recv_blocking(control_ep, pid) {
            Some(msg) => {
                if let Some(ep) = decode_cap_channel(msg.cap) {
                    // Parse client_pid from NewConnection message
                    let client_pid = if msg.len >= 5 {
                        // NewConnection wire format: u8(tag=0) + u32(client_pid)
                        u32::from_le_bytes([msg.data[1], msg.data[2], msg.data[3], msg.data[4]])
                    } else {
                        0
                    };
                    return AcceptedClient { endpoint: ep, client_pid };
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

/// RAII wrapper around a channel endpoint. Calls `channel_close` on drop.
/// Prevents the leak bug class where services forget to close client endpoints.
pub struct OwnedEndpoint(usize);

impl OwnedEndpoint {
    pub fn new(ep: usize) -> Self {
        OwnedEndpoint(ep)
    }

    pub fn raw(&self) -> usize {
        self.0
    }
}

impl Drop for OwnedEndpoint {
    fn drop(&mut self) {
        channel_close(self.0);
    }
}

/// Check if a channel endpoint is still active.
pub fn channel_is_active(endpoint: usize) -> bool {
    let (ch_idx, _) = ep_to_channel(endpoint);
    let mgr = CHANNELS.lock();
    if let Some(Some(ch)) = mgr.channels.get(ch_idx) {
        ch.active
    } else {
        false
    }
}

/// Increment the ref count for a channel endpoint. Returns false if
/// the channel is inactive or invalid (mirrors `shm_inc_ref`).
pub fn channel_inc_ref(endpoint: usize) -> bool {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(ref mut ch)) = mgr.channels.get_mut(ch_idx) {
        if !ch.active {
            return false;
        }
        if is_b {
            ch.ref_count_b += 1;
        } else {
            ch.ref_count_a += 1;
        }
        true
    } else {
        false
    }
}

/// Close an endpoint. Decrements the endpoint's ref count. Only deactivates
/// the channel when the ref count reaches 0. Wakes any blocked peer (recv or
/// send) so it can detect the close. Frees the channel slot when both ref
/// counts are 0.
pub fn channel_close(endpoint: usize) {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    let wake_recv;
    let wake_send;
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

        // Free the channel slot if both sides have zero refs
        if ch.ref_count_a == 0 && ch.ref_count_b == 0 {
            mgr.channels[ch_idx] = None;
        }
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
/// Returns the global SHM ID, or None if the table is full.
pub fn shm_create(base_ppn: PhysPageNum, page_count: usize) -> Option<usize> {
    let mut mgr = SHM_REGIONS.lock();
    for (i, slot) in mgr.regions.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(ShmRegion {
                base_ppn,
                page_count,
                ref_count: 1,
                active: true,
            });
            return Some(i);
        }
    }
    None
}

/// Increment the ref_count of a SHM region. Returns false if the region is invalid.
pub fn shm_inc_ref(shm_id: usize) -> bool {
    let mut mgr = SHM_REGIONS.lock();
    if let Some(Some(ref mut region)) = mgr.regions.get_mut(shm_id) {
        if region.active {
            region.ref_count += 1;
            return true;
        }
    }
    false
}

/// Decrement the ref_count of a SHM region. If it reaches 0, free the physical frames
/// and mark the region as inactive. Returns true if the region was valid.
pub fn shm_dec_ref(shm_id: usize) -> bool {
    let mut mgr = SHM_REGIONS.lock();
    if let Some(Some(ref mut region)) = mgr.regions.get_mut(shm_id) {
        if !region.active {
            return false;
        }
        if region.ref_count > 0 {
            region.ref_count -= 1;
        }
        if region.ref_count == 0 {
            // Free physical frames
            for i in 0..region.page_count {
                crate::mm::frame::frame_dealloc(PhysPageNum(region.base_ppn.0 + i));
            }
            region.active = false;
            // Remove from table
            mgr.regions[shm_id] = None;
        }
        return true;
    }
    false
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
