use alloc::collections::VecDeque;
use alloc::vec::Vec;
use crate::sync::SpinLock;

/// Maximum message payload size in bytes
const MAX_MSG_SIZE: usize = 64;
/// Maximum number of bidirectional channels
const MAX_CHANNELS: usize = 32;

/// Sentinel value meaning "no capability attached"
pub const NO_CAP: usize = usize::MAX;

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
    queue_a: VecDeque<Message>, // messages waiting for endpoint A to recv
    queue_b: VecDeque<Message>, // messages waiting for endpoint B to recv
    blocked_a: usize, // PID blocked on recv(ep_a), 0 = none
    blocked_b: usize, // PID blocked on recv(ep_b), 0 = none
    active: bool,
}

impl Channel {
    fn new() -> Self {
        Channel {
            queue_a: VecDeque::new(),
            queue_b: VecDeque::new(),
            blocked_a: 0,
            blocked_b: 0,
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
}

/// Helper: endpoint ID -> (channel_index, is_b_side)
fn ep_to_channel(endpoint: usize) -> (usize, bool) {
    (endpoint / 2, endpoint & 1 == 1)
}

/// Create a bidirectional channel pair.
/// Returns (ep_a, ep_b) — two global endpoint IDs.
pub fn channel_create_pair() -> (usize, usize) {
    let mut mgr = CHANNELS.lock();
    for (i, slot) in mgr.channels.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(Channel::new());
            return (i * 2, i * 2 + 1);
        }
    }
    panic!("No free channels");
}

/// Send a message on an endpoint.
/// send(ep_a) delivers to queue_b, send(ep_b) delivers to queue_a.
/// Returns the PID of a blocked receiver to wake (0 = none).
pub fn channel_send(endpoint: usize, msg: Message) -> usize {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if !channel.active {
            return 0;
        }
        if is_b {
            // Sending from B side -> push to queue_a (for A to recv)
            channel.queue_a.push_back(msg);
            let wake = channel.blocked_a;
            if wake != 0 {
                channel.blocked_a = 0;
            }
            wake
        } else {
            // Sending from A side -> push to queue_b (for B to recv)
            channel.queue_b.push_back(msg);
            let wake = channel.blocked_b;
            if wake != 0 {
                channel.blocked_b = 0;
            }
            wake
        }
    } else {
        0
    }
}

/// Send by reference (for syscall path). Returns Ok(wake_pid) or Err(()).
pub fn channel_send_ref(endpoint: usize, msg: &Message) -> Result<usize, ()> {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if !channel.active {
            return Err(());
        }
        if is_b {
            channel.queue_a.push_back(msg.clone());
            let wake = channel.blocked_a;
            if wake != 0 { channel.blocked_a = 0; }
            Ok(wake)
        } else {
            channel.queue_b.push_back(msg.clone());
            let wake = channel.blocked_b;
            if wake != 0 { channel.blocked_b = 0; }
            Ok(wake)
        }
    } else {
        Err(())
    }
}

/// Try to receive a message (non-blocking).
/// recv(ep_a) pops from queue_a, recv(ep_b) pops from queue_b.
pub fn channel_recv(endpoint: usize) -> Option<Message> {
    let (ch_idx, is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch_idx) {
        if is_b {
            channel.queue_b.pop_front()
        } else {
            channel.queue_a.pop_front()
        }
    } else {
        None
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

/// Close an endpoint. If both sides are closed, the channel is freed.
pub fn channel_close(endpoint: usize) {
    let (ch_idx, _is_b) = ep_to_channel(endpoint);
    let mut mgr = CHANNELS.lock();
    if let Some(slot) = mgr.channels.get_mut(ch_idx) {
        // For simplicity, closing either endpoint deactivates the channel
        if let Some(ref mut ch) = slot {
            ch.active = false;
        }
    }
}
