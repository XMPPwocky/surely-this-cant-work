use alloc::collections::VecDeque;
use alloc::vec::Vec;
use crate::sync::SpinLock;

/// Maximum message size in bytes
const MAX_MSG_SIZE: usize = 64;
const MAX_CHANNELS: usize = 16;

/// A fixed-size message
#[derive(Clone)]
pub struct Message {
    pub data: [u8; MAX_MSG_SIZE],
    pub len: usize,
    pub sender_pid: usize,
}

impl Message {
    pub fn from_str(s: &str, sender: usize) -> Self {
        let mut msg = Message {
            data: [0u8; MAX_MSG_SIZE],
            len: 0,
            sender_pid: sender,
        };
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(MAX_MSG_SIZE);
        msg.data[..copy_len].copy_from_slice(&bytes[..copy_len]);
        msg.len = copy_len;
        msg
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.data[..self.len]).unwrap_or("???")
    }
}

/// A uni-directional message channel (bounded queue)
struct Channel {
    queue: VecDeque<Message>,
    active: bool,
}

impl Channel {
    fn new() -> Self {
        Channel {
            queue: VecDeque::new(),
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

/// Create a new channel. Returns channel ID.
pub fn channel_create() -> usize {
    let mut mgr = CHANNELS.lock();
    for (i, slot) in mgr.channels.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(Channel::new());
            return i;
        }
    }
    panic!("No free channels");
}

/// Send a message on a channel (non-blocking).
pub fn channel_send(ch: usize, msg: Message) {
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch) {
        if channel.active {
            channel.queue.push_back(msg);
        }
    }
}

/// Try to receive a message from a channel (non-blocking).
/// Returns None if the queue is empty.
pub fn channel_recv(ch: usize) -> Option<Message> {
    let mut mgr = CHANNELS.lock();
    if let Some(Some(channel)) = mgr.channels.get_mut(ch) {
        channel.queue.pop_front()
    } else {
        None
    }
}

/// Close a channel.
pub fn channel_close(ch: usize) {
    let mut mgr = CHANNELS.lock();
    if let Some(slot) = mgr.channels.get_mut(ch) {
        *slot = None;
    }
}
