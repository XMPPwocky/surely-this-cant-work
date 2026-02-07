use crate::sync::SpinLock;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

const TRACE_CAPACITY: usize = 16384;
const TRACE_LABEL_LEN: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
struct TraceEntry {
    timestamp: u64,
    pid: usize,
    label: [u8; TRACE_LABEL_LEN],
    label_len: u8,
}

struct TraceRing {
    entries: [TraceEntry; TRACE_CAPACITY],
    head: usize,
    count: usize,
}

impl TraceRing {
    const fn new() -> Self {
        const EMPTY_ENTRY: TraceEntry = TraceEntry {
            timestamp: 0,
            pid: 0,
            label: [0u8; TRACE_LABEL_LEN],
            label_len: 0,
        };
        TraceRing {
            entries: [EMPTY_ENTRY; TRACE_CAPACITY],
            head: 0,
            count: 0,
        }
    }
}

static TRACE_RING: SpinLock<TraceRing> = SpinLock::new(TraceRing::new());

/// Push a trace entry with the current `rdtime` timestamp.
pub fn trace_push(pid: usize, label: &[u8]) {
    let time: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) time);
    }

    let copy_len = label.len().min(TRACE_LABEL_LEN);

    let mut ring = TRACE_RING.lock();
    let head = ring.head;
    let entry = &mut ring.entries[head];
    entry.timestamp = time;
    entry.pid = pid;
    entry.label[..copy_len].copy_from_slice(&label[..copy_len]);
    // Zero-pad the rest
    for i in copy_len..TRACE_LABEL_LEN {
        entry.label[i] = 0;
    }
    entry.label_len = copy_len as u8;

    ring.head = (head + 1) % TRACE_CAPACITY;
    if ring.count < TRACE_CAPACITY {
        ring.count += 1;
        if ring.count == TRACE_CAPACITY {
            crate::println!("[trace] ring buffer full ({} entries), oldest entries will be overwritten", TRACE_CAPACITY);
        }
    }
}

/// Convenience: push a trace entry with PID 0 (kernel context).
#[allow(dead_code)]
pub fn trace_kernel(label: &[u8]) {
    trace_push(0, label);
}

/// Snapshot all trace entries under the lock, then format without holding it.
pub fn trace_read() -> String {
    // Snapshot under the lock — just copy the entries we need
    let snapshot: Vec<TraceEntry>;
    let start: usize;
    {
        let ring = TRACE_RING.lock();
        if ring.count == 0 {
            return String::from("(no trace entries)\n");
        }
        let s = if ring.count < TRACE_CAPACITY { 0 } else { ring.head };
        let count = ring.count;
        let mut v = Vec::with_capacity(count);
        for i in 0..count {
            let idx = (s + i) % TRACE_CAPACITY;
            v.push(ring.entries[idx]);
        }
        snapshot = v;
        start = 0;
    }
    // Lock released — format at leisure
    let _ = start;
    let mut out = String::new();
    for e in snapshot.iter() {
        let label = core::str::from_utf8(&e.label[..e.label_len as usize]).unwrap_or("???");
        let _ = writeln!(out, "{}: pid {} hit {}", e.timestamp, e.pid, label);
    }
    out
}

/// Clear all trace entries.
pub fn trace_clear() {
    let mut ring = TRACE_RING.lock();
    ring.head = 0;
    ring.count = 0;
}
