use crate::ipc::{self, Message, MAX_MSG_SIZE};
use crate::mm::heap;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::sysinfo::SysinfoCommand;

/// Control endpoint for sysinfo service (set by kmain before spawn)
static SYSINFO_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    SYSINFO_CONTROL_EP.store(ep, Ordering::Relaxed);
}

/// Sysinfo service - runs as a kernel task.
/// Each iteration: wait for a client endpoint from init, serve one request, repeat.
pub fn sysinfo_service() {
    let control_ep = SYSINFO_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    loop {
        let accepted = ipc::accept_client(control_ep, my_pid);
        let client = accepted.endpoint;

        // Wait for one request from this client
        let msg = match ipc::channel_recv_blocking(client.raw(), my_pid) {
            Some(msg) => msg,
            None => continue, // client disconnected
        };

        // Deserialize command
        let cmd = match rvos_wire::from_bytes::<SysinfoCommand>(&msg.data[..msg.len]) {
            Ok(cmd) => cmd,
            Err(_) => {
                send_chunked(client.raw(), my_pid, b"Unknown command\n");
                continue;
            }
        };

        match cmd {
            SysinfoCommand::Ps {} => {
                let list = crate::task::process_list();
                send_chunked(client.raw(), my_pid, list.as_bytes());
            }
            SysinfoCommand::Memstat {} => {
                let text = format_memstat();
                send_chunked(client.raw(), my_pid, text.as_bytes());
            }
            SysinfoCommand::Trace {} => {
                let text = crate::trace::trace_read();
                send_chunked(client.raw(), my_pid, text.as_bytes());
            }
            SysinfoCommand::TraceClear {} => {
                crate::trace::trace_clear();
                send_chunked(client.raw(), my_pid, b"ok\n");
            }
        }
        // OwnedEndpoint closes on drop at end of loop iteration
    }
}

/// Send a byte slice in MAX_MSG_SIZE-sized chunks, with yield-on-full backpressure,
/// followed by a zero-length sentinel.
fn send_chunked(ep: usize, pid: usize, data: &[u8]) {
    let chunk_size = MAX_MSG_SIZE;
    let mut offset = 0;

    while offset < data.len() {
        let end = (offset + chunk_size).min(data.len());
        let chunk = &data[offset..end];

        let mut msg = Message::new();
        msg.data[..chunk.len()].copy_from_slice(chunk);
        msg.len = chunk.len();
        msg.sender_pid = pid;
        send_with_backpressure(ep, msg);
        offset = end;
    }

    // Send sentinel (len=0)
    let mut sentinel = Message::new();
    sentinel.sender_pid = pid;
    send_with_backpressure(ep, sentinel);
}

/// Format kernel heap statistics and per-process memory info.
fn format_memstat() -> String {
    let total = heap::heap_total_size();
    let (stats, count, used) = heap::heap_stats();
    let free = total.saturating_sub(used);
    let pct = ((used * 100).checked_div(total)).unwrap_or(0);

    let mut out = String::new();
    let _ = writeln!(out, "Kernel heap: {}K total, {}K used ({}%), {}K free",
        total / 1024, used / 1024, pct, free / 1024);
    let _ = writeln!(out, "  Tag     Current    Peak  Allocs");
    let _ = writeln!(out, "  ----  ---------  ------  ------");
    for s in stats.iter().take(count) {
        if s.current_bytes == 0 && s.peak_bytes == 0 && s.alloc_count == 0 {
            continue;
        }
        let name = heap::tag_to_str(s.tag);
        let name_str = core::str::from_utf8(&name).unwrap_or("????");
        let _ = writeln!(out, "  {}  {:>7}K  {:>4}K  {:>6}",
            name_str, s.current_bytes / 1024, s.peak_bytes / 1024, s.alloc_count);
    }

    let _ = writeln!(out);
    let proc_mem = crate::task::process_mem_list();
    let _ = write!(out, "Process memory:\n{}", proc_mem);
    out
}

/// Send a message, blocking if the queue is full.
fn send_with_backpressure(ep: usize, msg: Message) {
    let my_pid = crate::task::current_pid();
    let _ = ipc::channel_send_blocking(ep, msg, my_pid);
}
