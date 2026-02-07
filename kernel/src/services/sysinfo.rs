use crate::ipc::{self, Message, MAX_MSG_SIZE};
use core::sync::atomic::{AtomicUsize, Ordering};

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
        // Wait for a new client endpoint from init server
        let client_ep = loop {
            let (msg, send_wake) = ipc::channel_recv(control_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            match msg {
                Some(msg) => {
                    if let Some(ep) = ipc::decode_cap_channel(msg.cap) {
                        break ep;
                    }
                }
                None => {
                    ipc::channel_set_blocked(control_ep, my_pid);
                    crate::task::block_process(my_pid);
                    crate::task::schedule();
                }
            }
        };

        // Wait for one request from this client
        let msg = loop {
            let (msg, send_wake) = ipc::channel_recv(client_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            match msg {
                Some(msg) => break msg,
                None => {
                    ipc::channel_set_blocked(client_ep, my_pid);
                    crate::task::block_process(my_pid);
                    crate::task::schedule();
                }
            }
        };

        // Handle the request
        let cmd = &msg.data[..msg.len];
        if cmd == b"PS" {
            let list = crate::task::process_list();
            send_chunked(client_ep, my_pid, list.as_bytes());
        } else if cmd == b"TRACE" {
            let text = crate::trace::trace_read();
            send_chunked(client_ep, my_pid, text.as_bytes());
        } else if cmd == b"TRACECLR" {
            crate::trace::trace_clear();
            send_chunked(client_ep, my_pid, b"ok\n");
        } else {
            send_chunked(client_ep, my_pid, b"Unknown command\n");
        }

        // Done with this client — go back to waiting for the next one
        // (Don't close the channel; the client will close it)
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

/// Send a message, blocking if the queue is full.
fn send_with_backpressure(ep: usize, msg: Message) {
    let my_pid = crate::task::current_pid();
    loop {
        match ipc::channel_send(ep, msg.clone()) {
            Ok(wake) => {
                if wake != 0 {
                    crate::task::wake_process(wake);
                }
                return;
            }
            Err(ipc::SendError::QueueFull) => {
                if !ipc::channel_is_active(ep) { return; }
                ipc::channel_set_send_blocked(ep, my_pid);
                crate::task::block_process(my_pid);
                crate::task::schedule();
            }
            Err(_) => return, // channel closed, give up
        }
    }
}
