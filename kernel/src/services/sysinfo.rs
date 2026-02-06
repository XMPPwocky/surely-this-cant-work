use crate::ipc::{self, Message};
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
            match ipc::channel_recv(control_ep) {
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
            match ipc::channel_recv(client_ep) {
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
            send_process_list(client_ep, my_pid);
        } else {
            send_error(client_ep, my_pid, b"Unknown command");
        }

        // Done with this client — go back to waiting for the next one
        // (Don't close the channel; the client will close it)
    }
}

fn send_process_list(ep: usize, pid: usize) {
    let list = crate::task::process_list();
    let bytes = list.as_bytes();
    let chunk_size = 63;
    let mut offset = 0;

    while offset < bytes.len() {
        let end = (offset + chunk_size).min(bytes.len());
        let chunk = &bytes[offset..end];

        let mut msg = Message::new();
        msg.data[..chunk.len()].copy_from_slice(chunk);
        msg.len = chunk.len();
        msg.sender_pid = pid;
        let wake = ipc::channel_send(ep, msg);
        if wake != 0 { crate::task::wake_process(wake); }
        offset = end;
    }

    // Send sentinel (len=0)
    let mut sentinel = Message::new();
    sentinel.sender_pid = pid;
    let wake = ipc::channel_send(ep, sentinel);
    if wake != 0 { crate::task::wake_process(wake); }
}

fn send_error(ep: usize, pid: usize, err_msg: &[u8]) {
    let mut msg = Message::new();
    let copy_len = err_msg.len().min(64);
    msg.data[..copy_len].copy_from_slice(&err_msg[..copy_len]);
    msg.len = copy_len;
    msg.sender_pid = pid;
    let wake = ipc::channel_send(ep, msg);
    if wake != 0 { crate::task::wake_process(wake); }

    // Sentinel
    let mut sentinel = Message::new();
    sentinel.sender_pid = pid;
    let wake = ipc::channel_send(ep, sentinel);
    if wake != 0 { crate::task::wake_process(wake); }
}
