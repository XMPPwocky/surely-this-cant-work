use crate::ipc::{self, Message, NO_CAP};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Control endpoint for sysinfo service (set by kmain before spawn)
static SYSINFO_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    SYSINFO_CONTROL_EP.store(ep, Ordering::Relaxed);
}

/// Sysinfo service - runs as a kernel task.
/// Waits for a client endpoint via its control channel,
/// then serves requests on that endpoint.
pub fn sysinfo_service() {
    let control_ep = SYSINFO_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Wait for client endpoint from init server
    let client_ep = loop {
        match ipc::channel_recv(control_ep) {
            Some(msg) => {
                if msg.cap != NO_CAP {
                    break msg.cap;
                }
            }
            None => {
                ipc::channel_set_blocked(control_ep, my_pid);
                crate::task::block_process(my_pid);
                crate::task::schedule();
            }
        }
    };

    crate::println!("[sysinfo] Got client endpoint {}", client_ep);

    // Main service loop: serve requests on the client channel
    loop {
        match ipc::channel_recv(client_ep) {
            Some(msg) => {
                let cmd = &msg.data[..msg.len];
                if cmd == b"PS" {
                    send_process_list(client_ep, my_pid);
                } else {
                    send_error(client_ep, my_pid, b"Unknown command");
                }
            }
            None => {
                ipc::channel_set_blocked(client_ep, my_pid);
                crate::task::block_process(my_pid);
                crate::task::schedule();
            }
        }
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
