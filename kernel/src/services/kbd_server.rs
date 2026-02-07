/// Keyboard IPC server — kernel task that wraps VirtIO keyboard.
///
/// Registers as the "kbd" service. A single client (the window server)
/// connects and receives raw key events (press/release + keycode).

use crate::ipc::{self, Message};
use crate::drivers::tty;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Control endpoint for kbd service (set by kmain before spawn)
static KBD_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    KBD_CONTROL_EP.store(ep, Ordering::Relaxed);
}

// Protocol tags (server → client push)
const TAG_KEY_DOWN: u8 = 0;
const TAG_KEY_UP: u8 = 1;

pub fn kbd_server() {
    let control_ep = KBD_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register for raw keyboard wake
    tty::set_raw_kbd_wake_pid(my_pid);

    crate::println!("[kbd-server] ready");

    // Wait for a client endpoint from init (via control channel)
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

    crate::println!("[kbd-server] client connected");

    // Main loop: drain raw events, push to client
    loop {
        let mut sent_any = false;

        // Drain all available raw events
        loop {
            let event = tty::RAW_KBD_EVENTS.lock().pop();
            match event {
                Some(ev) => {
                    let tag = if ev.pressed { TAG_KEY_DOWN } else { TAG_KEY_UP };
                    let mut msg = Message::new();
                    msg.sender_pid = my_pid;
                    msg.data[0] = tag;
                    msg.data[1] = (ev.code & 0xFF) as u8;
                    msg.data[2] = (ev.code >> 8) as u8;
                    msg.len = 3;
                    match ipc::channel_send(client_ep, msg) {
                        Ok(wake) => {
                            if wake != 0 { crate::task::wake_process(wake); }
                            sent_any = true;
                        }
                        Err(ipc::SendError::QueueFull) => {
                            // Drop event if queue is full — keyboard events are
                            // best-effort; blocking here would stall the IRQ pipeline
                            break;
                        }
                        Err(_) => {
                            // Client disconnected
                            crate::println!("[kbd-server] client disconnected");
                            return;
                        }
                    }
                }
                None => break,
            }
        }

        if !sent_any {
            if !ipc::channel_is_active(client_ep) {
                crate::println!("[kbd-server] client disconnected");
                return;
            }
            // Block until next keyboard IRQ wakes us
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}
