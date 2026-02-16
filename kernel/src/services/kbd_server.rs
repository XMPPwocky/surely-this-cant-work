//! Keyboard IPC server — kernel task that wraps VirtIO keyboard.
//!
//! Registers as the "kbd" service. A single client (the window server)
//! connects and receives raw key events (press/release + keycode).

use crate::ipc::{self, Message};
use crate::drivers::tty;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::kbd::KbdEvent;

/// Control endpoint for kbd service (set by kmain before spawn)
static KBD_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    KBD_CONTROL_EP.store(ep, Ordering::Relaxed);
}

pub fn kbd_server() {
    let control_ep = KBD_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register for raw keyboard wake
    tty::set_raw_kbd_wake_pid(my_pid);

    crate::println!("[kbd-server] ready");

    // Wait for a client endpoint from init (via control channel)
    let accepted = ipc::accept_client(control_ep, my_pid);
    let client = accepted.endpoint;
    let client_ep = client.raw();

    crate::println!("[kbd-server] client connected");

    // Main loop: drain raw events, push to client
    loop {
        let mut sent_any = false;

        // Drain all available raw events
        loop {
            let event = tty::RAW_KBD_EVENTS.lock().pop();
            match event {
                Some(ev) => {
                    let kbd_event = if ev.pressed {
                        crate::println!("[kbd] D{}", ev.code);
                        KbdEvent::KeyDown { code: ev.code }
                    } else {
                        crate::println!("[kbd] U{}", ev.code);
                        KbdEvent::KeyUp { code: ev.code }
                    };
                    let mut msg = Message::new();
                    msg.sender_pid = my_pid;
                    msg.len = rvos_wire::to_bytes(&kbd_event, &mut msg.data).unwrap_or(0);
                    match ipc::channel_send_blocking(client_ep, msg, my_pid) {
                        Ok(()) => {
                            sent_any = true;
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
