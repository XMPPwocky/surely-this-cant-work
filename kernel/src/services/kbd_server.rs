/// Keyboard IPC server — kernel task that wraps VirtIO keyboard.
///
/// Registers as the "kbd" service. A single client (the window server)
/// connects and receives raw key events (press/release + keycode).

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
                    let kbd_event = if ev.pressed {
                        KbdEvent::KeyDown { code: ev.code }
                    } else {
                        KbdEvent::KeyUp { code: ev.code }
                    };
                    let mut msg = Message::new();
                    msg.sender_pid = my_pid;
                    msg.len = rvos_wire::to_bytes(&kbd_event, &mut msg.data).unwrap_or(0);
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
