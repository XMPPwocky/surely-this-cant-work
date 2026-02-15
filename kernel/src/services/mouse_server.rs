//! Mouse IPC server — kernel task that wraps VirtIO tablet/mouse.
//!
//! Registers as the "mouse" service. A single client (the window server)
//! connects and receives raw mouse events (move + button press/release).

use crate::ipc::{self, Message};
use crate::drivers::tty;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::mouse::MouseEvent;

/// Control endpoint for mouse service (set by kmain before spawn)
static MOUSE_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    MOUSE_CONTROL_EP.store(ep, Ordering::Relaxed);
}

pub fn mouse_server() {
    let control_ep = MOUSE_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register for raw mouse wake
    tty::set_raw_mouse_wake_pid(my_pid);

    crate::println!("[mouse-server] ready");

    // Wait for a client endpoint from init (via control channel)
    let accepted = ipc::accept_client(control_ep, my_pid);
    let client = ipc::OwnedEndpoint::new(accepted.endpoint);
    let client_ep = client.raw();

    crate::println!("[mouse-server] client connected");

    // Main loop: drain raw events, push to client
    loop {
        let mut sent_any = false;

        // Drain all available raw events
        loop {
            let event = tty::RAW_MOUSE_EVENTS.lock().pop();
            match event {
                Some(ev) => {
                    let mouse_event = match ev {
                        tty::RawMouseEvent::Move { abs_x, abs_y } => {
                            MouseEvent::Move { abs_x, abs_y }
                        }
                        tty::RawMouseEvent::ButtonDown { button } => {
                            MouseEvent::ButtonDown { button }
                        }
                        tty::RawMouseEvent::ButtonUp { button } => {
                            MouseEvent::ButtonUp { button }
                        }
                    };
                    let mut msg = Message::new();
                    msg.sender_pid = my_pid;
                    msg.len = rvos_wire::to_bytes(&mouse_event, &mut msg.data).unwrap_or(0);
                    match ipc::channel_send_blocking(client_ep, &msg, my_pid) {
                        Ok(()) => {
                            sent_any = true;
                        }
                        Err(_) => {
                            crate::println!("[mouse-server] client disconnected");
                            return;
                        }
                    }
                }
                None => break,
            }
        }

        if !sent_any {
            if !ipc::channel_is_active(client_ep) {
                crate::println!("[mouse-server] client disconnected");
                return;
            }
            // Block until next mouse IRQ wakes us
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}
