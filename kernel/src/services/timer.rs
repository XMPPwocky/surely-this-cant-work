//! Timer service — kernel task that provides timed wakeups via IPC.
//!
//! Registers as the "timer" service. Clients connect and send
//! `TimerRequest::After { duration_us }` on their per-client channel;
//! the service replies with `TimerResponse::Expired` after the
//! requested duration has elapsed.
//!
//! Uses `block_with_deadline` for efficient sleeping — the scheduler
//! re-arms the SBI timer for precise wakeup when the deadline is
//! sooner than the next regular 100ms tick.

use crate::ipc::{self, Cap, Message, OwnedEndpoint};
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::timer::{TimerRequest, TimerResponse};

/// Control endpoint for timer service (set by kmain before spawn).
static TIMER_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    TIMER_CONTROL_EP.store(ep, Ordering::Relaxed);
}

/// rdtime ticks per microsecond (QEMU virt aclint-mtimer @ 10 MHz).
const TICKS_PER_US: u64 = 10;

/// Maximum number of active timer clients.
const MAX_TIMER_CLIENTS: usize = 32;

struct TimerClient {
    /// RAII endpoint for the per-client channel (None = slot free).
    ep: Option<OwnedEndpoint>,
    /// Deadline tick (0 = no pending timer).
    deadline: u64,
}

impl TimerClient {
    const fn new() -> Self {
        TimerClient { ep: None, deadline: 0 }
    }

    fn is_active(&self) -> bool {
        self.ep.is_some()
    }

    fn raw_ep(&self) -> usize {
        self.ep.as_ref().unwrap().raw()
    }

    /// Deactivate and close the channel (via RAII drop).
    fn deactivate(&mut self) {
        self.ep = None;
        self.deadline = 0;
    }
}

/// Timer service entry point.
pub fn timer_service() {
    let control_ep = TIMER_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    let mut clients = [const { TimerClient::new() }; MAX_TIMER_CLIENTS];

    crate::println!("[timer] ready");

    loop {
        let mut did_work = false;
        let now = crate::task::process::rdtime();

        // 1. Check for expired deadlines and send Expired responses
        for c in clients.iter_mut() {
            if c.is_active() && c.deadline != 0 && now >= c.deadline {
                did_work = true;
                c.deadline = 0;
                let resp = TimerResponse::Expired {};
                let mut msg = Message::new();
                msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
                msg.sender_pid = my_pid;
                match ipc::channel_send(c.raw_ep(), msg) {
                    Ok(wake) => {
                        if wake != 0 {
                            crate::task::wake_process(wake);
                        }
                    }
                    Err(_) => {
                        // Channel closed — RAII cleanup
                        c.deactivate();
                    }
                }
            }
        }

        // 2. Accept new clients from control channel (non-blocking)
        loop {
            let (msg, send_wake) = ipc::channel_recv(control_ep);
            if send_wake != 0 {
                crate::task::wake_process(send_wake);
            }
            match msg {
                Some(mut msg) => {
                    did_work = true;
                    // Extract the client endpoint from the NewConnection cap
                    if let Cap::Channel(ep) = msg.caps[0].take() {
                        let mut ep_opt = Some(ep);
                        for c in clients.iter_mut() {
                            if !c.is_active() {
                                c.ep = ep_opt.take();
                                c.deadline = 0;
                                break;
                            }
                        }
                        if ep_opt.is_some() {
                            crate::println!("[timer] no free slots, rejecting client");
                            // drop(ep_opt) → RAII closes channel
                        }
                    }
                }
                None => break,
            }
        }

        // 3. Poll all active client channels for After requests
        for c in clients.iter_mut() {
            if !c.is_active() {
                continue;
            }
            loop {
                let (msg, send_wake) = ipc::channel_recv(c.raw_ep());
                if send_wake != 0 {
                    crate::task::wake_process(send_wake);
                }
                match msg {
                    Some(msg) => {
                        did_work = true;
                        if msg.len == 0 {
                            continue;
                        }
                        match rvos_wire::from_bytes::<TimerRequest>(&msg.data[..msg.len]) {
                            Ok(TimerRequest::After { duration_us }) => {
                                let now = crate::task::process::rdtime();
                                c.deadline = now.saturating_add(duration_us.saturating_mul(TICKS_PER_US));
                            }
                            Err(_) => {}
                        }
                    }
                    None => {
                        // Check if channel is closed
                        if !ipc::channel_is_active(c.raw_ep()) {
                            c.deactivate();
                        }
                        break;
                    }
                }
            }
        }

        // 4. Sleep until the earliest deadline or new messages
        if !did_work {
            // Find earliest deadline
            let mut earliest: u64 = u64::MAX;
            for c in clients.iter() {
                if c.is_active() && c.deadline != 0 && c.deadline < earliest {
                    earliest = c.deadline;
                }
            }

            // Register all channels for poll-based wakeup
            ipc::channel_set_blocked(control_ep, my_pid);
            for c in clients.iter() {
                if c.is_active() {
                    ipc::channel_set_blocked(c.raw_ep(), my_pid);
                }
            }

            if earliest != u64::MAX {
                // Sleep until earliest deadline (precise wakeup)
                crate::task::block_with_deadline(my_pid, earliest);
            } else {
                // No pending timers — block on channels only
                crate::task::block_process(my_pid);
            }
            crate::task::schedule();
        }
    }
}
