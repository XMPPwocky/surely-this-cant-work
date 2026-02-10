use crate::ipc::{self, Message};
use crate::ipc::transport::KernelTransport;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::math::{MathResponse, MathHandler, math_dispatch};
use rvos_wire::NO_CAP;

static MATH_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    MATH_CONTROL_EP.store(ep, Ordering::Relaxed);
}

struct MathImpl;

impl MathHandler for MathImpl {
    fn add(&mut self, a: u32, b: u32) -> (MathResponse, usize) {
        (MathResponse { answer: a.wrapping_add(b) }, NO_CAP)
    }
    fn mul(&mut self, a: u32, b: u32) -> (MathResponse, usize) {
        (MathResponse { answer: a.wrapping_mul(b) }, NO_CAP)
    }
    fn sub(&mut self, a: u32, b: u32) -> (MathResponse, usize) {
        (MathResponse { answer: a.wrapping_sub(b) }, NO_CAP)
    }
}

/// Math service - runs as a kernel task.
/// Each iteration: wait for a client endpoint from init, serve one request, repeat.
pub fn math_service() {
    let control_ep = MATH_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();
    let mut handler = MathImpl;

    loop {
        let accepted = ipc::accept_client(control_ep, my_pid);
        let client = ipc::OwnedEndpoint::new(accepted.endpoint);
        let mut transport = KernelTransport::new(client.raw(), my_pid);

        if math_dispatch(&mut transport, &mut handler).is_err() {
            // Bad request — send error text manually
            let mut resp = Message::new();
            let err = b"bad request";
            resp.data[..err.len()].copy_from_slice(err);
            resp.len = err.len();
            resp.sender_pid = my_pid;
            let _ = ipc::channel_send_blocking(client.raw(), &resp, my_pid);
        }
        // OwnedEndpoint closes on drop at end of loop iteration
    }
}
