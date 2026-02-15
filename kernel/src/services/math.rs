use crate::ipc;
use crate::ipc::transport::KernelTransport;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::math::{MathResponse, MathHandler, math_dispatch};

static MATH_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    MATH_CONTROL_EP.store(ep, Ordering::Relaxed);
}

struct MathImpl;

impl MathHandler for MathImpl {
    fn add(&mut self, a: u32, b: u32) -> MathResponse {
        MathResponse { answer: a.wrapping_add(b) }
    }
    fn mul(&mut self, a: u32, b: u32) -> MathResponse {
        MathResponse { answer: a.wrapping_mul(b) }
    }
    fn sub(&mut self, a: u32, b: u32) -> MathResponse {
        MathResponse { answer: a.wrapping_sub(b) }
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

        // On bad request, math_dispatch returns Err and we let the
        // OwnedEndpoint close the channel — the client sees ChannelClosed.
        let _ = math_dispatch(&mut transport, &mut handler);
        // OwnedEndpoint closes on drop at end of loop iteration
    }
}
