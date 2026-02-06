use crate::ipc::{self, Message};
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_wire::{Serialize, Deserialize, Writer, Reader, WireError};

// --- Protocol types ---

enum MathOp {
    Add(u32, u32),
    Mul(u32, u32),
    Sub(u32, u32),
}

struct MathResponse {
    answer: u32,
}

impl Serialize for MathOp {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        match self {
            MathOp::Add(a, b) => { w.write_u8(0)?; w.write_u32(*a)?; w.write_u32(*b) }
            MathOp::Mul(a, b) => { w.write_u8(1)?; w.write_u32(*a)?; w.write_u32(*b) }
            MathOp::Sub(a, b) => { w.write_u8(2)?; w.write_u32(*a)?; w.write_u32(*b) }
        }
    }
}

impl<'a> Deserialize<'a> for MathOp {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        match r.read_u8()? {
            0 => Ok(MathOp::Add(r.read_u32()?, r.read_u32()?)),
            1 => Ok(MathOp::Mul(r.read_u32()?, r.read_u32()?)),
            2 => Ok(MathOp::Sub(r.read_u32()?, r.read_u32()?)),
            t => Err(WireError::InvalidTag(t)),
        }
    }
}

impl Serialize for MathResponse {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        w.write_u32(self.answer)
    }
}

impl<'a> Deserialize<'a> for MathResponse {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        Ok(MathResponse { answer: r.read_u32()? })
    }
}

// --- Service ---

static MATH_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    MATH_CONTROL_EP.store(ep, Ordering::Relaxed);
}

/// Math service - runs as a kernel task.
/// Each iteration: wait for a client endpoint from init, serve one request, repeat.
pub fn math_service() {
    let control_ep = MATH_CONTROL_EP.load(Ordering::Relaxed);
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

        // Deserialize MathOp
        let mut reader = Reader::new(&msg.data[..msg.len]);
        let answer = match MathOp::deserialize(&mut reader) {
            Ok(MathOp::Add(a, b)) => a.wrapping_add(b),
            Ok(MathOp::Mul(a, b)) => a.wrapping_mul(b),
            Ok(MathOp::Sub(a, b)) => a.wrapping_sub(b),
            Err(_) => {
                // Send error response
                let mut resp = Message::new();
                let err = b"bad request";
                resp.data[..err.len()].copy_from_slice(err);
                resp.len = err.len();
                resp.sender_pid = my_pid;
                let wake = ipc::channel_send(client_ep, resp);
                if wake != 0 { crate::task::wake_process(wake); }
                continue;
            }
        };

        // Serialize MathResponse
        let response = MathResponse { answer };
        let mut resp = Message::new();
        let mut writer = Writer::new(&mut resp.data);
        let _ = response.serialize(&mut writer);
        resp.len = writer.position();
        resp.sender_pid = my_pid;
        let wake = ipc::channel_send(client_ep, resp);
        if wake != 0 { crate::task::wake_process(wake); }
    }
}
