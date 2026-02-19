//! GPU IPC server — kernel task that wraps VirtIO GPU access.
//!
//! Registers as the "gpu" service. A single client (the window server)
//! connects and receives the display framebuffer as a SHM capability,
//! then sends Flush commands to update rectangular regions.

use crate::ipc::{self, Message, Cap, OwnedEndpoint};
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::gpu::{GpuRequest, GpuResponse};

/// Control endpoint for gpu service (set by kmain before spawn)
static GPU_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    GPU_CONTROL_EP.store(ep, Ordering::Relaxed);
}

pub fn gpu_server() {
    let control_ep = GPU_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Get framebuffer physical info for SHM
    let (fb_ppn, fb_pages) = crate::drivers::virtio::gpu::framebuffer_phys()
        .expect("gpu_server: no GPU framebuffer");
    let (_fb_ptr, width, height) = crate::drivers::virtio::gpu::framebuffer()
        .expect("gpu_server: no GPU framebuffer");
    let stride = width; // pixels per row (no padding in our setup)

    // Create SHM region from the GPU framebuffer's physical pages
    let shm = ipc::shm_create(fb_ppn, fb_pages)
        .expect("gpu_server: failed to create SHM for framebuffer");

    crate::println!("[gpu-server] ready ({}x{}, {} pages, shm={:?})",
        width, height, fb_pages, shm);

    // Wait for a client endpoint from init (via control channel)
    let accepted = ipc::accept_client(control_ep, my_pid);
    let client = accepted.endpoint;

    crate::println!("[gpu-server] client connected");

    // Main loop: serve requests from the single client
    loop {
        let msg = match client.recv_blocking(my_pid) {
            Some(msg) => msg,
            None => {
                crate::println!("[gpu-server] client disconnected");
                return;
            }
        };

        if msg.len == 0 { continue; }

        let req: GpuRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
            Ok(r) => r,
            Err(_) => continue,
        };

        match req {
            GpuRequest::GetDisplayInfo {} => {
                let resp_data = GpuResponse::DisplayInfo {
                    width, height, stride, format: 0, // BGRA32
                };
                let mut resp = Message::new();
                resp.len = rvos_wire::to_bytes(&resp_data, &mut resp.data).unwrap_or(0);
                resp.sender_pid = my_pid;
                // Attach SHM capability (RW) — clone creates a new reference for the receiver
                resp.caps[0] = Cap::Shm { owned: shm.clone(), rw: true };
                resp.cap_count = 1;
                send_reply(&client, resp, my_pid);
            }
            GpuRequest::Flush { x, y, w, h } => {
                let in_bounds = x.checked_add(w).is_some_and(|xw| xw <= width)
                    && y.checked_add(h).is_some_and(|yh| yh <= height);
                if in_bounds {
                    crate::drivers::virtio::gpu::flush_rect(x, y, w, h);
                } else {
                    crate::println!("[gpu-server] flush out of bounds: {}x{}+{}+{} (display {}x{})",
                        w, h, x, y, width, height);
                }
                let resp_data = GpuResponse::FlushOk {};
                let mut resp = Message::new();
                resp.len = rvos_wire::to_bytes(&resp_data, &mut resp.data).unwrap_or(0);
                resp.sender_pid = my_pid;
                send_reply(&client, resp, my_pid);
            }
        }
    }
}

fn send_reply(ep: &OwnedEndpoint, msg: Message, pid: usize) {
    let _ = ep.send_blocking(msg, pid);
}
