//! GPU IPC server — kernel task that wraps VirtIO GPU access.
//!
//! Registers as the "gpu" service. A single client (the window server)
//! connects and receives the display framebuffer as a SHM capability,
//! then sends Flush commands to update rectangular regions.

use crate::ipc::{self, Message};
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
    let shm_id = ipc::shm_create(fb_ppn, fb_pages)
        .expect("gpu_server: failed to create SHM for framebuffer");

    crate::println!("[gpu-server] ready ({}x{}, {} pages, shm={})",
        width, height, fb_pages, shm_id);

    // Wait for a client endpoint from init (via control channel)
    let accepted = ipc::accept_client(control_ep, my_pid);
    let client_ep = accepted.endpoint;

    crate::println!("[gpu-server] client connected");

    // Main loop: serve requests from the single client
    loop {
        let msg = match ipc::channel_recv_blocking(client_ep, my_pid) {
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
                // Attach SHM capability (RW)
                resp.caps[0] = ipc::encode_cap_shm(shm_id, true);
                resp.cap_count = 1;
                // Inc ref so the SHM stays alive when client maps it
                ipc::shm_inc_ref(shm_id);
                send_msg(client_ep, resp);
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
                send_msg(client_ep, resp);
            }
        }
    }
}

fn send_msg(ep: usize, msg: Message) {
    let my_pid = crate::task::current_pid();
    let _ = ipc::channel_send_blocking(ep, &msg, my_pid);
}
