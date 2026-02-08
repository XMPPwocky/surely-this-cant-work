/// GPU IPC server — kernel task that wraps VirtIO GPU access.
///
/// Registers as the "gpu" service. A single client (the window server)
/// connects and receives the display framebuffer as a SHM capability,
/// then sends Flush commands to update rectangular regions.

use crate::ipc::{self, Message};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Control endpoint for gpu service (set by kmain before spawn)
static GPU_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    GPU_CONTROL_EP.store(ep, Ordering::Relaxed);
}

// Protocol tags
const TAG_GET_DISPLAY_INFO: u8 = 0;
const TAG_FLUSH: u8 = 1;

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
    let client_ep = ipc::accept_client(control_ep, my_pid);

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
        let tag = msg.data[0];

        match tag {
            TAG_GET_DISPLAY_INFO => {
                // Response: tag(u8) + width(u32) + height(u32) + stride(u32) + format(u8) + SHM cap
                let mut resp = Message::new();
                resp.sender_pid = my_pid;
                let mut w = rvos_wire::Writer::new(&mut resp.data);
                let _ = w.write_u8(TAG_GET_DISPLAY_INFO);
                let _ = w.write_u32(width);
                let _ = w.write_u32(height);
                let _ = w.write_u32(stride);
                let _ = w.write_u8(0); // format: BGRA32
                resp.len = w.position();
                // Attach SHM capability (RW)
                resp.cap = ipc::encode_cap_shm(shm_id, true);
                // Inc ref so the SHM stays alive when client maps it
                ipc::shm_inc_ref(shm_id);
                send_msg(client_ep, resp);
            }
            TAG_FLUSH => {
                // Request: tag(u8) + x(u32) + y(u32) + w(u32) + h(u32)
                if msg.len >= 17 {
                    let mut r = rvos_wire::Reader::new(&msg.data[1..msg.len]);
                    let x = r.read_u32().unwrap_or(0);
                    let y = r.read_u32().unwrap_or(0);
                    let fw = r.read_u32().unwrap_or(width);
                    let fh = r.read_u32().unwrap_or(height);
                    crate::drivers::virtio::gpu::flush_rect(x, y, fw, fh);
                } else {
                    // Full flush if no rect specified
                    crate::drivers::virtio::gpu::flush();
                }
                // Response: tag(u8) + ok(u8)
                let mut resp = Message::new();
                resp.sender_pid = my_pid;
                resp.data[0] = TAG_FLUSH;
                resp.data[1] = 0; // ok
                resp.len = 2;
                send_msg(client_ep, resp);
            }
            _ => {
                // Unknown tag, ignore
            }
        }
    }
}

fn send_msg(ep: usize, msg: Message) {
    let my_pid = crate::task::current_pid();
    let _ = ipc::channel_send_blocking(ep, &msg, my_pid);
}
