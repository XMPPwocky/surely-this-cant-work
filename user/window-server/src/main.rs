extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::gpu::{GpuRequest, GpuResponse};
use rvos_proto::kbd::KbdEvent;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowRequest, WindowServerMsg,
};

// --- Constants ---
const CONTROL_HANDLE: usize = 1; // window service control channel
const MAX_WINDOWS: usize = 4;

// --- State ---

struct Window {
    id: u32,
    channel_handle: usize,   // window channel endpoint (our side)
    shm_handle: usize,       // local SHM handle (RW)
    fb_ptr: *mut u32,        // mapped SHM address
    width: u32,
    height: u32,
    stride: u32,
    front_buffer: u8,        // 0 or 1 — which buffer the server reads from
    dirty: bool,
    active: bool,
}

struct Server {
    gpu_handle: usize,
    kbd_handle: usize,
    display_fb: *mut u32,      // mapped GPU framebuffer
    display_width: u32,
    display_height: u32,
    display_stride: u32,
    windows: [Option<Window>; MAX_WINDOWS],
    foreground: usize,
    next_window_id: u32,
}

fn main() {
    // Connect to "gpu" service via boot channel
    let gpu_handle = rvos::connect_to_service("gpu")
        .expect("failed to connect to gpu service")
        .into_raw_handle();
    // Connect to "kbd" service via boot channel
    let kbd_handle = rvos::connect_to_service("kbd")
        .expect("failed to connect to kbd service")
        .into_raw_handle();

    // Get display info from GPU server
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&GpuRequest::GetDisplayInfo {}, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(gpu_handle, &msg);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(gpu_handle, &mut resp);

    let (width, height, stride) = match rvos_wire::from_bytes::<GpuResponse>(&resp.data[..resp.len]) {
        Ok(GpuResponse::DisplayInfo { width, height, stride, .. }) => (width, height, stride),
        _ => (1024, 768, 1024),
    };

    // The response should carry an SHM capability for the framebuffer
    let gpu_shm_handle = resp.cap();

    // Map the GPU framebuffer into our address space
    let fb_size = (stride as usize) * (height as usize) * 4;
    let display_fb = raw::sys_mmap(gpu_shm_handle, fb_size) as *mut u32;

    let mut server = Server {
        gpu_handle,
        kbd_handle,
        display_fb,
        display_width: width,
        display_height: height,
        display_stride: stride,
        windows: [const { None }; MAX_WINDOWS],
        foreground: 0,
        next_window_id: 1,
    };

    // Main event loop
    loop {
        let mut did_work = false;

        // 1. Drain control channel for new client connections (routed by init)
        loop {
            let mut cmsg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut cmsg);
            if ret != 0 { break; }
            did_work = true;
            // Init sends a routing message with cap = per-client channel handle
            let per_client_handle = cmsg.cap();
            if per_client_handle != NO_CAP {
                handle_new_client(&mut server, per_client_handle);
            }
        }

        // 2. Drain ALL kbd events → forward to foreground window
        loop {
            let mut kmsg = Message::new();
            let ret = raw::sys_chan_recv(kbd_handle, &mut kmsg);
            if ret != 0 { break; }
            did_work = true;
            handle_kbd_event(&mut server, &kmsg);
        }

        // 3. Drain ALL window channel messages
        for i in 0..MAX_WINDOWS {
            let ch = match server.windows[i] {
                Some(ref win) if win.active => win.channel_handle,
                _ => continue,
            };
            loop {
                let mut wmsg = Message::new();
                let ret = raw::sys_chan_recv(ch, &mut wmsg);
                if ret != 0 { break; }
                did_work = true;
                handle_window_msg(&mut server, i, &wmsg);
            }
        }

        // 4. Composite and flush if any window is dirty
        let mut any_dirty = false;
        for i in 0..MAX_WINDOWS {
            if let Some(ref win) = server.windows[i] {
                if win.dirty { any_dirty = true; break; }
            }
        }
        if any_dirty {
            composite(&mut server);
            flush_display(&server);
        }

        if !did_work {
            // Register interest on all channels, then sleep until woken
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            raw::sys_chan_poll_add(kbd_handle);
            for i in 0..MAX_WINDOWS {
                if let Some(ref win) = server.windows[i] {
                    if win.active {
                        raw::sys_chan_poll_add(win.channel_handle);
                    }
                }
            }
            raw::sys_block();
        }
    }
}

fn handle_new_client(server: &mut Server, per_client_handle: usize) {
    // Wait for CreateWindow on the per-client channel (blocking)
    let mut msg = Message::new();
    raw::sys_chan_recv_blocking(per_client_handle, &mut msg);

    // Verify it's a CreateWindowRequest
    if rvos_wire::from_bytes::<CreateWindowRequest>(&msg.data[..msg.len]).is_err() {
        raw::sys_chan_close(per_client_handle);
        return;
    }

    // Find a free window slot
    let slot = match server.windows.iter().position(|w| w.is_none()) {
        Some(s) => s,
        None => {
            raw::sys_chan_close(per_client_handle);
            return;
        }
    };

    let width = server.display_width;
    let height = server.display_height;
    let stride = server.display_stride;
    let win_id = server.next_window_id;
    server.next_window_id += 1;

    // Create double-buffered SHM: stride * height * 4 * 2
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let shm_handle = raw::sys_shm_create(fb_size);

    // Map into our own address space (for compositing reads)
    let fb_ptr = raw::sys_mmap(shm_handle, fb_size) as *mut u32;

    // Clear both buffers to dark gray
    unsafe {
        let total_pixels = (stride as usize) * (height as usize) * 2;
        for i in 0..total_pixels {
            *fb_ptr.add(i) = 0xFF333333; // dark gray
        }
    }

    // Create channel pair for window communication
    let (our_ep, client_ep) = raw::sys_chan_create();

    server.windows[slot] = Some(Window {
        id: win_id,
        channel_handle: our_ep,
        shm_handle,
        fb_ptr,
        width,
        height,
        stride,
        front_buffer: 0,
        dirty: true,
        active: true,
    });

    // Set foreground to new window
    server.foreground = slot;

    // Reply on the per-client channel with window channel cap + window info
    let resp_data = CreateWindowResponse {
        window_id: win_id, width, height,
    };
    let mut resp = Message::new();
    resp.len = rvos_wire::to_bytes(&resp_data, &mut resp.data).unwrap_or(0);
    // Attach the client endpoint as a capability
    resp.set_cap(client_ep);
    raw::sys_chan_send_blocking(per_client_handle, &resp);

    // Close per-client channel (no longer needed after handshake)
    raw::sys_chan_close(per_client_handle);
}

fn handle_kbd_event(server: &mut Server, msg: &Message) {
    if msg.len < 1 { return; }

    let event: KbdEvent = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Convert kbd event to window event and forward to foreground window
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let win_event = match event {
            KbdEvent::KeyDown { code } => {
                println!("[winsrv] recv D{}, fwd to win {}", code, win.id);
                WindowServerMsg::KeyDown { code }
            }
            KbdEvent::KeyUp { code } => {
                println!("[winsrv] recv U{}, fwd to win {}", code, win.id);
                WindowServerMsg::KeyUp { code }
            }
        };
        let mut fwd = Message::new();
        fwd.len = rvos_wire::to_bytes(&win_event, &mut fwd.data).unwrap_or(0);
        raw::sys_chan_send_blocking(win.channel_handle, &fwd);
    }
}

fn handle_window_msg(server: &mut Server, slot: usize, msg: &Message) {
    if msg.len == 0 { return; }

    let req: WindowRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => return,
    };

    let win = match server.windows[slot].as_mut() {
        Some(w) => w,
        None => return,
    };

    match req {
        WindowRequest::GetInfo { seq } => {
            let reply = WindowServerMsg::InfoReply {
                seq,
                window_id: win.id,
                width: win.width,
                height: win.height,
                stride: win.stride,
                format: 0, // BGRA32
            };
            let mut resp = Message::new();
            resp.len = rvos_wire::to_bytes(&reply, &mut resp.data).unwrap_or(0);
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WindowRequest::GetFramebuffer { seq } => {
            let reply = WindowServerMsg::FbReply { seq };
            let mut resp = Message::new();
            resp.len = rvos_wire::to_bytes(&reply, &mut resp.data).unwrap_or(0);
            // Attach SHM handle (kernel translates local handle -> encoded cap on send)
            resp.set_cap(win.shm_handle);
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WindowRequest::SwapBuffers { seq } => {
            // Toggle front buffer
            win.front_buffer = 1 - win.front_buffer;
            win.dirty = true;

            let reply = WindowServerMsg::SwapReply { seq, ok: 0 };
            let mut resp = Message::new();
            resp.len = rvos_wire::to_bytes(&reply, &mut resp.data).unwrap_or(0);
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WindowRequest::CloseWindow {} => {
            raw::sys_chan_close(win.channel_handle);
            win.active = false;
            // Don't unmap/free SHM yet - just mark inactive
        }
    }
}

fn composite(server: &mut Server) {
    // For now: just copy the foreground window's front buffer to the display framebuffer.
    // In the future, this would iterate windows front-to-back with clipping.

    let fb = server.display_fb;
    let stride = server.display_stride as usize;
    let height = server.display_height as usize;
    let total_pixels = stride * height;

    // Start with black background
    unsafe {
        for i in 0..total_pixels {
            *fb.add(i) = 0xFF000000; // black
        }
    }

    // Composite foreground window
    let fg = server.foreground;
    if let Some(ref mut win) = server.windows[fg] {
        if win.active && !win.fb_ptr.is_null() {
            let front_offset = if win.front_buffer == 0 {
                0
            } else {
                (win.stride as usize) * (win.height as usize)
            };

            unsafe {
                let src = win.fb_ptr.add(front_offset);
                let copy_pixels = total_pixels.min(
                    (win.stride as usize) * (win.height as usize)
                );
                core::ptr::copy_nonoverlapping(src, fb, copy_pixels);
            }

            win.dirty = false;
        }
    }
}

fn flush_display(server: &Server) {
    // Send flush command to GPU server
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &GpuRequest::Flush {
            x: 0, y: 0,
            w: server.display_width,
            h: server.display_height,
        },
        &mut msg.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(server.gpu_handle, &msg);

    // Wait for flush response
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(server.gpu_handle, &mut resp);
}
