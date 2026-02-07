extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire::Reader;

// --- Protocol tags ---

// GPU protocol
const GPU_GET_DISPLAY_INFO: u8 = 0;
const GPU_FLUSH: u8 = 1;

// KBD protocol (server → us)
const KBD_KEY_DOWN: u8 = 0;
const KBD_KEY_UP: u8 = 1;

// Window control channel (client → server)
const WIN_CREATE_WINDOW: u8 = 0;

// Window channel: client → server
const WIN_GET_INFO: u8 = 0;
const WIN_GET_FRAMEBUFFER: u8 = 1;
const WIN_SWAP_BUFFERS: u8 = 2;
const WIN_CLOSE_WINDOW: u8 = 3;

// Window channel: server → client (replies)
const WIN_INFO_REPLY: u8 = 128;
const WIN_FB_REPLY: u8 = 129;
const WIN_SWAP_REPLY: u8 = 130;

// Window channel: server → client (events)
const WIN_KEY_DOWN: u8 = 192;
const WIN_KEY_UP: u8 = 193;

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
    let mut msg = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(GPU_GET_DISPLAY_INFO);
    });
    raw::sys_chan_send_blocking(gpu_handle, &msg);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(gpu_handle, &mut resp);

    let mut r = resp.reader();
    let _tag = r.read_u8().unwrap_or(255);
    let width = r.read_u32().unwrap_or(1024);
    let height = r.read_u32().unwrap_or(768);
    let stride = r.read_u32().unwrap_or(width);
    let _format = r.read_u8().unwrap_or(0);

    // The response should carry an SHM capability for the framebuffer
    let gpu_shm_handle = resp.cap;

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

        // 1. Poll control channel for new client connections (routed by init)
        let mut cmsg = Message::new();
        let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut cmsg);
        if ret == 0 {
            did_work = true;
            // Init sends a routing message with cap = per-client channel handle
            let per_client_handle = cmsg.cap;
            if per_client_handle != NO_CAP {
                handle_new_client(&mut server, per_client_handle);
            }
        }

        // 2. Poll kbd channel for key events → forward to foreground window
        let mut kmsg = Message::new();
        let ret = raw::sys_chan_recv(kbd_handle, &mut kmsg);
        if ret == 0 {
            did_work = true;
            handle_kbd_event(&mut server, &kmsg);
        }

        // 3. Poll each window channel
        for i in 0..MAX_WINDOWS {
            if let Some(ref mut win) = server.windows[i] {
                if !win.active { continue; }
                let mut wmsg = Message::new();
                let ret = raw::sys_chan_recv(win.channel_handle, &mut wmsg);
                if ret == 0 {
                    did_work = true;
                    handle_window_msg(&mut server, i, &wmsg);
                }
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
            raw::sys_yield();
        }
    }
}

fn handle_new_client(server: &mut Server, per_client_handle: usize) {
    // Wait for CreateWindow on the per-client channel (blocking)
    let mut msg = Message::new();
    raw::sys_chan_recv_blocking(per_client_handle, &mut msg);

    if msg.len == 0 || msg.data[0] != WIN_CREATE_WINDOW {
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
            *fb_ptr.add(i) = 0xFF222222; // dark gray BGRA
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
    let mut resp = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(WIN_CREATE_WINDOW);
        let _ = w.write_u32(win_id);
        let _ = w.write_u32(width);
        let _ = w.write_u32(height);
    });
    // Attach the client endpoint as a capability (local handle → kernel translates on send)
    resp.cap = client_ep;
    raw::sys_chan_send_blocking(per_client_handle, &resp);

    // Close per-client channel (no longer needed after handshake)
    raw::sys_chan_close(per_client_handle);
}

fn handle_kbd_event(server: &mut Server, msg: &Message) {
    if msg.len < 3 { return; }
    let tag = msg.data[0];
    let code = (msg.data[1] as u16) | ((msg.data[2] as u16) << 8);

    // Forward to foreground window
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let win_tag = if tag == KBD_KEY_DOWN { WIN_KEY_DOWN } else { WIN_KEY_UP };
        let evt = Message::build(NO_CAP, |w| {
            let _ = w.write_u8(win_tag);
            let _ = w.write_u16(code);
        });
        // Non-blocking send: drop event if queue full
        let _ = raw::sys_chan_send(win.channel_handle, &evt);
    }
}

fn handle_window_msg(server: &mut Server, slot: usize, msg: &Message) {
    if msg.len == 0 { return; }
    let tag = msg.data[0];
    let seq = if msg.len >= 5 {
        let mut r = Reader::new(&msg.data[1..5]);
        r.read_u32().unwrap_or(0)
    } else {
        0
    };

    let win = match server.windows[slot].as_mut() {
        Some(w) => w,
        None => return,
    };

    match tag {
        WIN_GET_INFO => {
            let resp = Message::build(NO_CAP, |w| {
                let _ = w.write_u8(WIN_INFO_REPLY);
                let _ = w.write_u32(seq);
                let _ = w.write_u32(win.id);
                let _ = w.write_u32(win.width);
                let _ = w.write_u32(win.height);
                let _ = w.write_u32(win.stride);
                let _ = w.write_u8(0); // format BGRA32
            });
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WIN_GET_FRAMEBUFFER => {
            // Send SHM capability to the client
            let mut resp = Message::build(NO_CAP, |w| {
                let _ = w.write_u8(WIN_FB_REPLY);
                let _ = w.write_u32(seq);
            });
            // Attach SHM handle (kernel translates local handle -> encoded cap on send)
            resp.cap = win.shm_handle;
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WIN_SWAP_BUFFERS => {
            // Toggle front buffer
            win.front_buffer = 1 - win.front_buffer;
            win.dirty = true;

            let resp = Message::build(NO_CAP, |w| {
                let _ = w.write_u8(WIN_SWAP_REPLY);
                let _ = w.write_u32(seq);
                let _ = w.write_u8(0); // ok
            });
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WIN_CLOSE_WINDOW => {
            raw::sys_chan_close(win.channel_handle);
            win.active = false;
            // Don't unmap/free SHM yet - just mark inactive
        }
        _ => {}
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
    let msg = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(GPU_FLUSH);
        let _ = w.write_u32(0); // x
        let _ = w.write_u32(0); // y
        let _ = w.write_u32(server.display_width);
        let _ = w.write_u32(server.display_height);
    });
    raw::sys_chan_send_blocking(server.gpu_handle, &msg);

    // Wait for flush response
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(server.gpu_handle, &mut resp);
}
