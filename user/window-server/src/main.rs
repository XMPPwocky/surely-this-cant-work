extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::gpu::{GpuRequest, GpuResponse};
use rvos_proto::kbd::KbdEvent;
use rvos_proto::mouse::MouseEvent;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowRequest, WindowReply, WindowEvent,
};
use rvos_gfx::framebuffer::Framebuffer;
use rvos_gfx::text;
use rvos_gfx::font::GLYPH_HEIGHT;

// --- Timing ---

#[inline(always)]
fn rdtime() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

const TICKS_PER_SEC: u64 = 10_000_000; // 10 MHz RISC-V timer

// --- Constants ---
const CONTROL_HANDLE: usize = 1; // window service control channel
const MAX_WINDOWS: usize = 4;

// Tablet absolute coordinate range (0..32767)
const TABLET_MAX: u32 = 32767;

// Background color (dark gray)
const BG_COLOR: u32 = 0xFF333333;

/// Raw display surface: pointer + dimensions.
struct Display {
    ptr: *mut u32,
    w: usize,
    h: usize,
    stride: usize,
}

// Window decoration constants
const TITLE_BAR_HEIGHT: i32 = 24;
const TITLE_BAR_FOCUSED: u32 = 0xFF2266AA;
const TITLE_BAR_UNFOCUSED: u32 = 0xFF555555;
const BORDER_COLOR: u32 = 0xFF888888;
const CLOSE_BTN_SIZE: i32 = 16;
const CLOSE_BTN_BG: u32 = 0xFFCC3333;
const CLOSE_BTN_FG: u32 = 0xFFFFFFFF;

// --- Cursor bitmap (12x19, 1-bit per pixel, MSB=leftmost) ---
const CURSOR_W: usize = 12;
const CURSOR_H: usize = 19;
#[rustfmt::skip]
static CURSOR_BITMAP: [u16; CURSOR_H] = [
    0b1000_0000_0000_0000,
    0b1100_0000_0000_0000,
    0b1110_0000_0000_0000,
    0b1111_0000_0000_0000,
    0b1111_1000_0000_0000,
    0b1111_1100_0000_0000,
    0b1111_1110_0000_0000,
    0b1111_1111_0000_0000,
    0b1111_1111_1000_0000,
    0b1111_1111_1100_0000,
    0b1111_1111_1110_0000,
    0b1111_1111_1111_0000,
    0b1111_1111_0000_0000,
    0b1111_1111_0000_0000,
    0b1100_1111_0000_0000,
    0b1000_0111_1000_0000,
    0b0000_0111_1000_0000,
    0b0000_0011_1100_0000,
    0b0000_0011_1100_0000,
];

// --- State ---

struct Window {
    id: u32,
    req_channel: usize,
    event_channel: usize,
    shm_handle: usize,
    fb_ptr: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
    x: i32,
    y: i32,
    front_buffer: u8,
    dirty: bool,
    active: bool,
    fullscreen: bool,
}

struct Server {
    gpu_handle: usize,
    kbd_handle: usize,
    mouse_handle: usize,
    display_fb: *mut u32,
    display_width: u32,
    display_height: u32,
    display_stride: u32,
    windows: [Option<Window>; MAX_WINDOWS],
    foreground: usize,
    next_window_id: u32,
    cursor_x: i32,
    cursor_y: i32,
    cursor_visible: bool,
    dragging: Option<usize>,
    drag_offset_x: i32,
    drag_offset_y: i32,
    alt_held: bool,
}

/// Send a WindowEvent on the event channel (non-blocking, best-effort).
fn send_event(handle: usize, event: &WindowEvent) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(event, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send(handle, &msg);
}

/// Send a WindowEvent on the event channel (blocking).
fn send_event_blocking(handle: usize, event: &WindowEvent) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(event, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

/// Send a WindowReply on the request channel (blocking).
fn send_reply(handle: usize, reply: &WindowReply) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(reply, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

/// Send a WindowReply with a capability on the request channel (blocking).
fn send_reply_with_cap(handle: usize, reply: &WindowReply, cap: usize) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(reply, &mut msg.data).unwrap_or(0);
    msg.caps[0] = cap;
    msg.cap_count = 1;
    raw::sys_chan_send_blocking(handle, &msg);
}

fn main() {
    let gpu_handle = rvos::connect_to_service("gpu")
        .expect("failed to connect to gpu service")
        .into_raw_handle();
    let kbd_handle = rvos::connect_to_service("kbd")
        .expect("failed to connect to kbd service")
        .into_raw_handle();
    let mouse_handle = rvos::connect_to_service("mouse")
        .expect("failed to connect to mouse service")
        .into_raw_handle();

    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&GpuRequest::GetDisplayInfo {}, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(gpu_handle, &msg);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(gpu_handle, &mut resp);

    let (width, height, stride) = match rvos_wire::from_bytes::<GpuResponse>(&resp.data[..resp.len]) {
        Ok(GpuResponse::DisplayInfo { width, height, stride, .. }) => (width, height, stride),
        _ => (1024, 768, 1024),
    };

    let gpu_shm_handle = if resp.cap_count > 0 { resp.caps[0] } else { NO_CAP };
    let fb_size = (stride as usize) * (height as usize) * 4;
    let display_fb = match raw::mmap(gpu_shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => panic!("[window-srv] mmap failed for display SHM"),
    };

    let mut server = Server {
        gpu_handle,
        kbd_handle,
        mouse_handle,
        display_fb,
        display_width: width,
        display_height: height,
        display_stride: stride,
        windows: [const { None }; MAX_WINDOWS],
        foreground: 0,
        next_window_id: 1,
        cursor_x: (width / 2) as i32,
        cursor_y: (height / 2) as i32,
        cursor_visible: false,
        dragging: None,
        drag_offset_x: 0,
        drag_offset_y: 0,
        alt_held: false,
    };

    // FPS tracking
    let mut fps_frame_count: u32 = 0;
    let mut fps_composite_ticks: u64 = 0;
    let mut fps_flush_ticks: u64 = 0;
    let mut fps_last_print: u64 = rdtime();

    loop {
        let mut did_work = false;

        // 1. Drain control channel
        loop {
            let mut cmsg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut cmsg);
            if ret != 0 { break; }
            did_work = true;
            let per_client_handle = if cmsg.cap_count > 0 { cmsg.caps[0] } else { NO_CAP };
            if per_client_handle != NO_CAP {
                handle_new_client(&mut server, per_client_handle);
            }
        }

        // 2. Drain kbd events
        loop {
            let mut kmsg = Message::new();
            let ret = raw::sys_chan_recv(server.kbd_handle, &mut kmsg);
            if ret != 0 { break; }
            did_work = true;
            handle_kbd_event(&mut server, &kmsg);
        }

        // 3. Drain mouse events
        loop {
            let mut mmsg = Message::new();
            let ret = raw::sys_chan_recv(server.mouse_handle, &mut mmsg);
            if ret != 0 { break; }
            did_work = true;
            handle_mouse_event(&mut server, &mmsg);
        }

        // 4. Drain window request channel messages
        for i in 0..MAX_WINDOWS {
            let ch = match server.windows[i] {
                Some(ref win) if win.active => win.req_channel,
                _ => continue,
            };
            loop {
                let mut wmsg = Message::new();
                let ret = raw::sys_chan_recv(ch, &mut wmsg);
                if ret == 2 {
                    // ChannelClosed — client disconnected
                    did_work = true;
                    destroy_window(&mut server, i);
                    break;
                }
                if ret != 0 { break; }
                did_work = true;
                handle_window_msg(&mut server, i, &wmsg);
            }
        }

        // 5. Composite and flush if dirty
        let mut any_dirty = false;
        for i in 0..MAX_WINDOWS {
            if let Some(ref win) = server.windows[i] {
                if win.dirty { any_dirty = true; break; }
            }
        }
        if any_dirty {
            let t0 = rdtime();
            composite(&mut server);
            let t1 = rdtime();
            flush_display(&server);
            let t2 = rdtime();

            fps_frame_count += 1;
            fps_composite_ticks += t1 - t0;
            fps_flush_ticks += t2 - t1;
        }

        // Print FPS stats every second
        let now = rdtime();
        if now - fps_last_print >= TICKS_PER_SEC {
            if fps_frame_count > 0 {
                let comp_avg_us = fps_composite_ticks / (10 * fps_frame_count as u64);
                let flush_avg_us = fps_flush_ticks / (10 * fps_frame_count as u64);
                println!(
                    "[compositor] fps={} composite={}us flush={}us",
                    fps_frame_count, comp_avg_us, flush_avg_us
                );
            }
            fps_frame_count = 0;
            fps_composite_ticks = 0;
            fps_flush_ticks = 0;
            fps_last_print = now;
        }

        if !did_work {
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            raw::sys_chan_poll_add(server.kbd_handle);
            raw::sys_chan_poll_add(server.mouse_handle);
            for i in 0..MAX_WINDOWS {
                if let Some(ref win) = server.windows[i] {
                    if win.active {
                        raw::sys_chan_poll_add(win.req_channel);
                    }
                }
            }
            raw::sys_block();
        }
    }
}

fn handle_new_client(server: &mut Server, per_client_handle: usize) {
    let mut msg = Message::new();
    raw::sys_chan_recv_blocking(per_client_handle, &mut msg);

    let req = match rvos_wire::from_bytes::<CreateWindowRequest>(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => {
            raw::sys_chan_close(per_client_handle);
            return;
        }
    };

    let slot = match server.windows.iter().position(|w| w.is_none()) {
        Some(s) => s,
        None => {
            raw::sys_chan_close(per_client_handle);
            return;
        }
    };

    let fullscreen = req.width == 0 || req.height == 0;
    let (width, height, x, y) = if fullscreen {
        (server.display_width, server.display_height, 0i32, 0i32)
    } else {
        let x = 50 + (slot as i32) * 30;
        let y = 50 + (slot as i32) * 30;
        (req.width, req.height, x, y)
    };
    let stride = width;
    let win_id = server.next_window_id;
    server.next_window_id += 1;

    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let shm_handle = raw::sys_shm_create(fb_size);
    let fb_ptr = match raw::mmap(shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => {
            println!("[window-srv] ERROR: mmap failed for window SHM");
            raw::sys_chan_close(per_client_handle);
            return;
        }
    };

    unsafe {
        let total_pixels = (stride as usize) * (height as usize) * 2;
        for i in 0..total_pixels {
            *fb_ptr.add(i) = 0xFF333333;
        }
    }

    // Create request/reply channel pair
    let (our_req_ep, client_req_ep) = raw::sys_chan_create();
    // Create event channel pair
    let (our_evt_ep, client_evt_ep) = raw::sys_chan_create();

    server.windows[slot] = Some(Window {
        id: win_id,
        req_channel: our_req_ep,
        event_channel: our_evt_ep,
        shm_handle,
        fb_ptr,
        width,
        height,
        stride,
        x,
        y,
        front_buffer: 0,
        dirty: true,
        active: true,
        fullscreen,
    });

    server.foreground = slot;

    let resp_data = CreateWindowResponse {
        window_id: win_id, width, height,
    };
    let mut resp = Message::new();
    resp.len = rvos_wire::to_bytes(&resp_data, &mut resp.data).unwrap_or(0);
    // caps[0] = request channel, caps[1] = event channel
    resp.caps[0] = client_req_ep;
    resp.caps[1] = client_evt_ep;
    resp.cap_count = 2;
    raw::sys_chan_send_blocking(per_client_handle, &resp);

    // Close handles we sent as caps — sending did inc_ref, so the
    // receiver's copies are independent.  Without this, 2 handles
    // leak per window creation, eventually filling the handle table.
    raw::sys_chan_close(client_req_ep);
    raw::sys_chan_close(client_evt_ep);
    raw::sys_chan_close(per_client_handle);
}

// Linux evdev keycodes
const KEY_TAB: u16 = 15;
const KEY_LEFTALT: u16 = 56;
const KEY_RIGHTALT: u16 = 100;

fn handle_kbd_event(server: &mut Server, msg: &Message) {
    if msg.len < 1 { return; }

    let event: KbdEvent = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Track Alt key state
    match event {
        KbdEvent::KeyDown { code } if code == KEY_LEFTALT || code == KEY_RIGHTALT => {
            server.alt_held = true;
            return;
        }
        KbdEvent::KeyUp { code } if code == KEY_LEFTALT || code == KEY_RIGHTALT => {
            server.alt_held = false;
            return;
        }
        _ => {}
    }

    // Alt+Tab: cycle focus to next active window
    if server.alt_held {
        if let KbdEvent::KeyDown { code } = event {
            if code == KEY_TAB {
                cycle_focus(server);
                return;
            }
        }
    }

    // Forward to foreground window's EVENT channel
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let win_event = match event {
            KbdEvent::KeyDown { code } => WindowEvent::KeyDown { code },
            KbdEvent::KeyUp { code } => WindowEvent::KeyUp { code },
        };
        send_event_blocking(win.event_channel, &win_event);
    }
}

/// Cycle foreground to the next active window.
fn cycle_focus(server: &mut Server) {
    let start = server.foreground;
    let mut next = (start + 1) % MAX_WINDOWS;
    while next != start {
        if let Some(ref win) = server.windows[next] {
            if win.active {
                server.foreground = next;
                mark_any_dirty(server);
                return;
            }
        }
        next = (next + 1) % MAX_WINDOWS;
    }
    // No other active window — stay on current
}

fn handle_mouse_event(server: &mut Server, msg: &Message) {
    if msg.len < 1 { return; }

    let event: MouseEvent = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
        Ok(e) => e,
        Err(_) => return,
    };

    match event {
        MouseEvent::Move { abs_x, abs_y } => {
            let new_x = (abs_x as u32 * server.display_width / (TABLET_MAX + 1)) as i32;
            let new_y = (abs_y as u32 * server.display_height / (TABLET_MAX + 1)) as i32;

            server.cursor_x = new_x;
            server.cursor_y = new_y;
            server.cursor_visible = true;

            if let Some(drag_idx) = server.dragging {
                if let Some(ref mut win) = server.windows[drag_idx] {
                    win.x = new_x - server.drag_offset_x;
                    win.y = new_y - server.drag_offset_y;
                    win.dirty = true;
                }
            }

            forward_mouse_move(server, new_x, new_y);
            mark_any_dirty(server);
        }
        MouseEvent::ButtonDown { button } => {
            if button == 0 {
                let cx = server.cursor_x;
                let cy = server.cursor_y;
                if let Some(idx) = window_at(server, cx, cy) {
                    server.foreground = idx;
                    mark_any_dirty(server);

                    let win_x = server.windows[idx].as_ref().map(|w| w.x).unwrap_or(0);
                    let win_y = server.windows[idx].as_ref().map(|w| w.y).unwrap_or(0);
                    let is_fs = server.windows[idx].as_ref().map(|w| w.fullscreen).unwrap_or(false);
                    let win_w = server.windows[idx].as_ref().map(|w| w.width).unwrap_or(0) as i32;

                    if !is_fs {
                        let local_x = cx - win_x;
                        let local_y = cy - win_y;

                        // Check close button (top-right of title bar)
                        let close_x = win_w - CLOSE_BTN_SIZE - 4;
                        let close_y = (TITLE_BAR_HEIGHT - CLOSE_BTN_SIZE) / 2;
                        if local_x >= close_x && local_x < close_x + CLOSE_BTN_SIZE
                            && local_y >= close_y && local_y < close_y + CLOSE_BTN_SIZE
                        {
                            // Send CloseRequested to client on event channel
                            send_close_requested(server, idx);
                            return;
                        }

                        if local_y < TITLE_BAR_HEIGHT {
                            // Click in title bar -> drag
                            server.dragging = Some(idx);
                            server.drag_offset_x = cx - win_x;
                            server.drag_offset_y = cy - win_y;
                            return;
                        }
                    }

                    // Click in content area -> forward to client
                }
            }
            forward_mouse_button(server, true, button);
        }
        MouseEvent::ButtonUp { button } => {
            if button == 0 {
                server.dragging = None;
            }
            forward_mouse_button(server, false, button);
        }
    }
}

fn send_close_requested(server: &Server, idx: usize) {
    if let Some(ref win) = server.windows[idx] {
        if !win.active { return; }
        send_event(win.event_channel, &WindowEvent::CloseRequested {});
    }
}

/// Find the topmost window containing (x, y), accounting for title bar.
fn window_at(server: &Server, x: i32, y: i32) -> Option<usize> {
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if win.active && point_in_decorated_window(win, x, y) {
            return Some(fg);
        }
    }
    for i in (0..MAX_WINDOWS).rev() {
        if i == fg { continue; }
        if let Some(ref win) = server.windows[i] {
            if win.active && point_in_decorated_window(win, x, y) {
                return Some(i);
            }
        }
    }
    None
}

fn point_in_decorated_window(win: &Window, x: i32, y: i32) -> bool {
    let total_h = if win.fullscreen {
        win.height as i32
    } else {
        win.height as i32 + TITLE_BAR_HEIGHT
    };
    x >= win.x && x < win.x + win.width as i32
        && y >= win.y && y < win.y + total_h
}

fn forward_mouse_move(server: &Server, x: i32, y: i32) {
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let y_offset = if win.fullscreen { 0 } else { TITLE_BAR_HEIGHT };
        let local_x = (x - win.x).max(0).min(win.width as i32 - 1).max(0) as u32;
        let local_y = (y - win.y - y_offset).max(0).min(win.height as i32 - 1).max(0) as u32;
        send_event(win.event_channel, &WindowEvent::MouseMove { x: local_x, y: local_y });
    }
}

fn forward_mouse_button(server: &Server, down: bool, button: u8) {
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let y_offset = if win.fullscreen { 0 } else { TITLE_BAR_HEIGHT };
        let local_x = (server.cursor_x - win.x).max(0).min(win.width as i32 - 1).max(0) as u32;
        let local_y = (server.cursor_y - win.y - y_offset).max(0).min(win.height as i32 - 1).max(0) as u32;
        let ev = if down {
            WindowEvent::MouseButtonDown { x: local_x, y: local_y, button }
        } else {
            WindowEvent::MouseButtonUp { x: local_x, y: local_y, button }
        };
        send_event(win.event_channel, &ev);
    }
}

fn mark_any_dirty(server: &mut Server) {
    let fg = server.foreground;
    if let Some(ref mut win) = server.windows[fg] {
        win.dirty = true;
    }
}

/// Clean up a window when the client disconnects without sending CloseWindow.
fn destroy_window(server: &mut Server, slot: usize) {
    let win = match server.windows[slot].take() {
        Some(w) => w,
        None => return,
    };
    raw::sys_chan_close(win.req_channel);
    raw::sys_chan_close(win.event_channel);
    let fb = win.fb_ptr as usize;
    if fb != 0 {
        let fb_size = (win.stride as usize) * (win.height as usize) * 4 * 2;
        raw::sys_munmap(fb, fb_size);
    }
    raw::sys_chan_close(win.shm_handle);
    // If foreground was this window, pick another
    if server.foreground == slot {
        server.foreground = 0;
        for i in 0..MAX_WINDOWS {
            if server.windows[i].is_some() {
                server.foreground = i;
                break;
            }
        }
    }
    mark_any_dirty(server);
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
            let reply = WindowReply::InfoReply {
                seq,
                window_id: win.id,
                width: win.width,
                height: win.height,
                stride: win.stride,
                format: 0,
            };
            send_reply(win.req_channel, &reply);
        }
        WindowRequest::GetFramebuffer { seq } => {
            send_reply_with_cap(win.req_channel, &WindowReply::FbReply { seq }, win.shm_handle);
        }
        WindowRequest::SwapBuffers { seq } => {
            win.front_buffer = 1 - win.front_buffer;
            win.dirty = true;
            send_reply(win.req_channel, &WindowReply::SwapReply { seq, ok: 0 });
        }
        WindowRequest::CloseWindow {} => {
            let req_ch = win.req_channel;
            let evt_ch = win.event_channel;
            let shm_h = win.shm_handle;
            let fb = win.fb_ptr as usize;
            let fb_size = (win.stride as usize) * (win.height as usize) * 4 * 2;
            // Send ack before closing
            send_reply(req_ch, &WindowReply::CloseAck {});
            // Free the slot so it can be reused by new windows
            server.windows[slot] = None;
            raw::sys_chan_close(req_ch);
            raw::sys_chan_close(evt_ch);
            if fb != 0 {
                raw::sys_munmap(fb, fb_size);
            }
            raw::sys_chan_close(shm_h);
            mark_any_dirty(server);
        }
    }
}

fn composite(server: &mut Server) {
    let disp = Display {
        ptr: server.display_fb,
        w: server.display_width as usize,
        h: server.display_height as usize,
        stride: server.display_stride as usize,
    };

    // 1. Clear to background color
    unsafe {
        for row in 0..disp.h {
            let row_start = row * disp.stride;
            for col in 0..disp.w {
                *disp.ptr.add(row_start + col) = BG_COLOR;
            }
        }
    }

    // 2. Draw windows back-to-front (foreground last = on top)
    let fg = server.foreground;
    for pass in 0..2 {
        for i in 0..MAX_WINDOWS {
            let is_fg = i == fg;
            if (pass == 0 && is_fg) || (pass == 1 && !is_fg) {
                continue;
            }
            if let Some(ref mut win) = server.windows[i] {
                if !win.active || win.fb_ptr.is_null() { continue; }

                if win.fullscreen {
                    blit_window_at(&disp, win, win.x, win.y);
                } else {
                    // Blit content shifted down by title bar height
                    blit_window_at(&disp, win, win.x, win.y + TITLE_BAR_HEIGHT);
                    // Draw decorations
                    draw_decorations(&disp, win, is_fg);
                }
                win.dirty = false;
            }
        }
    }

    // 3. Draw cursor
    if server.cursor_visible {
        draw_cursor(&disp, server.cursor_x, server.cursor_y);
    }
}

/// Blit a window's front buffer at the given display position with clipping.
fn blit_window_at(disp: &Display, win: &Window, dx: i32, dy: i32) {
    let ww = win.width as i32;
    let wh = win.height as i32;
    let ws = win.stride as usize;

    let front_offset = if win.front_buffer == 0 { 0 } else { ws * (win.height as usize) };

    let src_x0 = if dx < 0 { (-dx) as usize } else { 0 };
    let src_y0 = if dy < 0 { (-dy) as usize } else { 0 };
    let dst_x0 = dx.max(0) as usize;
    let dst_y0 = dy.max(0) as usize;
    let dst_x1 = ((dx + ww) as usize).min(disp.w);
    let dst_y1 = ((dy + wh) as usize).min(disp.h);

    if dst_x0 >= dst_x1 || dst_y0 >= dst_y1 { return; }

    let copy_w = dst_x1 - dst_x0;

    unsafe {
        for row in 0..(dst_y1 - dst_y0) {
            let src_row = src_y0 + row;
            let dst_row = dst_y0 + row;
            let src_ptr = win.fb_ptr.add(front_offset + src_row * ws + src_x0);
            let dst_ptr = disp.ptr.add(dst_row * disp.stride + dst_x0);
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, copy_w);
        }
    }
}

/// Draw window decorations (title bar, close button, border) directly on display fb.
fn draw_decorations(disp: &Display, win: &Window, focused: bool) {
    let wx = win.x;
    let wy = win.y;
    let ww = win.width as i32;
    let total_h = win.height as i32 + TITLE_BAR_HEIGHT;

    let title_color = if focused { TITLE_BAR_FOCUSED } else { TITLE_BAR_UNFOCUSED };

    // Draw title bar background
    for row in 0..TITLE_BAR_HEIGHT {
        let dy = wy + row;
        if dy < 0 || dy >= disp.h as i32 { continue; }
        let x0 = wx.max(0) as usize;
        let x1 = ((wx + ww) as usize).min(disp.w);
        unsafe {
            for col in x0..x1 {
                *disp.ptr.add(dy as usize * disp.stride + col) = title_color;
            }
        }
    }

    // Draw title text centered vertically in title bar
    let title_y = wy + (TITLE_BAR_HEIGHT - GLYPH_HEIGHT as i32) / 2;
    let title_x = wx + 6;
    if title_y >= 0 && title_y < disp.h as i32 && title_x >= 0 {
        // Build "Window N" title
        let mut title_buf = [0u8; 12];
        title_buf[0] = b'W';
        title_buf[1] = b'i';
        title_buf[2] = b'n';
        title_buf[3] = b' ';
        let id = win.id;
        if id >= 10 {
            title_buf[4] = b'0' + ((id / 10) % 10) as u8;
            title_buf[5] = b'0' + (id % 10) as u8;
            draw_title_text(disp, title_x, title_y, &title_buf[..6]);
        } else {
            title_buf[4] = b'0' + (id % 10) as u8;
            draw_title_text(disp, title_x, title_y, &title_buf[..5]);
        }
    }

    // Draw close button (top-right of title bar)
    let close_x = wx + ww - CLOSE_BTN_SIZE - 4;
    let close_y = wy + (TITLE_BAR_HEIGHT - CLOSE_BTN_SIZE) / 2;
    draw_close_button(disp, close_x, close_y);

    // Draw 1px border around entire decorated window
    // Top
    draw_hline(disp, wx, wy, ww, BORDER_COLOR);
    // Bottom
    draw_hline(disp, wx, wy + total_h - 1, ww, BORDER_COLOR);
    // Left
    draw_vline(disp, wx, wy, total_h, BORDER_COLOR);
    // Right
    draw_vline(disp, wx + ww - 1, wy, total_h, BORDER_COLOR);
}

fn draw_title_text(disp: &Display, x: i32, y: i32, text_bytes: &[u8]) {
    if y < 0 || y + GLYPH_HEIGHT as i32 > disp.h as i32 || x < 0 { return; }
    // Create a temporary framebuffer view over the display
    let total = disp.stride * disp.h;
    let fb_slice = unsafe { core::slice::from_raw_parts_mut(disp.ptr, total) };
    let mut fb = Framebuffer::new(fb_slice, disp.w as u32, disp.h as u32, disp.stride as u32);
    text::draw_str_no_bg(&mut fb, x as u32, y as u32, text_bytes, 0xFFFFFFFF);
}

fn draw_close_button(disp: &Display, bx: i32, by: i32) {
    // Red background
    for row in 0..CLOSE_BTN_SIZE {
        let dy = by + row;
        if dy < 0 || dy >= disp.h as i32 { continue; }
        for col in 0..CLOSE_BTN_SIZE {
            let dx = bx + col;
            if dx < 0 || dx >= disp.w as i32 { continue; }
            unsafe {
                *disp.ptr.add(dy as usize * disp.stride + dx as usize) = CLOSE_BTN_BG;
            }
        }
    }

    // White X (3px inset)
    let inset = 3;
    for i in 0..(CLOSE_BTN_SIZE - 2 * inset) {
        // Diagonal \
        let x1 = bx + inset + i;
        let y1 = by + inset + i;
        if x1 >= 0 && x1 < disp.w as i32 && y1 >= 0 && y1 < disp.h as i32 {
            unsafe { *disp.ptr.add(y1 as usize * disp.stride + x1 as usize) = CLOSE_BTN_FG; }
        }
        // Diagonal /
        let x2 = bx + CLOSE_BTN_SIZE - 1 - inset - i;
        if x2 >= 0 && x2 < disp.w as i32 && y1 >= 0 && y1 < disp.h as i32 {
            unsafe { *disp.ptr.add(y1 as usize * disp.stride + x2 as usize) = CLOSE_BTN_FG; }
        }
    }
}

fn draw_hline(disp: &Display, x: i32, y: i32, w: i32, color: u32) {
    if y < 0 || y >= disp.h as i32 { return; }
    let x0 = x.max(0) as usize;
    let x1 = ((x + w) as usize).min(disp.w);
    unsafe {
        for col in x0..x1 {
            *disp.ptr.add(y as usize * disp.stride + col) = color;
        }
    }
}

fn draw_vline(disp: &Display, x: i32, y: i32, h: i32, color: u32) {
    if x < 0 || x >= disp.w as i32 { return; }
    let y0 = y.max(0) as usize;
    let y1 = ((y + h) as usize).min(disp.h);
    unsafe {
        for row in y0..y1 {
            *disp.ptr.add(row * disp.stride + x as usize) = color;
        }
    }
}

fn draw_cursor(disp: &Display, cx: i32, cy: i32) {
    for (row, &bits) in CURSOR_BITMAP.iter().enumerate() {
        let dy = cy + row as i32;
        if dy < 0 || dy >= disp.h as i32 { continue; }
        for col in 0..CURSOR_W {
            let dx = cx + col as i32;
            if dx < 0 || dx >= disp.w as i32 { continue; }
            if bits & (1 << (15 - col)) != 0 {
                unsafe {
                    *disp.ptr.add(dy as usize * disp.stride + dx as usize) = 0xFFFFFFFF;
                }
            }
        }
    }
}

fn flush_display(server: &Server) {
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

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(server.gpu_handle, &mut resp);
}
