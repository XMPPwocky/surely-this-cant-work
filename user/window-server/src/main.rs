extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::gpu::{GpuRequest, GpuResponse};
use rvos_proto::kbd::KbdEvent;
use rvos_proto::mouse::MouseEvent;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowRequest, WindowServerMsg,
};
use rvos_gfx::framebuffer::Framebuffer;
use rvos_gfx::text;
use rvos_gfx::font::GLYPH_HEIGHT;

// --- Constants ---
const CONTROL_HANDLE: usize = 1; // window service control channel
const MAX_WINDOWS: usize = 4;

// Tablet absolute coordinate range (0..32767)
const TABLET_MAX: u32 = 32767;

// Background color (dark gray)
const BG_COLOR: u32 = 0xFF333333;

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
    channel_handle: usize,
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

    let gpu_shm_handle = resp.cap();
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

    loop {
        let mut did_work = false;

        // 1. Drain control channel
        loop {
            let mut cmsg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut cmsg);
            if ret != 0 { break; }
            did_work = true;
            let per_client_handle = cmsg.cap();
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

        // 4. Drain window channel messages
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

        // 5. Composite and flush if dirty
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
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            raw::sys_chan_poll_add(server.kbd_handle);
            raw::sys_chan_poll_add(server.mouse_handle);
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

    let (our_ep, client_ep) = raw::sys_chan_create();

    server.windows[slot] = Some(Window {
        id: win_id,
        channel_handle: our_ep,
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
    resp.set_cap(client_ep);
    raw::sys_chan_send_blocking(per_client_handle, &resp);

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

    // Forward to foreground window
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let win_event = match event {
            KbdEvent::KeyDown { code } => WindowServerMsg::KeyDown { code },
            KbdEvent::KeyUp { code } => WindowServerMsg::KeyUp { code },
        };
        let mut fwd = Message::new();
        fwd.len = rvos_wire::to_bytes(&win_event, &mut fwd.data).unwrap_or(0);
        raw::sys_chan_send_blocking(win.channel_handle, &fwd);
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
                            // Send CloseRequested to client
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

                    // Click in content area -> drag + forward (not fullscreen)
                    if !is_fs {
                        server.dragging = Some(idx);
                        server.drag_offset_x = cx - win_x;
                        server.drag_offset_y = cy - win_y;
                    }
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
        let ev = WindowServerMsg::CloseRequested {};
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(&ev, &mut msg.data).unwrap_or(0);
        raw::sys_chan_send(win.channel_handle, &msg);
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
        let local_x = (x - win.x).max(0) as u32;
        let local_y = (y - win.y - y_offset).max(0) as u32;
        let ev = WindowServerMsg::MouseMove { x: local_x, y: local_y };
        let mut fwd = Message::new();
        fwd.len = rvos_wire::to_bytes(&ev, &mut fwd.data).unwrap_or(0);
        raw::sys_chan_send(win.channel_handle, &fwd);
    }
}

fn forward_mouse_button(server: &Server, down: bool, button: u8) {
    let fg = server.foreground;
    if let Some(ref win) = server.windows[fg] {
        if !win.active { return; }
        let y_offset = if win.fullscreen { 0 } else { TITLE_BAR_HEIGHT };
        let local_x = (server.cursor_x - win.x).max(0) as u32;
        let local_y = (server.cursor_y - win.y - y_offset).max(0) as u32;
        let ev = if down {
            WindowServerMsg::MouseButtonDown { x: local_x, y: local_y, button }
        } else {
            WindowServerMsg::MouseButtonUp { x: local_x, y: local_y, button }
        };
        let mut fwd = Message::new();
        fwd.len = rvos_wire::to_bytes(&ev, &mut fwd.data).unwrap_or(0);
        raw::sys_chan_send(win.channel_handle, &fwd);
    }
}

fn mark_any_dirty(server: &mut Server) {
    let fg = server.foreground;
    if let Some(ref mut win) = server.windows[fg] {
        win.dirty = true;
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
                format: 0,
            };
            let mut resp = Message::new();
            resp.len = rvos_wire::to_bytes(&reply, &mut resp.data).unwrap_or(0);
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WindowRequest::GetFramebuffer { seq } => {
            let reply = WindowServerMsg::FbReply { seq };
            let mut resp = Message::new();
            resp.len = rvos_wire::to_bytes(&reply, &mut resp.data).unwrap_or(0);
            resp.set_cap(win.shm_handle);
            raw::sys_chan_send_blocking(win.channel_handle, &resp);
        }
        WindowRequest::SwapBuffers { seq } => {
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
            // Trigger recomposite to remove the closed window
            mark_any_dirty(server);
        }
    }
}

fn composite(server: &mut Server) {
    let fb = server.display_fb;
    let dw = server.display_width as usize;
    let dh = server.display_height as usize;
    let ds = server.display_stride as usize;

    // 1. Clear to background color
    unsafe {
        for row in 0..dh {
            let row_start = row * ds;
            for col in 0..dw {
                *fb.add(row_start + col) = BG_COLOR;
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
                    blit_window_at(fb, dw, dh, ds, win, win.x, win.y);
                } else {
                    // Blit content shifted down by title bar height
                    blit_window_at(fb, dw, dh, ds, win, win.x, win.y + TITLE_BAR_HEIGHT);
                    // Draw decorations
                    draw_decorations(fb, dw, dh, ds, win, is_fg);
                }
                win.dirty = false;
            }
        }
    }

    // 3. Draw cursor
    if server.cursor_visible {
        draw_cursor(fb, dw, dh, ds, server.cursor_x, server.cursor_y);
    }
}

/// Blit a window's front buffer at the given display position with clipping.
fn blit_window_at(display: *mut u32, dw: usize, dh: usize, ds: usize, win: &Window, dx: i32, dy: i32) {
    let ww = win.width as i32;
    let wh = win.height as i32;
    let ws = win.stride as usize;

    let front_offset = if win.front_buffer == 0 { 0 } else { ws * (win.height as usize) };

    let src_x0 = if dx < 0 { (-dx) as usize } else { 0 };
    let src_y0 = if dy < 0 { (-dy) as usize } else { 0 };
    let dst_x0 = dx.max(0) as usize;
    let dst_y0 = dy.max(0) as usize;
    let dst_x1 = ((dx + ww) as usize).min(dw);
    let dst_y1 = ((dy + wh) as usize).min(dh);

    if dst_x0 >= dst_x1 || dst_y0 >= dst_y1 { return; }

    let copy_w = dst_x1 - dst_x0;

    unsafe {
        for row in 0..(dst_y1 - dst_y0) {
            let src_row = src_y0 + row;
            let dst_row = dst_y0 + row;
            let src_ptr = win.fb_ptr.add(front_offset + src_row * ws + src_x0);
            let dst_ptr = display.add(dst_row * ds + dst_x0);
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, copy_w);
        }
    }
}

/// Draw window decorations (title bar, close button, border) directly on display fb.
fn draw_decorations(display: *mut u32, dw: usize, dh: usize, ds: usize, win: &Window, focused: bool) {
    let wx = win.x;
    let wy = win.y;
    let ww = win.width as i32;
    let total_h = win.height as i32 + TITLE_BAR_HEIGHT;

    let title_color = if focused { TITLE_BAR_FOCUSED } else { TITLE_BAR_UNFOCUSED };

    // Draw title bar background
    for row in 0..TITLE_BAR_HEIGHT {
        let dy = wy + row;
        if dy < 0 || dy >= dh as i32 { continue; }
        let x0 = wx.max(0) as usize;
        let x1 = ((wx + ww) as usize).min(dw);
        unsafe {
            for col in x0..x1 {
                *display.add(dy as usize * ds + col) = title_color;
            }
        }
    }

    // Draw title text centered vertically in title bar
    let title_y = wy + (TITLE_BAR_HEIGHT - GLYPH_HEIGHT as i32) / 2;
    let title_x = wx + 6;
    if title_y >= 0 && title_y < dh as i32 && title_x >= 0 {
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
            draw_title_text(display, dw, dh, ds, title_x, title_y, &title_buf[..6]);
        } else {
            title_buf[4] = b'0' + (id % 10) as u8;
            draw_title_text(display, dw, dh, ds, title_x, title_y, &title_buf[..5]);
        }
    }

    // Draw close button (top-right of title bar)
    let close_x = wx + ww - CLOSE_BTN_SIZE - 4;
    let close_y = wy + (TITLE_BAR_HEIGHT - CLOSE_BTN_SIZE) / 2;
    draw_close_button(display, dw, dh, ds, close_x, close_y);

    // Draw 1px border around entire decorated window
    // Top
    draw_hline(display, dw, dh, ds, wx, wy, ww, BORDER_COLOR);
    // Bottom
    draw_hline(display, dw, dh, ds, wx, wy + total_h - 1, ww, BORDER_COLOR);
    // Left
    draw_vline(display, dw, dh, ds, wx, wy, total_h, BORDER_COLOR);
    // Right
    draw_vline(display, dw, dh, ds, wx + ww - 1, wy, total_h, BORDER_COLOR);
}

fn draw_title_text(display: *mut u32, dw: usize, dh: usize, ds: usize, x: i32, y: i32, text_bytes: &[u8]) {
    if y < 0 || y + GLYPH_HEIGHT as i32 > dh as i32 || x < 0 { return; }
    // Create a temporary framebuffer view over the display
    let total = ds * dh;
    let fb_slice = unsafe { core::slice::from_raw_parts_mut(display, total) };
    let mut fb = Framebuffer::new(fb_slice, dw as u32, dh as u32, ds as u32);
    text::draw_str_no_bg(&mut fb, x as u32, y as u32, text_bytes, 0xFFFFFFFF);
}

fn draw_close_button(display: *mut u32, dw: usize, dh: usize, ds: usize, bx: i32, by: i32) {
    // Red background
    for row in 0..CLOSE_BTN_SIZE {
        let dy = by + row;
        if dy < 0 || dy >= dh as i32 { continue; }
        for col in 0..CLOSE_BTN_SIZE {
            let dx = bx + col;
            if dx < 0 || dx >= dw as i32 { continue; }
            unsafe {
                *display.add(dy as usize * ds + dx as usize) = CLOSE_BTN_BG;
            }
        }
    }

    // White X (3px inset)
    let inset = 3;
    for i in 0..(CLOSE_BTN_SIZE - 2 * inset) {
        // Diagonal \
        let x1 = bx + inset + i;
        let y1 = by + inset + i;
        if x1 >= 0 && x1 < dw as i32 && y1 >= 0 && y1 < dh as i32 {
            unsafe { *display.add(y1 as usize * ds + x1 as usize) = CLOSE_BTN_FG; }
        }
        // Diagonal /
        let x2 = bx + CLOSE_BTN_SIZE - 1 - inset - i;
        if x2 >= 0 && x2 < dw as i32 && y1 >= 0 && y1 < dh as i32 {
            unsafe { *display.add(y1 as usize * ds + x2 as usize) = CLOSE_BTN_FG; }
        }
    }
}

fn draw_hline(display: *mut u32, dw: usize, dh: usize, ds: usize, x: i32, y: i32, w: i32, color: u32) {
    if y < 0 || y >= dh as i32 { return; }
    let x0 = x.max(0) as usize;
    let x1 = ((x + w) as usize).min(dw);
    unsafe {
        for col in x0..x1 {
            *display.add(y as usize * ds + col) = color;
        }
    }
}

fn draw_vline(display: *mut u32, dw: usize, dh: usize, ds: usize, x: i32, y: i32, h: i32, color: u32) {
    if x < 0 || x >= dw as i32 { return; }
    let y0 = y.max(0) as usize;
    let y1 = ((y + h) as usize).min(dh);
    unsafe {
        for row in y0..y1 {
            *display.add(row * ds + x as usize) = color;
        }
    }
}

fn draw_cursor(display: *mut u32, dw: usize, dh: usize, ds: usize, cx: i32, cy: i32) {
    for row in 0..CURSOR_H {
        let dy = cy + row as i32;
        if dy < 0 || dy >= dh as i32 { continue; }
        let bits = CURSOR_BITMAP[row];
        for col in 0..CURSOR_W {
            let dx = cx + col as i32;
            if dx < 0 || dx >= dw as i32 { continue; }
            if bits & (1 << (15 - col)) != 0 {
                unsafe {
                    *display.add(dy as usize * ds + dx as usize) = 0xFFFFFFFF;
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
