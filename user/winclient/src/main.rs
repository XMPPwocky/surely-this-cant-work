extern crate rvos_rt;

use rvos::raw::{self};
use rvos::UserTransport;
use rvos::Channel;
use rvos::rvos_wire::Never;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowEvent, WindowClient,
};

/// Simple paint demo: click to draw colored dots, right-click to clear.
fn main() {
    println!("[winclient] starting — paint demo (left-click=draw, right-click=clear)");

    // 1. Connect to "window" service via boot channel
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // 2. CreateWindow handshake (returns embedded channel caps)
    let mut win_ctl_ch = Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
    win_ctl_ch.send(&CreateWindowRequest { width: 400, height: 300 })
        .expect("CreateWindow send");
    let create_resp = win_ctl_ch.recv_blocking()
        .expect("CreateWindow recv");
    let req_chan = create_resp.req_channel.raw();
    let event_chan = create_resp.event_channel.raw();

    // 3. Typed WindowClient for RPC on request channel
    let mut win_client = WindowClient::new(UserTransport::new(req_chan));

    // 4. GetInfo
    let (width, height, stride) = match win_client.get_info(1) {
        Ok(WindowReply::InfoReply { width, height, stride, .. }) => (width, height, stride),
        _ => (1024, 768, 1024),
    };

    // 5. GetFramebuffer -> SHM handle
    let shm_handle = match win_client.get_framebuffer(2) {
        Ok(WindowReply::FbReply { fb, .. }) => fb.0,
        _ => panic!("[winclient] GetFramebuffer failed"),
    };

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let fb_base = match raw::mmap(shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => {
            println!("[winclient] ERROR: mmap failed");
            return;
        }
    };
    let pixels_per_buffer = (stride as usize) * (height as usize);

    println!("[winclient] window ready ({}x{}, stride={})", width, height, stride);

    let fb = Framebuf { base: fb_base, pixels_per_buffer, stride, width, height };

    let mut current_back = 1u8;
    let mut swap_seq: u32 = 10;
    let mut color_idx: u8 = 0;
    let mut mouse_down = false;
    let mut need_present;

    // Clear to dark background
    clear_fb(fb_base, pixels_per_buffer, stride, width, height, 0xFF1A1A2E);

    // Initial present
    do_swap(&mut win_client, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
    need_present = false;

    // Main event loop — event-driven, no animation
    let mut events = Channel::<Never, WindowEvent>::from_raw_handle(event_chan);

    loop {
        // Drain all pending events
        let mut got_event = false;
        while let Some(event) = events.try_next_message() {
            got_event = true;

            match event {
                WindowEvent::MouseButtonDown { x, y, button } => {
                    if button == 0 {
                        // Left click: draw a dot
                        mouse_down = true;
                        let color = palette(color_idx);
                        draw_dot(&fb, x, y, 6, color);
                        need_present = true;
                    } else if button == 1 {
                        // Right click: clear canvas and cycle color
                        clear_fb(fb_base, pixels_per_buffer, stride, width, height, 0xFF1A1A2E);
                        color_idx = color_idx.wrapping_add(1);
                        need_present = true;
                    }
                }
                WindowEvent::MouseButtonUp { button, .. } => {
                    if button == 0 {
                        mouse_down = false;
                        // Cycle color after each stroke
                        color_idx = color_idx.wrapping_add(1);
                    }
                }
                WindowEvent::MouseMove { x, y } => {
                    if mouse_down {
                        // Draw while dragging
                        let color = palette(color_idx);
                        draw_dot(&fb, x, y, 6, color);
                    }
                    // Draw a small crosshair at cursor position
                    draw_crosshair(&fb, current_back, x, y);
                    need_present = true;
                }
                WindowEvent::KeyDown { code } => {
                    println!("[winclient] key down: {}", code);
                }
                WindowEvent::CloseRequested {} => {
                    println!("[winclient] close requested, exiting");
                    return;
                }
                _ => {}
            }
        }

        // Present if anything changed
        if need_present {
            do_swap(&mut win_client, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
            need_present = false;
        }

        if !got_event {
            // Block until next event
            events.poll_add();
            raw::sys_chan_poll_add(req_chan);
            raw::sys_block();
        }
    }
}

/// Shared framebuffer parameters passed to drawing helpers.
struct Framebuf {
    base: *mut u32,
    pixels_per_buffer: usize,
    stride: u32,
    width: u32,
    height: u32,
}

/// Cycle through bright colors for drawing.
fn palette(idx: u8) -> u32 {
    match idx % 8 {
        0 => 0xFFFF4444, // red
        1 => 0xFF44FF44, // green
        2 => 0xFF4488FF, // blue
        3 => 0xFFFFFF44, // yellow
        4 => 0xFFFF44FF, // magenta
        5 => 0xFF44FFFF, // cyan
        6 => 0xFFFF8844, // orange
        _ => 0xFFFFFFFF, // white
    }
}

/// Draw a filled circle at (cx, cy) with given radius and color.
/// Draws into both buffers so the dot persists across swaps.
fn draw_dot(
    fb: &Framebuf,
    cx: u32, cy: u32, radius: i32, color: u32,
) {
    let w = fb.width as i32;
    let h = fb.height as i32;
    let s = fb.stride as usize;
    let icx = cx as i32;
    let icy = cy as i32;

    for dy in -radius..=radius {
        for dx in -radius..=radius {
            if dx * dx + dy * dy > radius * radius { continue; }
            let px = icx + dx;
            let py = icy + dy;
            if px < 0 || px >= w || py < 0 || py >= h { continue; }
            let idx = py as usize * s + px as usize;
            unsafe {
                // Draw into both buffers so dots persist
                *fb.base.add(idx) = color;
                *fb.base.add(fb.pixels_per_buffer + idx) = color;
            }
        }
    }
}

/// Draw a small crosshair at cursor position (into current back buffer only).
fn draw_crosshair(
    fb: &Framebuf, current_back: u8,
    cx: u32, cy: u32,
) {
    let w = fb.width as i32;
    let h = fb.height as i32;
    let s = fb.stride as usize;
    let back_offset = if current_back == 0 { 0 } else { fb.pixels_per_buffer };
    let icx = cx as i32;
    let icy = cy as i32;
    let color: u32 = 0x80FFFFFF; // semi-transparent white

    // Horizontal line (5 pixels)
    for dx in -2i32..=2 {
        let px = icx + dx;
        if px >= 0 && px < w && icy >= 0 && icy < h {
            unsafe { *fb.base.add(back_offset + icy as usize * s + px as usize) = color; }
        }
    }
    // Vertical line (5 pixels)
    for dy in -2i32..=2 {
        let py = icy + dy;
        if icx >= 0 && icx < w && py >= 0 && py < h {
            unsafe { *fb.base.add(back_offset + py as usize * s + icx as usize) = color; }
        }
    }
}

/// Clear both framebuffers to a solid color.
fn clear_fb(
    fb_base: *mut u32, pixels_per_buffer: usize,
    stride: u32, width: u32, height: u32, color: u32,
) {
    let s = stride as usize;
    let w = width as usize;
    let h = height as usize;
    for y in 0..h {
        for x in 0..w {
            let idx = y * s + x;
            unsafe {
                *fb_base.add(idx) = color;
                *fb_base.add(pixels_per_buffer + idx) = color;
            }
        }
    }
}

/// Swap buffers, wait for swap reply, then copy front→new-back.
fn do_swap(
    window_client: &mut WindowClient<UserTransport>,
    seq: &mut u32,
    fb_base: *mut u32,
    pixels_per_buffer: usize,
    current_back: &mut u8,
) {
    let _ = window_client.swap_buffers(*seq);
    *seq = seq.wrapping_add(1);

    // Toggle back buffer
    *current_back = 1 - *current_back;

    // Copy front (what was just presented) → new back buffer
    let front_offset = if *current_back == 0 { pixels_per_buffer } else { 0 };
    let back_offset = if *current_back == 0 { 0 } else { pixels_per_buffer };
    unsafe {
        core::ptr::copy_nonoverlapping(
            fb_base.add(front_offset),
            fb_base.add(back_offset),
            pixels_per_buffer,
        );
    }
}
