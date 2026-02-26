extern crate rvos_rt;

use rvos::raw;
use rvos_proto::window::WindowEvent;

/// Simple paint demo: click to draw colored dots, right-click to clear.
fn main() {
    println!("[winclient] starting — paint demo (left-click=draw, right-click=clear)");

    let mut win = rvos::Window::create(400, 300).expect("[winclient] window creation failed");

    println!("[winclient] window ready ({}x{}, stride={})", win.width(), win.height(), win.stride());

    let fb = Framebuf {
        base: win.fb_base(),
        pixels_per_buffer: win.pixels_per_buffer(),
        stride: win.stride(),
        width: win.width(),
        height: win.height(),
    };

    let mut color_idx: u8 = 0;
    let mut mouse_down = false;
    let mut need_present;

    // Clear to dark background
    clear_fb(&fb, 0xFF1A1A2E);

    // Initial present
    win.present();
    need_present = false;

    loop {
        // Drain all pending events
        let mut got_event = false;
        while let Some(event) = win.event_channel().try_next_message() {
            got_event = true;

            match event {
                WindowEvent::MouseButtonDown { x, y, button } => {
                    if button == 0 {
                        mouse_down = true;
                        let color = palette(color_idx);
                        draw_dot(&fb, x, y, 6, color);
                        need_present = true;
                    } else if button == 1 {
                        clear_fb(&fb, 0xFF1A1A2E);
                        color_idx = color_idx.wrapping_add(1);
                        need_present = true;
                    }
                }
                WindowEvent::MouseButtonUp { button, .. } => {
                    if button == 0 {
                        mouse_down = false;
                        color_idx = color_idx.wrapping_add(1);
                    }
                }
                WindowEvent::MouseMove { x, y } => {
                    if mouse_down {
                        let color = palette(color_idx);
                        draw_dot(&fb, x, y, 6, color);
                    }
                    draw_crosshair(&fb, win.current_back(), x, y);
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

        if need_present {
            win.present();
            need_present = false;
        }

        if !got_event {
            win.poll_add();
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
fn clear_fb(fb: &Framebuf, color: u32) {
    let s = fb.stride as usize;
    let w = fb.width as usize;
    let h = fb.height as usize;
    for y in 0..h {
        for x in 0..w {
            let idx = y * s + x;
            unsafe {
                *fb.base.add(idx) = color;
                *fb.base.add(fb.pixels_per_buffer + idx) = color;
            }
        }
    }
}
