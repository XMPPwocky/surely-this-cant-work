extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;

// Window control channel tags
const WIN_CREATE_WINDOW: u8 = 0;

// Window channel: client → server
const WIN_GET_INFO: u8 = 0;
const WIN_GET_FRAMEBUFFER: u8 = 1;
const WIN_SWAP_BUFFERS: u8 = 2;

// Window channel: server → client (replies)
const WIN_INFO_REPLY: u8 = 128;
const WIN_FB_REPLY: u8 = 129;
const WIN_SWAP_REPLY: u8 = 130;

// Window channel: server → client (events)
const WIN_KEY_DOWN: u8 = 192;
const WIN_KEY_UP: u8 = 193;

fn main() {
    println!("[winclient] starting");

    // 1. Connect to "window" service via boot channel
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // 2. Send CreateWindow request
    let req = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(WIN_CREATE_WINDOW);
        let _ = w.write_u32(0); // width (ignored, fullscreen)
        let _ = w.write_u32(0); // height (ignored, fullscreen)
    });
    raw::sys_chan_send_blocking(win_ctl, &req);

    // 3. Receive CreateWindow reply with window channel capability
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_ctl, &mut resp);
    let win_chan = resp.cap; // window channel handle

    let mut r = resp.reader();
    let _tag = r.read_u8().unwrap_or(255);
    let _win_id = r.read_u32().unwrap_or(0);
    let _width = r.read_u32().unwrap_or(0);
    let _height = r.read_u32().unwrap_or(0);

    // 4. GetInfo on window channel
    let req = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(WIN_GET_INFO);
        let _ = w.write_u32(1); // seq
    });
    raw::sys_chan_send_blocking(win_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_chan, &mut resp);
    let mut r = resp.reader();
    let _reply_tag = r.read_u8().unwrap_or(255);
    let _seq = r.read_u32().unwrap_or(0);
    let _win_id = r.read_u32().unwrap_or(0);
    let width = r.read_u32().unwrap_or(1024);
    let height = r.read_u32().unwrap_or(768);
    let stride = r.read_u32().unwrap_or(width);
    let _format = r.read_u8().unwrap_or(0);

    // 5. GetFramebuffer → receive SHM handle
    let req = Message::build(NO_CAP, |w| {
        let _ = w.write_u8(WIN_GET_FRAMEBUFFER);
        let _ = w.write_u32(2); // seq
    });
    raw::sys_chan_send_blocking(win_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_chan, &mut resp);
    let shm_handle = resp.cap;

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let fb_base = raw::sys_mmap(shm_handle, fb_size) as *mut u32;
    let pixels_per_buffer = (stride as usize) * (height as usize);

    println!("[winclient] window ready ({}x{}, stride={}, fb={:#x})", width, height, stride, fb_base as usize);

    // 7. Draw and animate
    let mut frame: u32 = 0;
    let mut current_back = 1u8; // start drawing in buffer 1

    loop {
        // Calculate back buffer offset
        let back_offset = if current_back == 0 { 0 } else { pixels_per_buffer };

        // Draw a color gradient with animation
        draw_gradient(fb_base, back_offset, width, height, stride, frame);

        // SwapBuffers
        let req = Message::build(NO_CAP, |w| {
            let _ = w.write_u8(WIN_SWAP_BUFFERS);
            let _ = w.write_u32(frame);
        });
        raw::sys_chan_send_blocking(win_chan, &req);

        // Wait for swap reply, handling any key events that arrive first
        loop {
            let mut resp = Message::new();
            raw::sys_chan_recv_blocking(win_chan, &mut resp);
            if resp.len == 0 { break; }
            match resp.data[0] {
                WIN_SWAP_REPLY => break,
                WIN_KEY_DOWN | WIN_KEY_UP => print_key_event(&resp),
                _ => {}
            }
        }

        // After swap, what was back becomes front, toggle back
        current_back = 1 - current_back;
        frame = frame.wrapping_add(1);

        // Drain any pending key events between frames
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(win_chan, &mut msg);
            if ret != 0 { break; }
            if msg.len > 0 && (msg.data[0] == WIN_KEY_DOWN || msg.data[0] == WIN_KEY_UP) {
                print_key_event(&msg);
            }
        }

        // Small delay between frames
        for _ in 0..5 {
            raw::sys_yield();
        }
    }
}

fn print_key_event(msg: &Message) {
    let mut r = msg.reader();
    let tag = r.read_u8().unwrap_or(255);
    let code = r.read_u16().unwrap_or(0);
    let action = if tag == WIN_KEY_DOWN { "down" } else { "up" };
    let name = keycode_name(code);
    println!("[winclient] key {}: {} ({})", action, name, code);
}

fn keycode_name(code: u16) -> &'static str {
    match code {
        1 => "Esc", 2 => "1", 3 => "2", 4 => "3", 5 => "4",
        6 => "5", 7 => "6", 8 => "7", 9 => "8", 10 => "9", 11 => "0",
        12 => "-", 13 => "=", 14 => "Backspace", 15 => "Tab",
        16 => "Q", 17 => "W", 18 => "E", 19 => "R", 20 => "T",
        21 => "Y", 22 => "U", 23 => "I", 24 => "O", 25 => "P",
        26 => "[", 27 => "]", 28 => "Enter", 29 => "LCtrl",
        30 => "A", 31 => "S", 32 => "D", 33 => "F", 34 => "G",
        35 => "H", 36 => "J", 37 => "K", 38 => "L", 39 => ";", 40 => "'",
        41 => "`", 42 => "LShift", 43 => "\\",
        44 => "Z", 45 => "X", 46 => "C", 47 => "V", 48 => "B",
        49 => "N", 50 => "M", 51 => ",", 52 => ".", 53 => "/",
        54 => "RShift", 56 => "LAlt", 57 => "Space", 58 => "CapsLock",
        59 => "F1", 60 => "F2", 61 => "F3", 62 => "F4",
        63 => "F5", 64 => "F6", 65 => "F7", 66 => "F8",
        67 => "F9", 68 => "F10", 87 => "F11", 88 => "F12",
        96 => "KpEnter", 97 => "RCtrl", 100 => "RAlt",
        102 => "Home", 103 => "Up", 104 => "PgUp",
        105 => "Left", 106 => "Right", 107 => "End",
        108 => "Down", 109 => "PgDn", 110 => "Insert", 111 => "Delete",
        _ => "?",
    }
}

fn draw_gradient(fb: *mut u32, offset: usize, width: u32, height: u32, stride: u32, frame: u32) {
    let w = width as usize;
    let h = height as usize;
    let s = stride as usize;
    let shift = (frame as usize) % w;

    for y in 0..h {
        for x in 0..w {
            let px = (x + shift) % w;
            // Create a rainbow gradient: map x position to hue
            let hue = ((px * 360) / w) as u16;
            let (r, g, b) = hsv_to_rgb(hue, 255, 200);

            // Add vertical brightness variation
            let vy = ((y * 255) / h) as u8;
            let r = ((r as u16 * vy as u16) / 255) as u8;
            let g = ((g as u16 * vy as u16) / 255) as u8;
            let b = ((b as u16 * vy as u16) / 255) as u8;

            // BGRA32 as u32 (little-endian): 0xAARRGGBB
            let pixel = 0xFF000000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32);
            unsafe {
                *fb.add(offset + y * s + x) = pixel;
            }
        }
    }
}

/// Simple HSV to RGB conversion (S and V are 0-255)
fn hsv_to_rgb(h: u16, s: u8, v: u8) -> (u8, u8, u8) {
    if s == 0 {
        return (v, v, v);
    }

    let h = (h % 360) as u32;
    let s = s as u32;
    let v = v as u32;

    let region = h / 60;
    let remainder = (h - region * 60) * 255 / 60;

    let p = (v * (255 - s)) / 255;
    let q = (v * (255 - (s * remainder) / 255)) / 255;
    let t = (v * (255 - (s * (255 - remainder)) / 255)) / 255;

    let (r, g, b) = match region {
        0 => (v, t, p),
        1 => (q, v, p),
        2 => (p, v, t),
        3 => (p, q, v),
        4 => (t, p, v),
        _ => (v, p, q),
    };

    (r as u8, g as u8, b as u8)
}
