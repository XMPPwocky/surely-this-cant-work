extern crate rvos_rt;

use rvos::raw::{self};
use rvos::UserTransport;
use rvos::Channel;
use rvos::rvos_wire;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowEvent, WindowClient,
};

fn main() {
    println!("[winclient] starting");

    // 1. Connect to "window" service via boot channel
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // 2. CreateWindow handshake (returns 2 caps: request + event channels)
    let win_ctl_ch = Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
    win_ctl_ch.send(&CreateWindowRequest { width: 400, height: 300 })
        .expect("CreateWindow send");
    let (_create_resp, caps, _cap_count) = win_ctl_ch.recv_with_caps_blocking()
        .expect("CreateWindow recv");
    let req_chan = caps[0];
    let event_chan = caps[1];

    // 3. Typed WindowClient for RPC on request channel
    let mut win_client = WindowClient::new(UserTransport::new(req_chan));

    // 4. GetInfo
    let (width, height, stride) = match win_client.get_info(1) {
        Ok(WindowReply::InfoReply { width, height, stride, .. }) => (width, height, stride),
        _ => (1024, 768, 1024),
    };

    // 5. GetFramebuffer -> SHM handle
    let (_, shm) = win_client.get_framebuffer(2).expect("GetFramebuffer failed");

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let fb_base = match raw::mmap(shm.0, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => {
            println!("[winclient] ERROR: mmap failed");
            return;
        }
    };
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
        let _ = win_client.swap_buffers(frame);

        // After swap, what was back becomes front, toggle back
        current_back = 1 - current_back;
        frame = frame.wrapping_add(1);

        // Drain any pending key events from event channel between frames
        loop {
            let mut msg = rvos::Message::new();
            let ret = raw::sys_chan_recv(event_chan, &mut msg);
            if ret != 0 { break; }
            if msg.len > 0 {
                match rvos_wire::from_bytes::<WindowEvent>(&msg.data[..msg.len]) {
                    Ok(WindowEvent::KeyDown { code }) => print_key_event("down", code),
                    Ok(WindowEvent::KeyUp { code }) => print_key_event("up", code),
                    _ => {}
                }
            }
        }

        // Small delay between frames
        for _ in 0..5 {
            raw::sys_yield();
        }
    }
}

fn print_key_event(action: &str, code: u16) {
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
