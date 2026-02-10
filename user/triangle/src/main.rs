extern crate rvos_rt;

use rvos::raw;
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowRequest, WindowServerMsg,
};
use rvos_gfx::framebuffer::Framebuffer;
use rvos_gfx::shapes;
use rvos_gfx::text;

const WIN_W: u32 = 400;
const WIN_H: u32 = 300;

fn main() {
    println!("[triangle] starting");

    // 1. Connect to "window" service via boot channel
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // 2. Send CreateWindow request
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &CreateWindowRequest { width: WIN_W, height: WIN_H },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_ctl, &req);

    // 3. Receive CreateWindow reply with window channel capability
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_ctl, &mut resp);
    let win_chan = resp.cap();
    let _create_resp = rvos_wire::from_bytes::<CreateWindowResponse>(&resp.data[..resp.len]);

    // 4. GetInfo on window channel
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::GetInfo { seq: 1 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_chan, &mut resp);
    let (width, height, stride) = match rvos_wire::from_bytes::<WindowServerMsg>(&resp.data[..resp.len]) {
        Ok(WindowServerMsg::InfoReply { width, height, stride, .. }) => (width, height, stride),
        _ => (WIN_W, WIN_H, WIN_W),
    };

    // 5. GetFramebuffer -> receive SHM handle
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::GetFramebuffer { seq: 2 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_chan, &mut resp);
    let shm_handle = resp.cap();

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let fb_base = raw::sys_mmap(shm_handle, fb_size) as *mut u32;
    let pixels_per_buffer = (stride as usize) * (height as usize);

    println!("[triangle] window ready ({}x{}, stride={})", width, height, stride);

    // 7. Draw into back buffer (buffer 1)
    let back_offset = pixels_per_buffer;
    let fb_slice = unsafe {
        core::slice::from_raw_parts_mut(fb_base.add(back_offset), pixels_per_buffer)
    };
    let mut fb = Framebuffer::new(fb_slice, width, height, stride);

    // Navy background
    fb.clear(0xFF001840);

    // Green triangle
    shapes::fill_triangle(&mut fb,
        200, 40,    // top center
        80, 240,    // bottom left
        320, 240,   // bottom right
        0xFF00CC44,
    );

    // Orange overlapping triangle
    shapes::fill_triangle(&mut fb,
        200, 260,   // bottom center
        100, 80,    // top left
        300, 80,    // top right
        0xFFFF8800,
    );

    // Blue outlined rectangle
    shapes::draw_rect(&mut fb, 30, 30, 340, 240, 0xFF4488FF, 2);

    // Title text
    text::draw_str(&mut fb, 120, 10, b"Triangle Demo", 0xFFFFFFFF, 0xFF001840);

    // Instructions
    text::draw_str(&mut fb, 100, 275, b"Press ESC to close", 0xFFAAAAAA, 0xFF001840);

    // 8. SwapBuffers to present
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::SwapBuffers { seq: 10 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_chan, &req);

    // Wait for swap reply
    loop {
        let mut resp = Message::new();
        raw::sys_chan_recv_blocking(win_chan, &mut resp);
        if resp.len == 0 { break; }
        match rvos_wire::from_bytes::<WindowServerMsg>(&resp.data[..resp.len]) {
            Ok(WindowServerMsg::SwapReply { .. }) => break,
            _ => {}
        }
    }

    println!("[triangle] frame presented, entering event loop");

    // 9. Event loop: wait for ESC or CloseRequested
    loop {
        let mut msg = Message::new();
        let ret = raw::sys_chan_recv(win_chan, &mut msg);
        if ret == 2 {
            // Channel closed
            break;
        }
        if ret == 0 && msg.len > 0 {
            match rvos_wire::from_bytes::<WindowServerMsg>(&msg.data[..msg.len]) {
                Ok(WindowServerMsg::KeyDown { code }) => {
                    if code == 1 {
                        // ESC pressed
                        println!("[triangle] ESC pressed, exiting");
                        break;
                    }
                }
                Ok(WindowServerMsg::CloseRequested {}) => {
                    println!("[triangle] close requested, exiting");
                    break;
                }
                _ => {}
            }
            continue;
        }

        // No events — block until something arrives
        raw::sys_chan_poll_add(win_chan);
        raw::sys_block();
    }

    // Close window
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::CloseWindow {},
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send(win_chan, &req);
}
