extern crate rvos_rt;

use rvos::raw;
use rvos::UserTransport;
use rvos::Channel;
use rvos::rvos_wire;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowEvent, WindowClient,
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

    // 2. CreateWindow handshake (returns 2 caps: request + event channels)
    let win_ctl_ch = Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
    win_ctl_ch.send(&CreateWindowRequest { width: WIN_W, height: WIN_H })
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
        _ => (WIN_W, WIN_H, WIN_W),
    };

    // 5. GetFramebuffer -> SHM handle
    let (_, shm) = win_client.get_framebuffer(2).expect("GetFramebuffer failed");
    let shm_handle = shm.0;

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    if shm_handle == rvos::NO_CAP {
        println!("[triangle] ERROR: no SHM capability received from window server");
        return;
    }
    let fb_base = match raw::mmap(shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => {
            println!("[triangle] ERROR: mmap failed (shm_handle={}, size={})", shm_handle, fb_size);
            return;
        }
    };
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
    let _ = win_client.swap_buffers(10);

    println!("[triangle] frame presented, entering event loop");

    // 9. Event loop: wait for ESC or CloseRequested on event channel
    loop {
        let mut msg = rvos::Message::new();
        let ret = raw::sys_chan_recv(event_chan, &mut msg);
        if ret == 2 {
            // Channel closed
            break;
        }
        if ret == 0 && msg.len > 0 {
            match rvos_wire::from_bytes::<WindowEvent>(&msg.data[..msg.len]) {
                Ok(WindowEvent::KeyDown { code }) => {
                    if code == 1 {
                        // ESC pressed
                        println!("[triangle] ESC pressed, exiting");
                        break;
                    }
                }
                Ok(WindowEvent::CloseRequested {}) => {
                    println!("[triangle] close requested, exiting");
                    break;
                }
                _ => {}
            }
            continue;
        }

        // No events — block until something arrives
        raw::sys_chan_poll_add(event_chan);
        raw::sys_block();
    }

    // Close window
    let _ = win_client.close_window();
    raw::sys_chan_close(event_chan);
}
