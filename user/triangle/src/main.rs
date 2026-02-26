extern crate rvos_rt;

use rvos::raw;
use rvos_proto::window::WindowEvent;
use rvos_gfx::framebuffer::Framebuffer;
use rvos_gfx::shapes;
use rvos_gfx::text;

fn main() {
    println!("[triangle] starting");

    let mut win = rvos::Window::create(400, 300).expect("[triangle] window creation failed");

    println!("[triangle] window ready ({}x{}, stride={})", win.width(), win.height(), win.stride());

    // Draw into back buffer
    let (width, height, stride) = (win.width(), win.height(), win.stride());
    let mut fb = Framebuffer::new(win.back_buffer_mut(), width, height, stride);

    // Navy background
    fb.clear(0xFF001840);

    // Green triangle
    shapes::fill_triangle(&mut fb, 200, 40, 80, 240, 320, 240, 0xFF00CC44);

    // Orange overlapping triangle
    shapes::fill_triangle(&mut fb, 200, 260, 100, 80, 300, 80, 0xFFFF8800);

    // Blue outlined rectangle
    shapes::draw_rect(&mut fb, 30, 30, 340, 240, 0xFF4488FF, 2);

    // Title text
    text::draw_str(&mut fb, 120, 10, b"Triangle Demo", 0xFFFFFFFF, 0xFF001840);
    text::draw_str(&mut fb, 100, 275, b"Press ESC to close", 0xFFAAAAAA, 0xFF001840);

    // Present
    win.present_no_copy();

    println!("[triangle] frame presented, entering event loop");

    // Event loop: wait for ESC or CloseRequested
    loop {
        let mut got_event = false;
        let mut should_exit = false;
        while let Some(event) = win.event_channel().try_next_message() {
            got_event = true;
            match event {
                WindowEvent::KeyDown { code: 1 } => {
                    println!("[triangle] ESC pressed, exiting");
                    should_exit = true;
                    break;
                }
                WindowEvent::CloseRequested {} => {
                    println!("[triangle] close requested, exiting");
                    should_exit = true;
                    break;
                }
                _ => {}
            }
        }
        if should_exit { break; }

        if !got_event {
            win.poll_add();
            raw::sys_block();
        }
    }
}
