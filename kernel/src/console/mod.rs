pub mod font;
pub mod framebuffer;

use crate::sync::SpinLock;
use framebuffer::FbConsole;

pub static FB_CONSOLE: SpinLock<FbConsole> = SpinLock::new(FbConsole::new());

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    crate::drivers::uart::UART.lock().write_fmt(args).unwrap();
    let mut fb = FB_CONSOLE.lock();
    if fb.is_active() {
        let _ = fb.write_fmt(args);
    }
}

/// Initialise the framebuffer console (called after GPU init).
pub fn init_fb(fb: *mut u32, width: u32, height: u32) {
    let mut con = FB_CONSOLE.lock();
    con.init(fb, width, height);
}

/// Flush the framebuffer to the GPU display.
pub fn fb_flush() {
    crate::drivers::virtio::gpu::flush();
}
