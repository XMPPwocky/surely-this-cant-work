pub mod font;
pub mod framebuffer;
pub mod logo;

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

/// Draw the animated boot logo and offset the text console below it.
pub fn draw_boot_logo() {
    if let Some((fb, w, h)) = crate::drivers::virtio::gpu::framebuffer() {
        let rows_used = logo::draw_boot_logo(fb, w, h);
        let mut con = FB_CONSOLE.lock();
        con.set_row(rows_used);
    }
}

/// Keep the logo triangle spinning forever (call at shutdown).
/// Only does anything if GPU is active. Never returns.
pub fn animate_logo_forever() -> ! {
    if let Some((fb, w, h)) = crate::drivers::virtio::gpu::framebuffer() {
        logo::animate_forever(fb, w, h);
    }
    // No GPU — just halt
    loop { unsafe { core::arch::asm!("wfi"); } }
}
