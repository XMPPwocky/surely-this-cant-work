/// Framebuffer console: renders text on the VirtIO GPU framebuffer.
///
/// Uses an 8x16 bitmap font. Supports a Y offset so a logo banner
/// at the top is preserved when the text area scrolls.

use core::fmt;
use super::font::{FONT, FONT_WIDTH, FONT_HEIGHT};

pub struct FbConsole {
    fb: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
    col: u32,
    row: u32,
    cols: u32,
    rows: u32,
    /// Pixel Y offset where the text area starts (below the logo).
    y_offset: u32,
    fg: u32,
    bg: u32,
}

unsafe impl Send for FbConsole {}

impl FbConsole {
    pub const fn new() -> Self {
        FbConsole {
            fb: core::ptr::null_mut(),
            width: 0,
            height: 0,
            stride: 0,
            col: 0,
            row: 0,
            cols: 0,
            rows: 0,
            y_offset: 0,
            fg: 0x00FFFFFF,   // white
            bg: 0x00000000,   // black
        }
    }

    /// Initialise with a framebuffer. Returns false if fb is null.
    pub fn init(&mut self, fb: *mut u32, width: u32, height: u32) -> bool {
        if fb.is_null() || width == 0 || height == 0 {
            return false;
        }
        self.fb = fb;
        self.width = width;
        self.height = height;
        self.stride = width;
        self.col = 0;
        self.row = 0;
        self.y_offset = 0;
        self.cols = width / FONT_WIDTH;
        self.rows = height / FONT_HEIGHT;
        true
    }

    pub fn is_active(&self) -> bool {
        !self.fb.is_null()
    }

    /// Set a pixel Y offset for the text area (e.g. below a logo banner).
    /// Text rows and scrolling are confined to the area below this offset.
    pub fn set_row(&mut self, text_row: u32) {
        let pixel_offset = text_row * FONT_HEIGHT;
        self.y_offset = pixel_offset.min(self.height);
        self.rows = (self.height - self.y_offset) / FONT_HEIGHT;
        self.row = 0;
        self.col = 0;
    }

    /// Render a character glyph at character cell (cx, cy) within the text area.
    fn put_char(&self, cx: u32, cy: u32, ch: u8) {
        let glyph_idx = if (ch as usize) < 128 { ch as usize } else { 0 };
        let glyph = &FONT[glyph_idx];
        let px = cx * FONT_WIDTH;
        let py = self.y_offset + cy * FONT_HEIGHT;

        for row in 0..FONT_HEIGHT {
            let bits = glyph[row as usize];
            let y = py + row;
            if y >= self.height {
                break;
            }
            for col in 0..FONT_WIDTH {
                let x = px + col;
                if x >= self.width {
                    break;
                }
                let pixel = if bits & (0x80 >> col) != 0 {
                    self.fg
                } else {
                    self.bg
                };
                let offset = (y * self.stride + x) as isize;
                unsafe {
                    self.fb.offset(offset).write_volatile(pixel);
                }
            }
        }
    }

    /// Write one character at the cursor position and advance.
    pub fn write_char(&mut self, ch: u8) {
        match ch {
            b'\n' => {
                self.col = 0;
                self.row += 1;
                if self.row >= self.rows {
                    self.scroll_up();
                    self.row = self.rows - 1;
                }
            }
            b'\r' => {
                self.col = 0;
            }
            b'\t' => {
                let next = (self.col + 8) & !7;
                while self.col < next && self.col < self.cols {
                    self.put_char(self.col, self.row, b' ');
                    self.col += 1;
                }
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows {
                        self.scroll_up();
                        self.row = self.rows - 1;
                    }
                }
            }
            ch => {
                self.put_char(self.col, self.row, ch);
                self.col += 1;
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows {
                        self.scroll_up();
                        self.row = self.rows - 1;
                    }
                }
            }
        }
    }

    /// Scroll the text area up by one text row, preserving the logo above y_offset.
    fn scroll_up(&self) {
        let font_row_pixels = (self.stride * FONT_HEIGHT) as usize;
        let text_start = (self.y_offset * self.stride) as usize;
        let text_area_pixels = (self.stride * (self.height - self.y_offset)) as usize;
        let copy_pixels = text_area_pixels - font_row_pixels;

        unsafe {
            // Move text area up by FONT_HEIGHT pixel rows
            core::ptr::copy(
                self.fb.add(text_start + font_row_pixels),
                self.fb.add(text_start),
                copy_pixels,
            );
            // Clear the bottom text row
            core::ptr::write_bytes(
                self.fb.add(text_start + copy_pixels),
                0,
                font_row_pixels,
            );
        }
    }
}

impl fmt::Write for FbConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_char(byte);
        }
        Ok(())
    }
}
