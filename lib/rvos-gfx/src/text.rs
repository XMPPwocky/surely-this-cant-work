use crate::font::{FONT_8X16, GLYPH_WIDTH, GLYPH_HEIGHT};
use crate::framebuffer::Framebuffer;

/// Render one 8x16 glyph at pixel position (x, y) with foreground and background colors.
pub fn draw_char(fb: &mut Framebuffer, x: u32, y: u32, ch: u8, fg: u32, bg: u32) {
    let glyph_idx = if (ch as usize) < 128 { ch as usize } else { 0 };
    let glyph = &FONT_8X16[glyph_idx];
    for row in 0..GLYPH_HEIGHT {
        let bits = glyph[row as usize];
        let py = y + row;
        if py >= fb.height { break; }
        for col in 0..GLYPH_WIDTH {
            let px = x + col;
            if px >= fb.width { break; }
            let pixel = if bits & (0x80 >> col) != 0 { fg } else { bg };
            fb.pixels[(py * fb.stride + px) as usize] = pixel;
        }
    }
}

/// Render a byte string at pixel position (x, y). Returns the pixel width of the rendered text.
pub fn draw_str(fb: &mut Framebuffer, x: u32, y: u32, s: &[u8], fg: u32, bg: u32) -> u32 {
    let mut cx = x;
    for &ch in s {
        draw_char(fb, cx, y, ch, fg, bg);
        cx += GLYPH_WIDTH;
    }
    cx - x
}

/// Render text with only foreground pixels (no background overwrite) — for overlays.
pub fn draw_str_no_bg(fb: &mut Framebuffer, x: u32, y: u32, s: &[u8], fg: u32) {
    let mut cx = x;
    for &ch in s {
        let glyph_idx = if (ch as usize) < 128 { ch as usize } else { 0 };
        let glyph = &FONT_8X16[glyph_idx];
        for row in 0..GLYPH_HEIGHT {
            let bits = glyph[row as usize];
            let py = y + row;
            if py >= fb.height { break; }
            for col in 0..GLYPH_WIDTH {
                let px = cx + col;
                if px >= fb.width { break; }
                if bits & (0x80 >> col) != 0 {
                    fb.pixels[(py * fb.stride + px) as usize] = fg;
                }
            }
        }
        cx += GLYPH_WIDTH;
    }
}
