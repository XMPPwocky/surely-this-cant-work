/// Graphical boot logo with animated spinning triangles.
///
/// Draws a colorful logo banner with:
/// - Gradient-filled spinning triangle (color-interpolated vertices)
/// - Counter-rotating inner triangle
/// - Large scaled "rvOS" text
/// - Rainbow gradient bar

use super::font::FONT;

// --- Sin/cos lookup (64 entries, values scaled by 256) ---

const SIN_TABLE: [i32; 64] = [
    0, 25, 50, 74, 98, 121, 142, 162,
    181, 198, 213, 226, 237, 245, 251, 255,
    256, 255, 251, 245, 237, 226, 213, 198,
    181, 162, 142, 121, 98, 74, 50, 25,
    0, -25, -50, -74, -98, -121, -142, -162,
    -181, -198, -213, -226, -237, -245, -251, -255,
    -256, -255, -251, -245, -237, -226, -213, -198,
    -181, -162, -142, -121, -98, -74, -50, -25,
];

fn sin256(step: usize) -> i32 { SIN_TABLE[step % 64] }
fn cos256(step: usize) -> i32 { SIN_TABLE[(step + 16) % 64] }

// --- Color helpers ---

const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

fn hue_to_rgb(hue: u32) -> u32 {
    let h = hue % 256;
    let sector = h / 43;
    let f = ((h % 43) * 6).min(255);
    match sector {
        0 => rgb(255, f as u8, 0),
        1 => rgb((255 - f) as u8, 255, 0),
        2 => rgb(0, 255, f as u8),
        3 => rgb(0, (255 - f) as u8, 255),
        4 => rgb(f as u8, 0, 255),
        _ => rgb(255, 0, (255 - f) as u8),
    }
}

// --- Drawing primitives ---

struct Canvas {
    fb: *mut u32,
    stride: u32,
    width: u32,
    height: u32,
}

impl Canvas {
    fn put_pixel(&self, x: i32, y: i32, color: u32) {
        if x >= 0 && y >= 0 && (x as u32) < self.width && (y as u32) < self.height {
            unsafe {
                *self.fb.add(y as usize * self.stride as usize + x as usize) = color;
            }
        }
    }

    fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        for dy in 0..h {
            for dx in 0..w {
                self.put_pixel((x + dx) as i32, (y + dy) as i32, color);
            }
        }
    }

    /// Draw a circle ring (annulus).
    fn draw_ring(&self, cx: i32, cy: i32, outer_r: i32, inner_r: i32, color: u32) {
        let or2 = outer_r * outer_r;
        let ir2 = inner_r * inner_r;
        for dy in -outer_r..=outer_r {
            for dx in -outer_r..=outer_r {
                let d2 = dx * dx + dy * dy;
                if d2 <= or2 && d2 >= ir2 {
                    self.put_pixel(cx + dx, cy + dy, color);
                }
            }
        }
    }

    /// Draw a filled triangle with per-vertex color interpolation (gradient).
    fn draw_gradient_triangle(
        &self,
        x0: i32, y0: i32, c0: u32,
        x1: i32, y1: i32, c1: u32,
        x2: i32, y2: i32, c2: u32,
    ) {
        let min_x = x0.min(x1).min(x2).max(0);
        let max_x = x0.max(x1).max(x2).min(self.width as i32 - 1);
        let min_y = y0.min(y1).min(y2).max(0);
        let max_y = y0.max(y1).max(y2).min(self.height as i32 - 1);

        let det = (y1 - y2) * (x0 - x2) + (x2 - x1) * (y0 - y2);
        if det == 0 { return; }

        let (c0r, c0g, c0b) = unpack(c0);
        let (c1r, c1g, c1b) = unpack(c1);
        let (c2r, c2g, c2b) = unpack(c2);

        for py in min_y..=max_y {
            for px in min_x..=max_x {
                let w0 = (y1 - y2) * (px - x2) + (x2 - x1) * (py - y2);
                let w1 = (y2 - y0) * (px - x2) + (x0 - x2) * (py - y2);
                let w2 = det - w0 - w1;

                let inside = if det > 0 {
                    w0 >= 0 && w1 >= 0 && w2 >= 0
                } else {
                    w0 <= 0 && w1 <= 0 && w2 <= 0
                };

                if inside {
                    let (aw0, aw1, aw2, total) = if det > 0 {
                        (w0, w1, w2, det)
                    } else {
                        (-w0, -w1, -w2, -det)
                    };
                    let r = ((c0r * aw0 + c1r * aw1 + c2r * aw2) / total) as u8;
                    let g = ((c0g * aw0 + c1g * aw1 + c2g * aw2) / total) as u8;
                    let b = ((c0b * aw0 + c1b * aw1 + c2b * aw2) / total) as u8;
                    self.put_pixel(px, py, rgb(r, g, b));
                }
            }
        }
    }

    /// Draw a solid filled triangle.
    fn draw_filled_triangle(
        &self, x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32,
    ) {
        let min_x = x0.min(x1).min(x2).max(0);
        let max_x = x0.max(x1).max(x2).min(self.width as i32 - 1);
        let min_y = y0.min(y1).min(y2).max(0);
        let max_y = y0.max(y1).max(y2).min(self.height as i32 - 1);

        for py in min_y..=max_y {
            for px in min_x..=max_x {
                if pt_in_tri(px, py, x0, y0, x1, y1, x2, y2) {
                    self.put_pixel(px, py, color);
                }
            }
        }
    }

    /// Draw a character from the bitmap font, scaled up by `scale`.
    fn draw_char_scaled(&self, ch: u8, x: u32, y: u32, scale: u32, color: u32) {
        if ch as usize >= 128 { return; }
        let glyph = &FONT[ch as usize];
        for row in 0..16u32 {
            let bits = glyph[row as usize];
            for col in 0..8u32 {
                if bits & (0x80 >> col) != 0 {
                    self.fill_rect(
                        x + col * scale, y + row * scale, scale, scale, color,
                    );
                }
            }
        }
    }

    /// Draw a text string with scaled font.
    fn draw_text_scaled(&self, text: &str, x: u32, y: u32, scale: u32, color: u32) {
        let mut cx = x;
        for ch in text.bytes() {
            self.draw_char_scaled(ch, cx, y, scale, color);
            cx += 8 * scale + (scale / 2).max(1);
        }
    }
}

fn unpack(c: u32) -> (i32, i32, i32) {
    (((c >> 16) & 0xFF) as i32, ((c >> 8) & 0xFF) as i32, (c & 0xFF) as i32)
}

fn pt_in_tri(
    px: i32, py: i32,
    x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32,
) -> bool {
    let d1 = (px - x1) * (y0 - y1) - (x0 - x1) * (py - y1);
    let d2 = (px - x2) * (y1 - y2) - (x1 - x2) * (py - y2);
    let d3 = (px - x0) * (y2 - y0) - (x2 - x0) * (py - y0);
    !((d1 < 0 || d2 < 0 || d3 < 0) && (d1 > 0 || d2 > 0 || d3 > 0))
}

// --- Timing ---

fn read_time() -> u64 {
    // rdtime reads the time CSR (enabled by OpenSBI via mcounteren)
    // 10 MHz on QEMU virt
    let val: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) val); }
    val
}

fn delay_ms(ms: u32) {
    let start = read_time();
    let ticks = ms as u64 * 10_000;
    while read_time() - start < ticks {
        core::hint::spin_loop();
    }
}

// --- Logo constants ---

const BG_DARK: u32    = rgb(12, 14, 24);
const RING_COLOR: u32 = rgb(40, 50, 80);
const TEXT_WHITE: u32 = rgb(240, 240, 250);
const TEXT_TEAL: u32  = rgb(0, 200, 180);
const TEXT_GRAY: u32  = rgb(120, 130, 150);

const BANNER_HEIGHT: u32 = 210;

const RAINBOW: [u32; 6] = [
    rgb(255, 60, 60),
    rgb(255, 160, 0),
    rgb(255, 220, 0),
    rgb(0, 200, 80),
    rgb(0, 150, 255),
    rgb(160, 80, 255),
];

/// Compute triangle vertex position from center, radius, and angle step.
fn tri_vertex(cx: i32, cy: i32, radius: i32, step: usize) -> (i32, i32) {
    (
        cx + cos256(step) * radius / 256,
        cy + sin256(step) * radius / 256,
    )
}

/// Draw the animated boot logo.
///
/// Call after GPU init. Returns the number of text rows consumed by the banner
/// (so the framebuffer console can start below it).
pub fn draw_boot_logo(fb: *mut u32, width: u32, height: u32) -> u32 {
    let c = Canvas { fb, stride: width, width, height };

    // 1. Dark background banner
    c.fill_rect(0, 0, width, BANNER_HEIGHT, BG_DARK);

    // 2. Static ring around triangle area
    let cx = 120i32;
    let cy = 105i32;
    c.draw_ring(cx, cy, 82, 78, RING_COLOR);

    // 3. Static text: "rvOS" large
    c.draw_text_scaled("rvOS", 250, 20, 5, TEXT_WHITE);

    // 4. Subtitle
    c.draw_text_scaled("RISC-V 64-bit Microkernel", 250, 115, 2, TEXT_TEAL);

    // 5. Version / tagline
    c.draw_text_scaled("Written in Rust -- no external crates", 252, 160, 1, TEXT_GRAY);

    // 6. Rainbow bar
    let bar_y = 195;
    let bar_h = 6u32;
    let bar_margin = 30u32;
    let bar_w = width.saturating_sub(2 * bar_margin);
    let seg_w = bar_w / 6;
    for (i, &color) in RAINBOW.iter().enumerate() {
        c.fill_rect(bar_margin + i as u32 * seg_w, bar_y, seg_w, bar_h, color);
    }

    // 7. Animate spinning triangles
    let outer_r = 72i32;
    let inner_r = 36i32;
    let clear_margin = 77u32;
    let clear_x = (cx as u32).saturating_sub(clear_margin);
    let clear_y = (cy as u32).saturating_sub(clear_margin);
    let clear_size = clear_margin * 2;

    let num_frames = 24u32;
    for frame in 0..num_frames {
        // Clear triangle area (preserve ring)
        c.fill_rect(clear_x, clear_y, clear_size, clear_size, BG_DARK);

        // Outer gradient triangle — rotates clockwise
        let step = frame as usize;
        let (x0, y0) = tri_vertex(cx, cy, outer_r, step);
        let (x1, y1) = tri_vertex(cx, cy, outer_r, step + 21);
        let (x2, y2) = tri_vertex(cx, cy, outer_r, step + 42);

        // Vertex colors cycle through hues
        let hue_base = frame * 256 / num_frames;
        let c0 = hue_to_rgb(hue_base);
        let c1 = hue_to_rgb(hue_base + 85);
        let c2 = hue_to_rgb(hue_base + 170);

        c.draw_gradient_triangle(x0, y0, c0, x1, y1, c1, x2, y2, c2);

        // Inner triangle — rotates counter-clockwise, white with slight tint
        let istep = 64usize.wrapping_sub(frame as usize * 2);
        let (ix0, iy0) = tri_vertex(cx, cy, inner_r, istep);
        let (ix1, iy1) = tri_vertex(cx, cy, inner_r, istep + 21);
        let (ix2, iy2) = tri_vertex(cx, cy, inner_r, istep + 42);

        let inner_tint = hue_to_rgb(hue_base + 128);
        let inner_white = rgb(240, 245, 255);
        c.draw_gradient_triangle(
            ix0, iy0, inner_white,
            ix1, iy1, inner_tint,
            ix2, iy2, inner_white,
        );

        // Flush to display + delay
        crate::drivers::virtio::gpu::flush();
        delay_ms(50);
    }

    // Redraw ring on top (animation may have clipped edges)
    c.draw_ring(cx, cy, 82, 78, RING_COLOR);
    crate::drivers::virtio::gpu::flush();

    // Return number of text rows the banner occupies
    // (BANNER_HEIGHT / 16 rounded up)
    (BANNER_HEIGHT + 15) / 16
}
