use crate::framebuffer::Framebuffer;

/// Draw an outlined rectangle with the given thickness.
pub fn draw_rect(fb: &mut Framebuffer, x: u32, y: u32, w: u32, h: u32, color: u32, thickness: u32) {
    // Top edge
    fb.fill_rect(x, y, w, thickness.min(h), color);
    // Bottom edge
    if h > thickness {
        fb.fill_rect(x, y + h - thickness, w, thickness, color);
    }
    // Left edge
    if h > 2 * thickness {
        fb.fill_rect(x, y + thickness, thickness.min(w), h - 2 * thickness, color);
    }
    // Right edge
    if w > thickness && h > 2 * thickness {
        fb.fill_rect(x + w - thickness, y + thickness, thickness, h - 2 * thickness, color);
    }
}

/// Fill a triangle using scanline rasterization.
pub fn fill_triangle(
    fb: &mut Framebuffer,
    x0: i32, y0: i32,
    x1: i32, y1: i32,
    x2: i32, y2: i32,
    color: u32,
) {
    // Sort vertices by y-coordinate
    let (mut vx0, mut vy0) = (x0, y0);
    let (mut vx1, mut vy1) = (x1, y1);
    let (mut vx2, mut vy2) = (x2, y2);

    if vy0 > vy1 { (vx0, vy0, vx1, vy1) = (vx1, vy1, vx0, vy0); }
    if vy0 > vy2 { (vx0, vy0, vx2, vy2) = (vx2, vy2, vx0, vy0); }
    if vy1 > vy2 { (vx1, vy1, vx2, vy2) = (vx2, vy2, vx1, vy1); }

    let total_height = vy2 - vy0;
    if total_height == 0 { return; }

    for y in vy0..=vy2 {
        if y < 0 || y >= fb.height as i32 { continue; }

        let second_half = y >= vy1;
        let segment_height = if second_half { vy2 - vy1 } else { vy1 - vy0 };
        if segment_height == 0 { continue; }

        let alpha = (y - vy0) as f32 / total_height as f32;
        let beta = if second_half {
            (y - vy1) as f32 / segment_height as f32
        } else {
            (y - vy0) as f32 / segment_height as f32
        };

        let mut xa = vx0 + ((vx2 - vx0) as f32 * alpha) as i32;
        let mut xb = if second_half {
            vx1 + ((vx2 - vx1) as f32 * beta) as i32
        } else {
            vx0 + ((vx1 - vx0) as f32 * beta) as i32
        };

        if xa > xb { (xa, xb) = (xb, xa); }

        let row_start = xa.max(0) as u32;
        let row_end = (xb + 1).min(fb.width as i32).max(0) as u32;

        for x in row_start..row_end {
            fb.pixels[(y as u32 * fb.stride + x) as usize] = color;
        }
    }
}
