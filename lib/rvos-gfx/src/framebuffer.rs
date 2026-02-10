pub struct Framebuffer<'a> {
    pub pixels: &'a mut [u32],
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

impl<'a> Framebuffer<'a> {
    pub fn new(pixels: &'a mut [u32], width: u32, height: u32, stride: u32) -> Self {
        Framebuffer { pixels, width, height, stride }
    }

    #[inline]
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x < self.width && y < self.height {
            self.pixels[(y * self.stride + x) as usize] = color;
        }
    }

    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let x1 = x.min(self.width);
        let y1 = y.min(self.height);
        let x2 = (x + w).min(self.width);
        let y2 = (y + h).min(self.height);
        for row in y1..y2 {
            let start = (row * self.stride + x1) as usize;
            let end = (row * self.stride + x2) as usize;
            for px in &mut self.pixels[start..end] {
                *px = color;
            }
        }
    }

    pub fn clear(&mut self, color: u32) {
        for row in 0..self.height {
            let start = (row * self.stride) as usize;
            let end = start + self.width as usize;
            for px in &mut self.pixels[start..end] {
                *px = color;
            }
        }
    }

    pub fn hline(&mut self, x: u32, y: u32, w: u32, color: u32) {
        if y >= self.height { return; }
        let x1 = x.min(self.width);
        let x2 = (x + w).min(self.width);
        let start = (y * self.stride + x1) as usize;
        let end = (y * self.stride + x2) as usize;
        for px in &mut self.pixels[start..end] {
            *px = color;
        }
    }

    pub fn vline(&mut self, x: u32, y: u32, h: u32, color: u32) {
        if x >= self.width { return; }
        let y1 = y.min(self.height);
        let y2 = (y + h).min(self.height);
        for row in y1..y2 {
            self.pixels[(row * self.stride + x) as usize] = color;
        }
    }
}
