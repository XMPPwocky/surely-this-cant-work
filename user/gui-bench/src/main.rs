extern crate rvos_rt;

// --- Timing helpers ---

#[inline(always)]
fn rdtime() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

fn ticks_to_us(ticks: u64) -> u64 {
    ticks / 10 // 10 MHz clock => 1 tick = 100ns
}

// --- Print helpers (allocation-free, same style as bench) ---

fn print_u64(val: u64) {
    if val == 0 {
        print!("0");
        return;
    }
    let mut digits = [0u8; 20];
    let mut d = 0;
    let mut v = val;
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    let mut s = [0u8; 20];
    for i in 0..d {
        s[i] = digits[d - 1 - i];
    }
    let st = unsafe { core::str::from_utf8_unchecked(&s[..d]) };
    print!("{}", st);
}

fn print_result(name: &str, iters: u32, total_us: u64, per_us: u64, fill_us: u64, swap_us: u64) {
    print!("  ");
    print!("{}", name);
    for _ in name.len()..28 {
        print!(" ");
    }
    print_u64(iters as u64);
    print!("  total=");
    print_u64(total_us);
    print!("us  per_frame=");
    print_u64(per_us);
    print!("us  fill=");
    print_u64(fill_us);
    print!("us  swap=");
    print_u64(swap_us);
    print!("us  fps=");
    if let Some(fps) = (iters as u64 * 1_000_000).checked_div(total_us) {
        print_u64(fps);
    } else {
        print!("inf");
    }
    println!();
}

fn fill_solid(fb: *mut u32, offset: usize, count: usize, color: u32) {
    unsafe {
        for i in 0..count {
            *fb.add(offset + i) = color;
        }
    }
}

// --- Benchmarks ---

fn bench_small_fill_swap() {
    let iters = 60u32;
    let mut win = rvos::Window::create(400, 300).expect("gui-bench: window creation failed");

    // Warmup: 5 frames
    for _ in 0..5u32 {
        fill_solid(win.fb_base(), if win.current_back() == 0 { 0 } else { win.pixels_per_buffer() },
                   win.pixels_per_buffer(), 0xFF222222);
        win.present_no_copy();
    }

    println!("[gui-bench] small window (400x300) solid fill + swap x{}", iters);

    let start = rdtime();
    let mut swap_ticks: u64 = 0;
    let mut fill_ticks: u64 = 0;

    for i in 0..iters {
        let off = if win.current_back() == 0 { 0 } else { win.pixels_per_buffer() };
        let color = 0xFF000000 | (i * 4);

        let t0 = rdtime();
        fill_solid(win.fb_base(), off, win.pixels_per_buffer(), color);
        let t1 = rdtime();
        win.present_no_copy();
        let t2 = rdtime();

        fill_ticks += t1 - t0;
        swap_ticks += t2 - t1;
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;
    let fill_us = ticks_to_us(fill_ticks) / iters as u64;
    let swap_us = ticks_to_us(swap_ticks) / iters as u64;

    print_result("small fill+swap", iters, total_us, per_us, fill_us, swap_us);
}

fn bench_fullscreen_fill_swap() {
    let iters = 30u32;
    let mut win = rvos::Window::create(0, 0).expect("gui-bench: window creation failed");

    // Warmup
    for _ in 0..3u32 {
        fill_solid(win.fb_base(), if win.current_back() == 0 { 0 } else { win.pixels_per_buffer() },
                   win.pixels_per_buffer(), 0xFF222222);
        win.present_no_copy();
    }

    println!("[gui-bench] fullscreen ({}x{}) solid fill + swap x{}", win.width(), win.height(), iters);

    let start = rdtime();
    let mut swap_ticks: u64 = 0;
    let mut fill_ticks: u64 = 0;

    for i in 0..iters {
        let off = if win.current_back() == 0 { 0 } else { win.pixels_per_buffer() };
        let color = 0xFF000000 | ((i * 8) & 0xFF);

        let t0 = rdtime();
        fill_solid(win.fb_base(), off, win.pixels_per_buffer(), color);
        let t1 = rdtime();
        win.present_no_copy();
        let t2 = rdtime();

        fill_ticks += t1 - t0;
        swap_ticks += t2 - t1;
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;
    let fill_us = ticks_to_us(fill_ticks) / iters as u64;
    let swap_us = ticks_to_us(swap_ticks) / iters as u64;

    print_result("fullscreen fill+swap", iters, total_us, per_us, fill_us, swap_us);
}

fn bench_swap_only() {
    let iters = 60u32;
    let mut win = rvos::Window::create(400, 300).expect("gui-bench: window creation failed");

    // Fill both buffers once with same color
    fill_solid(win.fb_base(), 0, win.pixels_per_buffer(), 0xFF444444);
    fill_solid(win.fb_base(), win.pixels_per_buffer(), win.pixels_per_buffer(), 0xFF444444);
    win.present_no_copy();

    println!("[gui-bench] small window (400x300) swap-only (no fill) x{}", iters);

    let start = rdtime();
    for _ in 0..iters {
        win.present_no_copy();
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;

    print_result("swap-only (no fill)", iters, total_us, per_us, 0, per_us);
}

fn main() {
    println!();
    println!("=== rvOS GUI Benchmark ===");
    println!();

    bench_small_fill_swap();
    bench_fullscreen_fill_swap();
    bench_swap_only();

    println!();
    println!("=== GUI Benchmark Complete ===");
}
