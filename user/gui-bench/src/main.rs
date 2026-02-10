extern crate rvos_rt;

use rvos::raw::{self};
use rvos::UserTransport;
use rvos::Channel;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowClient,
};

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

// --- Window helpers ---

struct WinContext {
    client: WindowClient<UserTransport>,
    event_chan: usize,
    width: u32,
    height: u32,
    fb_base: *mut u32,
    pixels_per_buffer: usize,
}

fn connect_window(width: u32, height: u32) -> WinContext {
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // CreateWindow handshake (returns embedded channel caps)
    let mut win_ctl_ch = Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
    win_ctl_ch.send(&CreateWindowRequest { width, height }).expect("CreateWindow send");
    let create_resp = win_ctl_ch.recv_blocking()
        .expect("CreateWindow recv");
    let req_chan = create_resp.req_channel.raw();
    let event_chan = create_resp.event_channel.raw();

    // Typed WindowClient for subsequent RPCs
    let mut client = WindowClient::new(UserTransport::new(req_chan));

    let info = client.get_info(1).expect("GetInfo failed");
    let (w, h, stride) = match info {
        WindowReply::InfoReply { width, height, stride, .. } => (width, height, stride),
        _ => (width, height, width),
    };

    let shm_handle = match client.get_framebuffer(2) {
        Ok(WindowReply::FbReply { fb, .. }) => fb.0,
        _ => panic!("gui-bench: GetFramebuffer failed"),
    };

    let fb_size = (stride as usize) * (h as usize) * 4 * 2;
    let fb_base = match raw::mmap(shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => panic!("gui-bench: mmap failed"),
    };
    let pixels_per_buffer = (stride as usize) * (h as usize);

    WinContext { client, event_chan, width: w, height: h, fb_base, pixels_per_buffer }
}

fn close_window(ctx: &mut WinContext) {
    let _ = ctx.client.close_window();
    raw::sys_chan_close(ctx.event_chan);
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
    let mut ctx = connect_window(400, 300);
    let mut back = 1u8;

    // Warmup: 5 frames
    for i in 0..5u32 {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, 0xFF222222);
        let _ = ctx.client.swap_buffers(i);
        back = 1 - back;
    }

    println!("[gui-bench] small window (400x300) solid fill + swap x{}", iters);

    let start = rdtime();
    let mut swap_ticks: u64 = 0;
    let mut fill_ticks: u64 = 0;

    for i in 0..iters {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        let color = 0xFF000000 | (i * 4);

        let t0 = rdtime();
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, color);
        let t1 = rdtime();
        let _ = ctx.client.swap_buffers(100 + i);
        let t2 = rdtime();

        fill_ticks += t1 - t0;
        swap_ticks += t2 - t1;
        back = 1 - back;
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;
    let fill_us = ticks_to_us(fill_ticks) / iters as u64;
    let swap_us = ticks_to_us(swap_ticks) / iters as u64;

    print_result("small fill+swap", iters, total_us, per_us, fill_us, swap_us);
    close_window(&mut ctx);
}

fn bench_fullscreen_fill_swap() {
    let iters = 30u32;
    let mut ctx = connect_window(0, 0); // fullscreen
    let mut back = 1u8;

    // Warmup
    for i in 0..3u32 {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, 0xFF222222);
        let _ = ctx.client.swap_buffers(i);
        back = 1 - back;
    }

    println!("[gui-bench] fullscreen ({}x{}) solid fill + swap x{}", ctx.width, ctx.height, iters);

    let start = rdtime();
    let mut swap_ticks: u64 = 0;
    let mut fill_ticks: u64 = 0;

    for i in 0..iters {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        let color = 0xFF000000 | ((i * 8) & 0xFF);

        let t0 = rdtime();
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, color);
        let t1 = rdtime();
        let _ = ctx.client.swap_buffers(200 + i);
        let t2 = rdtime();

        fill_ticks += t1 - t0;
        swap_ticks += t2 - t1;
        back = 1 - back;
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;
    let fill_us = ticks_to_us(fill_ticks) / iters as u64;
    let swap_us = ticks_to_us(swap_ticks) / iters as u64;

    print_result("fullscreen fill+swap", iters, total_us, per_us, fill_us, swap_us);
    close_window(&mut ctx);
}

fn bench_swap_only() {
    let iters = 60u32;
    let mut ctx = connect_window(400, 300);

    // Fill both buffers once with same color
    fill_solid(ctx.fb_base, 0, ctx.pixels_per_buffer, 0xFF444444);
    fill_solid(ctx.fb_base, ctx.pixels_per_buffer, ctx.pixels_per_buffer, 0xFF444444);
    let _ = ctx.client.swap_buffers(0);
    let mut back = 0u8;

    println!("[gui-bench] small window (400x300) swap-only (no fill) x{}", iters);

    let start = rdtime();
    for i in 0..iters {
        let _ = ctx.client.swap_buffers(300 + i);
        back = 1 - back;
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;

    print_result("swap-only (no fill)", iters, total_us, per_us, 0, per_us);
    close_window(&mut ctx);
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
