extern crate rvos_rt;

use rvos::raw::{self};
use rvos::Message;
use rvos::rvos_wire;
use rvos_proto::window::{
    CreateWindowRequest,
    WindowRequest, WindowReply,
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
    if total_us > 0 {
        print_u64((iters as u64 * 1_000_000) / total_us);
    } else {
        print!("inf");
    }
    println!();
}

// --- Window helpers ---

struct WinContext {
    req_chan: usize,
    event_chan: usize,
    width: u32,
    height: u32,
    stride: u32,
    fb_base: *mut u32,
    pixels_per_buffer: usize,
}

fn connect_window(width: u32, height: u32) -> WinContext {
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // CreateWindow
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &CreateWindowRequest { width, height },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(win_ctl, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(win_ctl, &mut resp);
    let req_chan = resp.caps[0];
    let event_chan = resp.caps[1];

    // GetInfo — replies arrive on req_chan only (no interleaved events)
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::GetInfo { seq: 1 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(req_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(req_chan, &mut resp);
    let (w, h, stride) = match rvos_wire::from_bytes::<WindowReply>(&resp.data[..resp.len]) {
        Ok(WindowReply::InfoReply { width, height, stride, .. }) => (width, height, stride),
        _ => (width, height, width),
    };

    // GetFramebuffer
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::GetFramebuffer { seq: 2 },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(req_chan, &req);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(req_chan, &mut resp);
    let shm_handle = resp.cap();

    let fb_size = (stride as usize) * (h as usize) * 4 * 2;
    let fb_base = match raw::mmap(shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => panic!("gui-bench: mmap failed"),
    };
    let pixels_per_buffer = (stride as usize) * (h as usize);

    WinContext { req_chan, event_chan, width: w, height: h, stride, fb_base, pixels_per_buffer }
}

fn swap_buffers(req_chan: usize, seq: u32) {
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(
        &WindowRequest::SwapBuffers { seq },
        &mut req.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(req_chan, &req);

    // Wait for swap reply (no events on req_chan)
    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(req_chan, &mut resp);
}

fn close_window(req_chan: usize, event_chan: usize) {
    let mut req = Message::new();
    req.len = rvos_wire::to_bytes(&WindowRequest::CloseWindow {}, &mut req.data).unwrap_or(0);
    raw::sys_chan_send(req_chan, &req);
    raw::sys_chan_close(req_chan);
    raw::sys_chan_close(event_chan);
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
    let ctx = connect_window(400, 300);
    let mut back = 1u8;

    // Warmup: 5 frames
    for i in 0..5u32 {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, 0xFF222222);
        swap_buffers(ctx.req_chan, i);
        back = 1 - back;
    }

    println!("[gui-bench] small window (400x300) solid fill + swap x{}", iters);

    let start = rdtime();
    let mut swap_ticks: u64 = 0;
    let mut fill_ticks: u64 = 0;

    for i in 0..iters {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        let color = 0xFF000000 | ((i * 4) as u32);

        let t0 = rdtime();
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, color);
        let t1 = rdtime();
        swap_buffers(ctx.req_chan, 100 + i);
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
    close_window(ctx.req_chan, ctx.event_chan);
}

fn bench_fullscreen_fill_swap() {
    let iters = 30u32;
    let ctx = connect_window(0, 0); // fullscreen
    let mut back = 1u8;

    // Warmup
    for i in 0..3u32 {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, 0xFF222222);
        swap_buffers(ctx.req_chan, i);
        back = 1 - back;
    }

    println!("[gui-bench] fullscreen ({}x{}) solid fill + swap x{}", ctx.width, ctx.height, iters);

    let start = rdtime();
    let mut swap_ticks: u64 = 0;
    let mut fill_ticks: u64 = 0;

    for i in 0..iters {
        let off = if back == 0 { 0 } else { ctx.pixels_per_buffer };
        let color = 0xFF000000 | (((i * 8) & 0xFF) as u32);

        let t0 = rdtime();
        fill_solid(ctx.fb_base, off, ctx.pixels_per_buffer, color);
        let t1 = rdtime();
        swap_buffers(ctx.req_chan, 200 + i);
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
    close_window(ctx.req_chan, ctx.event_chan);
}

fn bench_swap_only() {
    let iters = 60u32;
    let ctx = connect_window(400, 300);
    let mut back = 1u8;

    // Fill both buffers once with same color
    fill_solid(ctx.fb_base, 0, ctx.pixels_per_buffer, 0xFF444444);
    fill_solid(ctx.fb_base, ctx.pixels_per_buffer, ctx.pixels_per_buffer, 0xFF444444);
    swap_buffers(ctx.req_chan, 0);
    back = 0;

    println!("[gui-bench] small window (400x300) swap-only (no fill) x{}", iters);

    let start = rdtime();
    for i in 0..iters {
        swap_buffers(ctx.req_chan, 300 + i);
        back = 1 - back;
    }

    let total = rdtime() - start;
    let total_us = ticks_to_us(total);
    let per_us = total_us / iters as u64;

    print_result("swap-only (no fill)", iters, total_us, per_us, 0, per_us);
    close_window(ctx.req_chan, ctx.event_chan);
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
