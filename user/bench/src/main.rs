extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;

// --- Timing helpers ---

#[inline(always)]
fn rdtime() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

fn ticks_to_us(ticks: u64) -> u64 {
    ticks / 10 // 10 MHz clock => 1 tick = 100ns = 0.1us
}

fn ticks_to_ns(ticks: u64) -> u64 {
    ticks * 100 // 10 MHz clock => 1 tick = 100ns
}

// --- Path formatting (no heap allocation) ---

fn bench_path(buf: &mut [u8; 24], n: u32) -> &str {
    // Produces "/tmp/bench/f_NNN"
    let prefix = b"/tmp/bench/f_";
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();
    if n == 0 {
        buf[pos] = b'0';
        pos += 1;
    } else {
        let mut digits = [0u8; 10];
        let mut d = 0;
        let mut val = n;
        while val > 0 {
            digits[d] = b'0' + (val % 10) as u8;
            val /= 10;
            d += 1;
        }
        for i in (0..d).rev() {
            buf[pos] = digits[i];
            pos += 1;
        }
    }
    unsafe { core::str::from_utf8_unchecked(&buf[..pos]) }
}

// --- Print helpers ---

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

fn count_digits(mut v: u64) -> usize {
    if v == 0 { return 1; }
    let mut d = 0;
    while v > 0 { d += 1; v /= 10; }
    d
}

fn print_row(name: &str, iters: u32, total_us: u64, per_ns: u64) {
    print!("  {}", name);
    for _ in name.len()..24 {
        print!(" ");
    }
    let iters_len = count_digits(iters as u64);
    for _ in iters_len..6 {
        print!(" ");
    }
    print_u64(iters as u64);
    print!("  ");
    let us_len = count_digits(total_us);
    for _ in us_len..10 {
        print!(" ");
    }
    print_u64(total_us);
    print!("  ");
    let ns_len = count_digits(per_ns);
    for _ in ns_len..10 {
        print!(" ");
    }
    print_u64(per_ns);
    println!();
}

/// Run a named benchmark, printing name before and results after.
fn run_bench(name: &str, f: fn() -> (u64, u32)) {
    print!("[bench] {}...", name);
    let (ticks, iters) = f();
    println!(" done");
    print_row(name, iters, ticks_to_us(ticks), ticks_to_ns(ticks) / iters as u64);
}

// --- Benchmarks ---

fn bench_syscall_getpid() -> (u64, u32) {
    let iters = 10000u32;
    let start = rdtime();
    for _ in 0..iters {
        unsafe { core::arch::asm!("ecall", in("a7") 172usize, lateout("a0") _, options(nostack)) };
    }
    (rdtime() - start, iters)
}

fn bench_yield() -> (u64, u32) {
    let iters = 100u32;
    let start = rdtime();
    for _ in 0..iters {
        raw::sys_yield();
    }
    (rdtime() - start, iters)
}

fn bench_chan_create_close() -> (u64, u32) {
    let iters = 1000u32;
    let start = rdtime();
    for _ in 0..iters {
        let (ha, hb) = raw::sys_chan_create();
        raw::sys_chan_close(ha);
        raw::sys_chan_close(hb);
    }
    (rdtime() - start, iters)
}

fn bench_ipc_roundtrip() -> (u64, u32) {
    let iters = 1000u32;
    let (ha, hb) = raw::sys_chan_create();
    let msg = Message::from_bytes(b"ping");
    let mut recv_msg = Message::new();
    let start = rdtime();
    for _ in 0..iters {
        raw::sys_chan_send(ha, &msg);
        raw::sys_chan_recv(hb, &mut recv_msg);
    }
    let elapsed = rdtime() - start;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    (elapsed, iters)
}

fn bench_ipc_throughput() -> (u64, u32) {
    let iters = 1000u32;
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::new();
    msg.len = 1000;
    for i in 0..1000 {
        msg.data[i] = (i & 0xFF) as u8;
    }
    let mut recv_msg = Message::new();
    let start = rdtime();
    for _ in 0..iters {
        raw::sys_chan_send(ha, &msg);
        raw::sys_chan_recv(hb, &mut recv_msg);
    }
    let elapsed = rdtime() - start;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    (elapsed, iters)
}

fn bench_mmap_munmap() -> (u64, u32) {
    let iters = 100u32;
    let start = rdtime();
    for _ in 0..iters {
        let addr = raw::sys_mmap(0, 4096);
        if addr != usize::MAX {
            raw::sys_munmap(addr, 4096);
        }
    }
    (rdtime() - start, iters)
}

fn bench_file_create_write() -> (u64, u32) {
    let iters = 20u32;
    let _ = std::fs::create_dir_all("/tmp/bench");
    let start = rdtime();
    for i in 0..iters {
        let mut buf = [0u8; 24];
        let path = bench_path(&mut buf, i);
        let _ = std::fs::write(path, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    }
    (rdtime() - start, iters)
}

fn bench_file_read() -> (u64, u32) {
    let iters = 20u32;
    let start = rdtime();
    for i in 0..iters {
        let mut buf = [0u8; 24];
        let path = bench_path(&mut buf, i);
        let _ = std::fs::read(path);
    }
    (rdtime() - start, iters)
}

fn bench_file_stat() -> (u64, u32) {
    let iters = 20u32;
    let start = rdtime();
    for _ in 0..iters {
        let _ = std::fs::metadata("/tmp/bench/f_0");
    }
    (rdtime() - start, iters)
}

fn bench_file_delete() -> (u64, u32) {
    let iters = 20u32;
    let start = rdtime();
    for i in 0..iters {
        let mut buf = [0u8; 24];
        let path = bench_path(&mut buf, i);
        let _ = std::fs::remove_file(path);
    }
    (rdtime() - start, iters)
}

fn bench_readdir_small() -> (u64, u32) {
    let iters = 20u32;
    let _ = std::fs::create_dir_all("/tmp/bench_sm");
    for i in 0..10 {
        let name = format!("/tmp/bench_sm/f_{}", i);
        let _ = std::fs::write(&name, "x");
    }
    let start = rdtime();
    for _ in 0..iters {
        if let Ok(entries) = std::fs::read_dir("/tmp/bench_sm") {
            for _ in entries {}
        }
    }
    let elapsed = rdtime() - start;
    for i in 0..10 {
        let name = format!("/tmp/bench_sm/f_{}", i);
        let _ = std::fs::remove_file(&name);
    }
    (elapsed, iters)
}

fn bench_readdir_large() -> (u64, u32) {
    let iters = 3u32;
    let file_count = 30; // 30 files — more takes too long via IPC
    let _ = std::fs::create_dir_all("/tmp/bench_lg");
    for i in 0..file_count {
        let name = format!("/tmp/bench_lg/f_{}", i);
        let _ = std::fs::write(&name, "x");
    }
    let start = rdtime();
    for _ in 0..iters {
        if let Ok(entries) = std::fs::read_dir("/tmp/bench_lg") {
            for _ in entries {}
        }
    }
    let elapsed = rdtime() - start;
    for i in 0..file_count {
        let name = format!("/tmp/bench_lg/f_{}", i);
        let _ = std::fs::remove_file(&name);
    }
    (elapsed, iters)
}

fn bench_process_spawn() -> (u64, u32) {
    use rvos_proto::boot::{BootRequest, BootResponse};
    let iters = 3u32;
    let start = rdtime();
    for _ in 0..iters {
        let mut msg = Message::new();
        msg.len = rvos::rvos_wire::to_bytes(
            &BootRequest::Spawn { path: "/bin/hello-std", args: &[], ns_overrides: &[] },
            &mut msg.data,
        ).unwrap_or(0);
        msg.set_cap(NO_CAP);
        raw::sys_chan_send_blocking(0, &msg);

        let mut resp = Message::new();
        raw::sys_chan_recv_blocking(0, &mut resp);
        if let Ok(BootResponse::Ok {}) = rvos::rvos_wire::from_bytes::<BootResponse>(&resp.data[..resp.len]) {
            if resp.cap() != NO_CAP {
                let mut exit_msg = Message::new();
                raw::sys_chan_recv_blocking(resp.cap(), &mut exit_msg);
                raw::sys_chan_close(resp.cap());
            }
        }
    }
    (rdtime() - start, iters)
}

fn main() {
    println!("=== rvOS Benchmark Suite ===");
    println!();

    let (wall_start, cpu_start) = raw::sys_clock();

    println!("  {:<24} {:>6}  {:>10}  {:>10}", "Benchmark", "Iters", "Total(us)", "Per(ns)");
    println!("  {:<24} {:>6}  {:>10}  {:>10}", "------------------------", "------", "----------", "----------");

    run_bench("syscall (getpid)", bench_syscall_getpid);
    run_bench("yield", bench_yield);
    run_bench("chan create+close", bench_chan_create_close);
    run_bench("ipc round-trip", bench_ipc_roundtrip);

    // IPC throughput with MB/s calculation
    print!("[bench] ipc throughput 1KB...");
    let (ticks, iters) = bench_ipc_throughput();
    println!(" done");
    let total_bytes = iters as u64 * 1000;
    let total_us = ticks_to_us(ticks);
    print_row("ipc throughput 1KB", iters, total_us, ticks_to_ns(ticks) / iters as u64);
    if total_us > 0 {
        let mb_per_sec = total_bytes / total_us;
        print!("    => ");
        print_u64(mb_per_sec);
        println!(" MB/s");
    }

    run_bench("mmap+munmap 4K", bench_mmap_munmap);
    run_bench("file create+write 64B", bench_file_create_write);
    run_bench("file read 64B", bench_file_read);
    run_bench("file stat", bench_file_stat);
    run_bench("file delete", bench_file_delete);
    run_bench("readdir small (10)", bench_readdir_small);
    run_bench("readdir large (30)", bench_readdir_large);
    run_bench("process spawn", bench_process_spawn);

    let (wall_end, cpu_end) = raw::sys_clock();
    let wall_us = ticks_to_us(wall_end - wall_start);
    let cpu_us = ticks_to_us(cpu_end - cpu_start);

    println!();
    print!("  Wall time: ");
    print_u64(wall_us);
    println!(" us");
    print!("  CPU time:  ");
    print_u64(cpu_us);
    println!(" us");
    println!();
    println!("=== Benchmark Complete ===");

    // Cleanup
    let _ = std::fs::remove_file("/tmp/bench");
}
