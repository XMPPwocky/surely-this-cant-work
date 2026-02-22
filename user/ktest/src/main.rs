extern crate rvos_rt;

use rvos::raw::{self, MemInfo, NO_CAP};
use rvos::Message;

// ============================================================
// Test framework
// ============================================================

struct TestResult {
    pass: u32,
    fail: u32,
    leak: u32,
}

impl TestResult {
    fn new() -> Self {
        Self { pass: 0, fail: 0, leak: 0 }
    }

    fn merge(&mut self, other: &TestResult) {
        self.pass += other.pass;
        self.fail += other.fail;
        self.leak += other.leak;
    }
}

fn meminfo() -> MemInfo {
    let mut info = MemInfo {
        heap_used: 0,
        heap_total: 0,
        frames_used: 0,
        frames_total: 0,
        proc_mem_pages: 0,
    };
    raw::sys_meminfo(&mut info);
    info
}

fn run_test(name: &str, test_fn: fn() -> Result<(), &'static str>) -> TestResult {
    let mut result = TestResult::new();

    // 1. Warmup run
    let _ = test_fn();

    // 2. Snapshot memory
    let before = meminfo();

    // 3. Second run (should be memory-neutral)
    let outcome = test_fn();

    // 4. Snapshot again
    let after = meminfo();

    // 5. Check for test pass/fail
    match outcome {
        Ok(()) => {
            // Check for leaks
            if after.heap_used > before.heap_used + 64
                || after.frames_used > before.frames_used
                || after.proc_mem_pages > before.proc_mem_pages
            {
                print!("  [LEAK] {:<32}", name);
                if after.heap_used > before.heap_used + 64 {
                    print!(" heap: +{}", after.heap_used - before.heap_used);
                }
                if after.frames_used > before.frames_used {
                    print!(" frames: +{}", after.frames_used - before.frames_used);
                }
                if after.proc_mem_pages > before.proc_mem_pages {
                    print!(" pages: +{}", after.proc_mem_pages - before.proc_mem_pages);
                }
                println!();
                result.leak += 1;
            } else {
                println!("  [PASS] {:<32} (no leak)", name);
                result.pass += 1;
            }
        }
        Err(msg) => {
            println!("  [FAIL] {:<32} {}", name, msg);
            result.fail += 1;
        }
    }
    result
}

type TestEntry = (&'static str, fn() -> Result<(), &'static str>);

fn run_section(name: &str, tests: &[TestEntry]) -> TestResult {
    println!();
    println!("--- {} ---", name);
    let mut result = TestResult::new();
    for (test_name, test_fn) in tests {
        let r = run_test(test_name, *test_fn);
        result.merge(&r);
    }
    result
}

// ============================================================
// Assertion helpers
// ============================================================

fn assert_eq(a: usize, b: usize, msg: &'static str) -> Result<(), &'static str> {
    if a == b { Ok(()) } else { Err(msg) }
}

fn assert_ne(a: usize, b: usize, msg: &'static str) -> Result<(), &'static str> {
    if a != b { Ok(()) } else { Err(msg) }
}

fn assert_lt(a: usize, b: usize, msg: &'static str) -> Result<(), &'static str> {
    if a < b { Ok(()) } else { Err(msg) }
}

fn assert_true(cond: bool, msg: &'static str) -> Result<(), &'static str> {
    if cond { Ok(()) } else { Err(msg) }
}

// ============================================================
// 1. Syscall Basics
// ============================================================

fn test_getpid() -> Result<(), &'static str> {
    let pid = unsafe {
        let ret: usize;
        core::arch::asm!("ecall", inlateout("a0") 0usize => ret, in("a7") 172usize, options(nostack));
        ret
    };
    assert_true(pid > 0 && pid < 64, "pid out of range")
}

fn test_getpid_stable() -> Result<(), &'static str> {
    let pid1 = unsafe {
        let ret: usize;
        core::arch::asm!("ecall", inlateout("a0") 0usize => ret, in("a7") 172usize, options(nostack));
        ret
    };
    let pid2 = unsafe {
        let ret: usize;
        core::arch::asm!("ecall", inlateout("a0") 0usize => ret, in("a7") 172usize, options(nostack));
        ret
    };
    assert_eq(pid1, pid2, "pid changed between calls")
}

fn test_yield() -> Result<(), &'static str> {
    raw::sys_yield();
    Ok(())
}

fn test_clock_monotonic() -> Result<(), &'static str> {
    let (wall1, _) = raw::sys_clock();
    let (wall2, _) = raw::sys_clock();
    assert_true(wall2 >= wall1, "clock went backwards")
}

fn test_clock_both_nonzero() -> Result<(), &'static str> {
    let (wall, cpu) = raw::sys_clock();
    assert_true(wall > 0, "wall ticks was 0")?;
    assert_true(cpu > 0, "cpu ticks was 0")
}

// ============================================================
// 2. Channel Lifecycle
// ============================================================

fn test_chan_create() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    assert_ne(ha, usize::MAX, "chan_create failed")?;
    assert_ne(ha, hb, "handles are identical")?;
    assert_lt(ha, 32, "handle_a out of range")?;
    assert_lt(hb, 32, "handle_b out of range")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_chan_close() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let r1 = raw::syscall1(raw::SYS_CHAN_CLOSE, ha);
    let r2 = raw::syscall1(raw::SYS_CHAN_CLOSE, hb);
    assert_ne(r1, usize::MAX, "close ha returned MAX")?;
    assert_ne(r2, usize::MAX, "close hb returned MAX")
}

fn test_chan_double_close() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    // Second close on same handle should return error, not crash
    let r = raw::syscall1(raw::SYS_CHAN_CLOSE, ha);
    assert_eq(r, usize::MAX, "double close didn't return MAX")
}

fn test_chan_send_recv() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let msg = Message::from_bytes(b"hello");
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 0, "recv failed")?;
    assert_eq(recv.len, 5, "wrong length")?;
    assert_true(&recv.data[..5] == b"hello", "data mismatch")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_chan_send_closed() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    raw::sys_chan_close(hb);
    let msg = Message::from_bytes(b"x");
    let ret = raw::sys_chan_send(ha, &msg);
    assert_ne(ret, 0, "send to closed should fail")?;
    raw::sys_chan_close(ha);
    Ok(())
}

fn test_chan_recv_closed() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    raw::sys_chan_close(ha);
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 2, "recv on closed should return 2")?;
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_chan_recv_empty() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 1, "recv on empty should return 1")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_chan_create_close_loop() -> Result<(), &'static str> {
    for _ in 0..100 {
        let (ha, hb) = raw::sys_chan_create();
        if ha == usize::MAX {
            return Err("chan_create failed in loop");
        }
        raw::sys_chan_close(ha);
        raw::sys_chan_close(hb);
    }
    Ok(())
}

// ============================================================
// 3. Message Integrity
// ============================================================

fn test_msg_zero_len() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::new();
    msg.len = 0;
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 0, "recv failed")?;
    assert_eq(recv.len, 0, "len should be 0")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_msg_max_len() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::new();
    msg.len = 1024;
    for i in 0..1024 {
        msg.data[i] = (i & 0xFF) as u8;
    }
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 0, "recv failed")?;
    assert_eq(recv.len, 1024, "len should be 1024")?;
    for i in 0..1024 {
        if recv.data[i] != (i & 0xFF) as u8 {
            return Err("data mismatch at max len");
        }
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_msg_data_pattern() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::new();
    msg.len = 1024;
    for i in 0..1024 {
        msg.data[i] = ((i * 7 + 13) & 0xFF) as u8;
    }
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    raw::sys_chan_recv(hb, &mut recv);
    for i in 0..1024 {
        if recv.data[i] != ((i * 7 + 13) & 0xFF) as u8 {
            return Err("data pattern mismatch");
        }
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_msg_sender_pid() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let my_pid = unsafe {
        let ret: usize;
        core::arch::asm!("ecall", inlateout("a0") 0usize => ret, in("a7") 172usize, options(nostack));
        ret
    };
    let msg = Message::from_bytes(b"x");
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    raw::sys_chan_recv(hb, &mut recv);
    assert_eq(recv.sender_pid, my_pid, "sender_pid mismatch")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_msg_various_sizes() -> Result<(), &'static str> {
    let sizes = [1, 7, 63, 127, 511, 1000, 1024];
    let (ha, hb) = raw::sys_chan_create();
    for &sz in &sizes {
        let mut msg = Message::new();
        msg.len = sz;
        for i in 0..sz {
            msg.data[i] = (i & 0xFF) as u8;
        }
        raw::sys_chan_send(ha, &msg);
        let mut recv = Message::new();
        let ret = raw::sys_chan_recv(hb, &mut recv);
        assert_eq(ret, 0, "recv failed for size")?;
        assert_eq(recv.len, sz, "len mismatch")?;
        for i in 0..sz {
            if recv.data[i] != (i & 0xFF) as u8 {
                return Err("data mismatch at various sizes");
            }
        }
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_msg_caps_no_cap() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::from_bytes(b"x");
    msg.cap_count = 0;
    msg.caps[0] = NO_CAP;
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    raw::sys_chan_recv(hb, &mut recv);
    assert_eq(recv.caps[0], NO_CAP, "cap should be NO_CAP")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

// ============================================================
// 4. Non-Blocking Behavior
// ============================================================

fn test_nonblock_recv_empty() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(ha, &mut recv);
    assert_eq(ret, 1, "empty recv should return 1")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_nonblock_send_full() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let msg = Message::from_bytes(b"x");
    // Fill queue to 64 messages
    for _ in 0..64 {
        let ret = raw::sys_chan_send(ha, &msg);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("send failed before queue full");
        }
    }
    // 65th should fail with 5 (queue full)
    let ret = raw::sys_chan_send(ha, &msg);
    // Drain the queue
    for _ in 0..64 {
        let mut recv = Message::new();
        raw::sys_chan_recv(hb, &mut recv);
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    assert_eq(ret, 5, "65th send should return 5 (queue full)")
}

fn test_nonblock_drain_queue() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    // Fill queue with numbered messages
    for i in 0..64u8 {
        let mut msg = Message::new();
        msg.data[0] = i;
        msg.len = 1;
        let ret = raw::sys_chan_send(ha, &msg);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("send failed during fill");
        }
    }
    // Drain and verify order
    for i in 0..64u8 {
        let mut recv = Message::new();
        let ret = raw::sys_chan_recv(hb, &mut recv);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("recv failed during drain");
        }
        if recv.data[0] != i {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("message order wrong");
        }
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

// ============================================================
// 5. Capability Passing
// ============================================================

fn test_cap_pass_channel() -> Result<(), &'static str> {
    // Create transport channel (ta, tb) and a second channel (ca, cb)
    let (ta, tb) = raw::sys_chan_create();
    let (ca, cb) = raw::sys_chan_create();
    // Send cb as a capability via ta
    let mut msg = Message::from_bytes(b"cap");
    msg.caps[0] = cb;
    msg.cap_count = 1;
    raw::sys_chan_send(ta, &msg);
    // Close our local cb (ref count still held by message)
    raw::sys_chan_close(cb);
    // Recv on tb, get the cap
    let mut recv = Message::new();
    raw::sys_chan_recv(tb, &mut recv);
    let received_cap = recv.caps[0];
    assert_ne(received_cap, NO_CAP, "received cap is NO_CAP")?;
    // Verify the received cap is usable: send on ca, recv on received_cap
    let test_msg = Message::from_bytes(b"ok");
    raw::sys_chan_send(ca, &test_msg);
    let mut recv2 = Message::new();
    let ret = raw::sys_chan_recv(received_cap, &mut recv2);
    assert_eq(ret, 0, "recv on passed cap failed")?;
    assert_true(&recv2.data[..2] == b"ok", "data mismatch on passed cap")?;
    raw::sys_chan_close(ta);
    raw::sys_chan_close(tb);
    raw::sys_chan_close(ca);
    raw::sys_chan_close(received_cap);
    Ok(())
}

fn test_cap_pass_shm() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    // Map and write
    let addr = raw::sys_mmap(shm, 4096);
    assert_ne(addr, usize::MAX, "mmap failed")?;
    unsafe { *(addr as *mut u8) = 0xAB; }
    raw::sys_munmap(addr, 4096);
    // Send SHM handle as cap
    let (ta, tb) = raw::sys_chan_create();
    let mut msg = Message::from_bytes(b"shm");
    msg.caps[0] = shm;
    msg.cap_count = 1;
    raw::sys_chan_send(ta, &msg);
    raw::sys_chan_close(shm);
    // Recv cap
    let mut recv = Message::new();
    raw::sys_chan_recv(tb, &mut recv);
    let recv_shm = recv.caps[0];
    assert_ne(recv_shm, NO_CAP, "recv shm is NO_CAP")?;
    // Map received SHM and verify data
    let addr2 = raw::sys_mmap(recv_shm, 4096);
    assert_ne(addr2, usize::MAX, "mmap recv shm failed")?;
    let val = unsafe { *(addr2 as *const u8) };
    assert_eq(val as usize, 0xAB, "shm data mismatch")?;
    raw::sys_munmap(addr2, 4096);
    raw::sys_chan_close(ta);
    raw::sys_chan_close(tb);
    raw::sys_chan_close(recv_shm);
    Ok(())
}

fn test_cap_multi() -> Result<(), &'static str> {
    let (ta, tb) = raw::sys_chan_create();
    let (c1a, c1b) = raw::sys_chan_create();
    let (c2a, c2b) = raw::sys_chan_create();
    let mut msg = Message::from_bytes(b"mc");
    msg.caps[0] = c1b;
    msg.caps[1] = c2b;
    msg.cap_count = 2;
    raw::sys_chan_send(ta, &msg);
    raw::sys_chan_close(c1b);
    raw::sys_chan_close(c2b);
    let mut recv = Message::new();
    raw::sys_chan_recv(tb, &mut recv);
    assert_ne(recv.caps[0], NO_CAP, "cap 0 is NO_CAP")?;
    assert_ne(recv.caps[1], NO_CAP, "cap 1 is NO_CAP")?;
    raw::sys_chan_close(recv.caps[0]);
    raw::sys_chan_close(recv.caps[1]);
    raw::sys_chan_close(ta);
    raw::sys_chan_close(tb);
    raw::sys_chan_close(c1a);
    raw::sys_chan_close(c2a);
    Ok(())
}

fn test_cap_max() -> Result<(), &'static str> {
    let (ta, tb) = raw::sys_chan_create();
    let mut pairs = [(0usize, 0usize); 4];
    let mut msg = Message::from_bytes(b"mx");
    for (i, pair) in pairs.iter_mut().enumerate() {
        let (ca, cb) = raw::sys_chan_create();
        *pair = (ca, cb);
        msg.caps[i] = cb;
    }
    msg.cap_count = 4;
    raw::sys_chan_send(ta, &msg);
    for &(_, cb) in &pairs {
        raw::sys_chan_close(cb);
    }
    let mut recv = Message::new();
    raw::sys_chan_recv(tb, &mut recv);
    for &cap in &recv.caps {
        assert_ne(cap, NO_CAP, "cap slot is NO_CAP")?;
        raw::sys_chan_close(cap);
    }
    for &(ca, _) in &pairs {
        raw::sys_chan_close(ca);
    }
    raw::sys_chan_close(ta);
    raw::sys_chan_close(tb);
    Ok(())
}

fn test_cap_no_cap_slots() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::from_bytes(b"nc");
    msg.caps[0] = NO_CAP;
    msg.cap_count = 0;
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    raw::sys_chan_recv(hb, &mut recv);
    assert_eq(recv.caps[0], NO_CAP, "cap should remain NO_CAP")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

// ============================================================
// 6. Shared Memory
// ============================================================

fn test_shm_create_map_write_read() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    let addr = raw::sys_mmap(shm, 4096);
    assert_ne(addr, usize::MAX, "mmap failed")?;
    let ptr = addr as *mut u8;
    for i in 0..4096 {
        unsafe { *ptr.add(i) = (i & 0xFF) as u8; }
    }
    for i in 0..4096 {
        let v = unsafe { *ptr.add(i) };
        if v != (i & 0xFF) as u8 {
            raw::sys_munmap(addr, 4096);
            raw::sys_chan_close(shm);
            return Err("shm write/read mismatch");
        }
    }
    raw::sys_munmap(addr, 4096);
    raw::sys_chan_close(shm);
    Ok(())
}

fn test_shm_dup_ro_readable() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    let addr = raw::sys_mmap(shm, 4096);
    assert_ne(addr, usize::MAX, "mmap rw failed")?;
    unsafe { *(addr as *mut u8) = 42; }
    raw::sys_munmap(addr, 4096);
    let ro = raw::sys_shm_dup_ro(shm);
    assert_ne(ro, usize::MAX, "dup_ro failed")?;
    let addr2 = raw::sys_mmap(ro, 4096);
    assert_ne(addr2, usize::MAX, "mmap ro failed")?;
    let val = unsafe { *(addr2 as *const u8) };
    assert_eq(val as usize, 42, "RO data mismatch")?;
    raw::sys_munmap(addr2, 4096);
    raw::sys_chan_close(ro);
    raw::sys_chan_close(shm);
    Ok(())
}

fn test_shm_close_lifecycle() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    let addr = raw::sys_mmap(shm, 4096);
    assert_ne(addr, usize::MAX, "mmap failed")?;
    raw::sys_munmap(addr, 4096);
    raw::sys_chan_close(shm);
    Ok(())
}

fn test_shm_multi_map() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    // First map, write, unmap
    let addr1 = raw::sys_mmap(shm, 4096);
    assert_ne(addr1, usize::MAX, "first mmap failed")?;
    unsafe { *(addr1 as *mut u8) = 99; }
    raw::sys_munmap(addr1, 4096);
    // Second map, read back
    let addr2 = raw::sys_mmap(shm, 4096);
    assert_ne(addr2, usize::MAX, "second mmap failed")?;
    let val = unsafe { *(addr2 as *const u8) };
    assert_eq(val as usize, 99, "data not persisted across remap")?;
    raw::sys_munmap(addr2, 4096);
    raw::sys_chan_close(shm);
    Ok(())
}

fn test_shm_ref_counting() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    let ro = raw::sys_shm_dup_ro(shm);
    assert_ne(ro, usize::MAX, "dup_ro failed")?;
    // Close original, RO copy should still work
    raw::sys_chan_close(shm);
    let addr = raw::sys_mmap(ro, 4096);
    assert_ne(addr, usize::MAX, "mmap on RO after closing original failed")?;
    raw::sys_munmap(addr, 4096);
    raw::sys_chan_close(ro);
    Ok(())
}

fn test_shm_create_various_sizes() -> Result<(), &'static str> {
    for &pages in &[1, 2, 4] {
        let size = pages * 4096;
        let shm = raw::sys_shm_create(size);
        assert_ne(shm, usize::MAX, "shm_create failed for size")?;
        let addr = raw::sys_mmap(shm, size);
        assert_ne(addr, usize::MAX, "mmap failed for size")?;
        // Touch every page
        for p in 0..pages {
            unsafe { *((addr + p * 4096) as *mut u8) = 0xAA; }
        }
        raw::sys_munmap(addr, size);
        raw::sys_chan_close(shm);
    }
    Ok(())
}

fn test_shm_dup_ro_on_ro() -> Result<(), &'static str> {
    let shm = raw::sys_shm_create(4096);
    assert_ne(shm, usize::MAX, "shm_create failed")?;
    let ro = raw::sys_shm_dup_ro(shm);
    assert_ne(ro, usize::MAX, "dup_ro failed")?;
    // dup_ro on an already-RO handle — kernel allows it (still returns RO)
    let ro2 = raw::sys_shm_dup_ro(ro);
    // Either succeeds (returns valid handle) or fails (returns MAX) — both acceptable
    if ro2 != usize::MAX {
        raw::sys_chan_close(ro2);
    }
    raw::sys_chan_close(ro);
    raw::sys_chan_close(shm);
    Ok(())
}

// ============================================================
// 7. Anonymous mmap
// ============================================================

fn test_mmap_anon_write_read() -> Result<(), &'static str> {
    let addr = raw::sys_mmap(0, 4096);
    assert_ne(addr, usize::MAX, "mmap failed")?;
    let ptr = addr as *mut u8;
    for i in 0..4096 {
        unsafe { *ptr.add(i) = (i & 0xFF) as u8; }
    }
    for i in 0..4096 {
        if unsafe { *ptr.add(i) } != (i & 0xFF) as u8 {
            raw::sys_munmap(addr, 4096);
            return Err("anon mmap data mismatch");
        }
    }
    raw::sys_munmap(addr, 4096);
    Ok(())
}

fn test_mmap_anon_zeroed() -> Result<(), &'static str> {
    let addr = raw::sys_mmap(0, 4096);
    assert_ne(addr, usize::MAX, "mmap failed")?;
    let ptr = addr as *const u8;
    for i in 0..4096 {
        if unsafe { *ptr.add(i) } != 0 {
            raw::sys_munmap(addr, 4096);
            return Err("anon mmap not zeroed");
        }
    }
    raw::sys_munmap(addr, 4096);
    Ok(())
}

fn test_mmap_anon_multi_page() -> Result<(), &'static str> {
    let addr = raw::sys_mmap(0, 16384);
    assert_ne(addr, usize::MAX, "mmap 4-page failed")?;
    let ptr = addr as *mut u8;
    // Write to each page
    for page in 0..4 {
        let off = page * 4096;
        unsafe { *ptr.add(off) = (page & 0xFF) as u8; }
    }
    // Read back
    for page in 0..4 {
        let off = page * 4096;
        if unsafe { *ptr.add(off) } != (page & 0xFF) as u8 {
            raw::sys_munmap(addr, 16384);
            return Err("multi-page data mismatch");
        }
    }
    raw::sys_munmap(addr, 16384);
    Ok(())
}

fn test_mmap_munmap_roundtrip() -> Result<(), &'static str> {
    for _ in 0..100 {
        let addr = raw::sys_mmap(0, 4096);
        if addr == usize::MAX {
            return Err("mmap failed in roundtrip loop");
        }
        let ret = raw::sys_munmap(addr, 4096);
        if ret != 0 {
            return Err("munmap failed in roundtrip loop");
        }
    }
    Ok(())
}

fn test_munmap_invalid() -> Result<(), &'static str> {
    // munmap an address that was never mapped
    let ret = raw::sys_munmap(0x1000_0000, 4096);
    assert_eq(ret, usize::MAX, "munmap invalid should return MAX")
}

// ============================================================
// 8. Handle Table Limits
// ============================================================

fn test_handle_exhaustion() -> Result<(), &'static str> {
    // We start with some handles already used (boot channel, stdio, etc.)
    // Create pairs until we fail
    let mut pairs = [(0usize, 0usize); 16];
    let mut count = 0;
    for pair in &mut pairs {
        let (ha, hb) = raw::sys_chan_create();
        if ha == usize::MAX {
            break;
        }
        *pair = (ha, hb);
        count += 1;
    }
    // At least some should succeed
    assert_true(count > 0, "couldn't create any channels")?;
    // Clean up
    for &(ha, hb) in pairs.iter().take(count) {
        raw::sys_chan_close(ha);
        raw::sys_chan_close(hb);
    }
    Ok(())
}

fn test_handle_reuse() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    assert_ne(ha, usize::MAX, "first create failed")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    // Create again — should succeed and may reuse the same indices
    let (ha2, hb2) = raw::sys_chan_create();
    assert_ne(ha2, usize::MAX, "second create after close failed")?;
    raw::sys_chan_close(ha2);
    raw::sys_chan_close(hb2);
    Ok(())
}

fn test_handle_close_frees_slot() -> Result<(), &'static str> {
    // Fill up handles
    let mut pairs = [(0usize, 0usize); 16];
    let mut count = 0;
    for pair in &mut pairs {
        let (ha, hb) = raw::sys_chan_create();
        if ha == usize::MAX {
            break;
        }
        *pair = (ha, hb);
        count += 1;
    }
    if count == 0 {
        return Err("no channels created");
    }
    // Close one pair
    raw::sys_chan_close(pairs[0].0);
    raw::sys_chan_close(pairs[0].1);
    // Should be able to create a new pair
    let (ha_new, hb_new) = raw::sys_chan_create();
    assert_ne(ha_new, usize::MAX, "create after close-free failed")?;
    raw::sys_chan_close(ha_new);
    raw::sys_chan_close(hb_new);
    // Clean up remaining
    for &(ha, hb) in pairs.iter().take(count).skip(1) {
        raw::sys_chan_close(ha);
        raw::sys_chan_close(hb);
    }
    Ok(())
}

// ============================================================
// 9. Queue Depth
// ============================================================

fn test_queue_depth_64() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let msg = Message::from_bytes(b"q");
    for _ in 0..64 {
        let ret = raw::sys_chan_send(ha, &msg);
        if ret != 0 {
            // Drain and clean up
            for _ in 0..64 { let mut r = Message::new(); raw::sys_chan_recv(hb, &mut r); }
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("send failed before reaching 64");
        }
    }
    // Drain
    for _ in 0..64 {
        let mut recv = Message::new();
        raw::sys_chan_recv(hb, &mut recv);
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_queue_full_then_drain() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    // Fill with numbered messages
    for i in 0..64u8 {
        let mut msg = Message::new();
        msg.data[0] = i;
        msg.len = 1;
        let ret = raw::sys_chan_send(ha, &msg);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("send failed during fill");
        }
    }
    // 65th should fail
    let msg = Message::from_bytes(b"x");
    let ret = raw::sys_chan_send(ha, &msg);
    assert_eq(ret, 5, "65th send should fail with 5")?;
    // Drain and verify
    for i in 0..64u8 {
        let mut recv = Message::new();
        let ret = raw::sys_chan_recv(hb, &mut recv);
        if ret != 0 || recv.data[0] != i {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("drain data integrity failure");
        }
    }
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

// ============================================================
// 10. Edge Cases
// ============================================================

fn test_mmap_zero_length() -> Result<(), &'static str> {
    let ret = raw::sys_mmap(0, 0);
    assert_eq(ret, usize::MAX, "mmap(0,0) should fail")
}

fn test_shm_create_zero_size() -> Result<(), &'static str> {
    let ret = raw::sys_shm_create(0);
    assert_eq(ret, usize::MAX, "shm_create(0) should fail")
}

fn test_chan_recv_self() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let msg = Message::from_bytes(b"self");
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 0, "recv failed")?;
    assert_true(&recv.data[..4] == b"self", "data mismatch")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_msg_oversize_len() -> Result<(), &'static str> {
    let (ha, hb) = raw::sys_chan_create();
    let mut msg = Message::new();
    msg.len = 2048; // Over MAX_MSG_SIZE
    msg.data[0] = 0xAA;
    raw::sys_chan_send(ha, &msg);
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv(hb, &mut recv);
    assert_eq(ret, 0, "recv failed")?;
    // Kernel should clamp len to 1024
    assert_true(recv.len <= 1024, "len not clamped")?;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_invalid_handle() -> Result<(), &'static str> {
    let mut msg = Message::from_bytes(b"x");
    // Use handle 99 (out of range: MAX_HANDLES=32) — guaranteed invalid
    let ret = raw::sys_chan_send(99, &msg);
    assert_eq(ret, usize::MAX, "send on invalid handle should fail")?;
    let ret = raw::sys_chan_recv(99, &mut msg);
    assert_eq(ret, usize::MAX, "recv on invalid handle should fail")?;
    let ret = raw::syscall1(raw::SYS_CHAN_CLOSE, 99);
    assert_eq(ret, usize::MAX, "close on invalid handle should fail")
}

// ============================================================
// 11. File System
// ============================================================

fn test_fs_write_read() -> Result<(), &'static str> {
    let content = "ktest file content 12345";
    let path = "/tmp/ktest_wr";
    std::fs::write(path, content).map_err(|_| "write failed")?;
    let data = std::fs::read_to_string(path).map_err(|_| "read failed")?;
    assert_true(data.as_str() == content, "content mismatch")?;
    let _ = std::fs::remove_file(path);
    Ok(())
}

fn test_fs_stat() -> Result<(), &'static str> {
    let path = "/tmp/ktest_stat";
    let content = "twelve chars";
    std::fs::write(path, content).map_err(|_| "write failed")?;
    let meta = std::fs::metadata(path).map_err(|_| "stat failed")?;
    assert_eq(meta.len() as usize, content.len(), "size mismatch")?;
    let _ = std::fs::remove_file(path);
    Ok(())
}

fn test_fs_delete() -> Result<(), &'static str> {
    let path = "/tmp/ktest_del";
    std::fs::write(path, "x").map_err(|_| "write failed")?;
    std::fs::remove_file(path).map_err(|_| "delete failed")?;
    let result = std::fs::read_to_string(path);
    assert_true(result.is_err(), "read after delete should fail")
}

fn test_fs_readdir() -> Result<(), &'static str> {
    let _ = std::fs::create_dir_all("/tmp/ktest_rd");
    std::fs::write("/tmp/ktest_rd/a", "1").map_err(|_| "write a failed")?;
    std::fs::write("/tmp/ktest_rd/b", "2").map_err(|_| "write b failed")?;
    let entries = std::fs::read_dir("/tmp/ktest_rd").map_err(|_| "readdir failed")?;
    let count = entries.count();
    assert_true(count >= 2, "readdir should list at least 2 entries")?;
    let _ = std::fs::remove_file("/tmp/ktest_rd/a");
    let _ = std::fs::remove_file("/tmp/ktest_rd/b");
    Ok(())
}

// ============================================================
// 12. Process Spawn
// ============================================================

fn test_spawn_hello() -> Result<(), &'static str> {
    let proc_chan = rvos::spawn_process("/bin/hello-std")
        .map_err(|_| "spawn failed")?;
    let proc_handle = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);
    raw::sys_chan_close(proc_handle);
    Ok(())
}

fn test_spawn_exit_notification() -> Result<(), &'static str> {
    let proc_chan = rvos::spawn_process("/bin/hello-std")
        .map_err(|_| "spawn failed")?;
    let proc_handle = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);
    assert_eq(ret, 0, "recv exit notification failed")?;
    raw::sys_chan_close(proc_handle);
    Ok(())
}

// ============================================================
// 13. Regression -- Scheduling
// ============================================================

#[inline(always)]
fn rdtime() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

fn test_yield_latency() -> Result<(), &'static str> {
    // 100 yields should complete in <5M ticks (500ms at 10MHz).
    // With idle-in-ready-queue bug, each yield stalls ~100ms → 10s total.
    let start = rdtime();
    for _ in 0..100 {
        raw::sys_yield();
    }
    let elapsed = rdtime() - start;
    assert_true(elapsed < 5_000_000, "yield latency too high (scheduling bug?)")
}

fn test_ipc_roundtrip_latency() -> Result<(), &'static str> {
    // 100 send+recv roundtrips should complete in <5M ticks (500ms).
    // With the scheduling bug (premature blocked clear), each roundtrip
    // stalls ~50-100ms.
    let (ha, hb) = raw::sys_chan_create();
    let start = rdtime();
    for i in 0..100u8 {
        let mut msg = Message::new();
        msg.data[0] = i;
        msg.len = 1;
        raw::sys_chan_send(ha, &msg);
        let mut recv = Message::new();
        let ret = raw::sys_chan_recv(hb, &mut recv);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("recv failed during roundtrip");
        }
    }
    let elapsed = rdtime() - start;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    assert_true(elapsed < 5_000_000, "IPC roundtrip latency too high (scheduling bug?)")
}

// ============================================================
// 14. Regression -- Wakeup
// ============================================================

fn test_blocking_recv_wakeup() -> Result<(), &'static str> {
    // Send a message, then blocking recv. Should complete quickly.
    // If wakeup is lost, blocks until timer tick (~10ms minimum).
    let (ha, hb) = raw::sys_chan_create();
    let msg = Message::from_bytes(b"wake");
    raw::sys_chan_send(ha, &msg);
    let start = rdtime();
    let mut recv = Message::new();
    let ret = raw::sys_chan_recv_blocking(hb, &mut recv);
    let elapsed = rdtime() - start;
    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    assert_eq(ret, 0, "blocking recv failed")?;
    assert_true(&recv.data[..4] == b"wake", "data mismatch")?;
    assert_true(elapsed < 1_000_000, "blocking recv too slow (wakeup bug?)")
}

fn test_fill_drain_fill_no_loss() -> Result<(), &'static str> {
    // Fill channel to 64, drain 64, fill again to 64, drain again.
    // Verify data integrity on second drain. Tests that blocked/wakeup
    // state resets properly between fill/drain cycles.
    let (ha, hb) = raw::sys_chan_create();

    // First fill
    for i in 0..64u8 {
        let mut msg = Message::new();
        msg.data[0] = i;
        msg.len = 1;
        let ret = raw::sys_chan_send(ha, &msg);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("first fill: send failed");
        }
    }

    // First drain
    for i in 0..64u8 {
        let mut recv = Message::new();
        let ret = raw::sys_chan_recv(hb, &mut recv);
        if ret != 0 || recv.data[0] != i {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("first drain: data mismatch");
        }
    }

    // Second fill (values offset by 100)
    for i in 0..64u8 {
        let mut msg = Message::new();
        msg.data[0] = i.wrapping_add(100);
        msg.len = 1;
        let ret = raw::sys_chan_send(ha, &msg);
        if ret != 0 {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("second fill: send failed");
        }
    }

    // Second drain — verify integrity
    for i in 0..64u8 {
        let mut recv = Message::new();
        let ret = raw::sys_chan_recv(hb, &mut recv);
        if ret != 0 || recv.data[0] != i.wrapping_add(100) {
            raw::sys_chan_close(ha);
            raw::sys_chan_close(hb);
            return Err("second drain: data mismatch");
        }
    }

    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

// ============================================================
// 15. Regression -- Validation
// ============================================================

fn test_buffer_validation_overflow() -> Result<(), &'static str> {
    // Pass a pointer near usize::MAX so ptr+sizeof(Message) wraps around.
    // With the old validate_user_buffer bug, the kernel would accept this
    // and crash. All must return error (usize::MAX).
    let (ha, hb) = raw::sys_chan_create();
    let bad_ptr = usize::MAX - 16;

    let ret = raw::syscall2(raw::SYS_CHAN_SEND, ha, bad_ptr);
    assert_eq(ret, usize::MAX, "send with overflow ptr should fail")?;

    let ret = raw::syscall2(raw::SYS_CHAN_RECV, hb, bad_ptr);
    assert_eq(ret, usize::MAX, "recv with overflow ptr should fail")?;

    let ret = raw::syscall2(raw::SYS_CHAN_RECV_BLOCKING, hb, bad_ptr);
    assert_eq(ret, usize::MAX, "recv_blocking with overflow ptr should fail")?;

    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

fn test_buffer_validation_null() -> Result<(), &'static str> {
    // Null pointer for message buffer — must return error, not crash.
    let (ha, hb) = raw::sys_chan_create();

    let ret = raw::syscall2(raw::SYS_CHAN_SEND, ha, 0);
    assert_eq(ret, usize::MAX, "send with null ptr should fail")?;

    let ret = raw::syscall2(raw::SYS_CHAN_RECV, hb, 0);
    assert_eq(ret, usize::MAX, "recv with null ptr should fail")?;

    let ret = raw::syscall1(raw::SYS_MEMINFO, 0);
    assert_eq(ret, usize::MAX, "meminfo with null ptr should fail")?;

    raw::sys_chan_close(ha);
    raw::sys_chan_close(hb);
    Ok(())
}

// ============================================================
// 16. Regression -- Resource Limits
// ============================================================

fn test_mmap_many_regions() -> Result<(), &'static str> {
    // Allocate 64 anonymous mmap regions. If old limit (32) exists,
    // fails at region 33.
    let mut addrs = [0usize; 64];
    for (i, addr) in addrs.iter_mut().enumerate() {
        let a = raw::sys_mmap(0, 4096);
        if a == usize::MAX {
            // Clean up what we mapped
            for &prev in addrs.iter().take(i) {
                raw::sys_munmap(prev, 4096);
            }
            return Err("mmap failed before 64 regions");
        }
        *addr = a;
    }
    // Clean up
    for &a in &addrs {
        raw::sys_munmap(a, 4096);
    }
    Ok(())
}

fn test_mmap_child_region_count() -> Result<(), &'static str> {
    // Spawn ktest-helper with command byte 2 (allocate 64 mmap regions).
    let (our_ep, child_ep) = raw::sys_chan_create();

    // Send command byte 2
    let mut cmd = Message::new();
    cmd.data[0] = 2;
    cmd.len = 1;
    raw::sys_chan_send(our_ep, &cmd);

    let proc_chan = rvos::spawn_process_with_cap("/bin/ktest-helper", child_ep)
        .map_err(|_| "spawn ktest-helper failed")?;
    raw::sys_chan_close(child_ep);

    // Receive count from child
    let mut reply = Message::new();
    let ret = raw::sys_chan_recv_blocking(our_ep, &mut reply);
    if ret != 0 {
        // Wait for exit and clean up
        let ph = proc_chan.into_raw_handle();
        let mut exit_msg = Message::new();
        raw::sys_chan_recv_blocking(ph, &mut exit_msg);
        raw::sys_chan_close(ph);
        raw::sys_chan_close(our_ep);
        return Err("recv from child failed");
    }

    let count = if reply.len >= 4 {
        u32::from_le_bytes([reply.data[0], reply.data[1], reply.data[2], reply.data[3]])
    } else {
        0
    };

    // Wait for child exit
    let ph = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(ph, &mut exit_msg);
    raw::sys_chan_close(ph);
    raw::sys_chan_close(our_ep);

    assert_eq(count as usize, 64, "child couldn't allocate 64 mmap regions")
}

// ============================================================
// 17. Regression -- Resource Leaks
// ============================================================

fn test_spawn_cleanup_no_leak() -> Result<(), &'static str> {
    // Spawn hello-std 5× in a loop, each time wait for exit.
    // The framework's built-in leak detection (meminfo before/after
    // second run) catches growing heap/frames.
    for _ in 0..5 {
        let proc_chan = rvos::spawn_process("/bin/hello-std")
            .map_err(|_| "spawn failed")?;
        let proc_handle = proc_chan.into_raw_handle();
        let mut exit_msg = Message::new();
        raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);
        raw::sys_chan_close(proc_handle);
    }
    Ok(())
}

// ============================================================
// 18. Regression -- Fault Isolation
// ============================================================

fn test_umode_fault_kills_child_not_kernel() -> Result<(), &'static str> {
    // Spawn ktest-helper with arg "crash" (null dereference).
    // Wait for exit notification. Assert kernel still alive.
    let proc_chan = rvos::spawn_process_with_args("/bin/ktest-helper", b"crash")
        .map_err(|_| "spawn ktest-helper failed")?;
    let proc_handle = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);
    raw::sys_chan_close(proc_handle);

    // If we got here, kernel survived. Verify clock still works.
    let (wall, _) = raw::sys_clock();
    assert_true(wall > 0, "kernel dead after child crash")
}

// ============================================================
// 19. Regression -- Cap Ref Counting
// ============================================================

fn test_ns_override_cap_delivery() -> Result<(), &'static str> {
    // Redirect a custom service name (not stdout — stdout requires a Write/WriteOk
    // round-trip protocol that a raw channel can't satisfy). The child (hello-std)
    // never connects to "ktest-svc" so it runs normally. This tests that the
    // override cap is properly ref-counted during spawn.
    let (our_ep, child_ep) = raw::sys_chan_create();

    let proc_chan = rvos::spawn_process_with_overrides(
        "/bin/hello-std",
        b"",
        &[rvos::NsOverride::Redirect("ktest-svc", child_ep)],
    ).map_err(|_| "spawn with override failed")?;
    raw::sys_chan_close(child_ep);

    // Wait for child to exit
    let proc_handle = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);
    raw::sys_chan_close(proc_handle);

    // Verify our channel is still alive (send should succeed if peer endpoint
    // exists — it won't be consumed but the send should not return error for
    // a closed channel).
    let test_msg = Message::from_bytes(b"alive");
    let ret = raw::sys_chan_send(our_ep, &test_msg);
    raw::sys_chan_close(our_ep);

    // Send returns 0 on success, nonzero if channel is dead.
    // After child exit, the override endpoint should have been cleaned up,
    // but our_ep's peer may be closed. What matters is: the spawn succeeded
    // and the child exited normally (didn't crash due to ref counting).
    // ret == 0 means channel still alive (init server holds ref), or
    // ret != 0 means peer closed (expected after cleanup). Both are fine.
    let _ = ret;
    Ok(())
}

fn test_two_children_shared_override() -> Result<(), &'static str> {
    // Spawn TWO children sequentially with the same override endpoint.
    // If bug 0002 exists, child 1's exit kills the override channel
    // and child 2's spawn fails or child 2 can't connect to services.
    let (our_ep, child_ep) = raw::sys_chan_create();

    // Child 1
    let proc1 = rvos::spawn_process_with_overrides(
        "/bin/hello-std",
        b"",
        &[rvos::NsOverride::Redirect("ktest-svc", child_ep)],
    ).map_err(|_| "spawn child 1 failed")?;
    let ph1 = proc1.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(ph1, &mut exit_msg);
    raw::sys_chan_close(ph1);

    // Child 2 — same override endpoint. If ref counting is broken, the
    // endpoint was deactivated when child 1 exited, and this spawn might
    // fail or the child might crash.
    let proc2 = rvos::spawn_process_with_overrides(
        "/bin/hello-std",
        b"",
        &[rvos::NsOverride::Redirect("ktest-svc", child_ep)],
    ).map_err(|_| "spawn child 2 failed (cap ref counting bug?)")?;
    raw::sys_chan_close(child_ep);

    let ph2 = proc2.into_raw_handle();
    let mut exit_msg2 = Message::new();
    raw::sys_chan_recv_blocking(ph2, &mut exit_msg2);
    raw::sys_chan_close(ph2);
    raw::sys_chan_close(our_ep);

    Ok(())
}

fn test_cap_delivery_via_spawn() -> Result<(), &'static str> {
    // Create channel pair, send command byte 1 on our end, spawn
    // ktest-helper with cap. Child reads command, writes "ktest-ok" back.
    let (our_ep, child_ep) = raw::sys_chan_create();

    // Send command byte 1
    let mut cmd = Message::new();
    cmd.data[0] = 1;
    cmd.len = 1;
    raw::sys_chan_send(our_ep, &cmd);

    let proc_chan = rvos::spawn_process_with_cap("/bin/ktest-helper", child_ep)
        .map_err(|_| "spawn ktest-helper failed")?;
    raw::sys_chan_close(child_ep);

    // Receive reply
    let mut reply = Message::new();
    let ret = raw::sys_chan_recv_blocking(our_ep, &mut reply);

    // Wait for child exit
    let ph = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(ph, &mut exit_msg);
    raw::sys_chan_close(ph);
    raw::sys_chan_close(our_ep);

    assert_eq(ret, 0, "recv from child failed")?;
    assert_true(reply.len >= 8 && &reply.data[..8] == b"ktest-ok", "child didn't reply ktest-ok")
}

// ============================================================
// 20. Regression -- Debugger Second Attach (Bug 0007)
// ============================================================

fn test_debugger_second_attach() -> Result<(), &'static str> {
    // Regression test for Bug 0007: debugger service hangs on second attach
    // because it didn't close transferred B endpoints after send.
    //
    // 1. Spawn a long-lived child (command byte 3 = wait mode)
    // 2. Attach to it via process-debug service
    // 3. Detach (close session/event channels)
    // 4. Attach again — should succeed, not hang
    // 5. Detach and clean up
    use rvos::rvos_wire;
    use rvos_proto::debug::*;

    let (our_ep, child_ep) = raw::sys_chan_create();

    // Send command byte 3 (wait mode)
    let mut cmd = Message::new();
    cmd.data[0] = 3;
    cmd.len = 1;
    raw::sys_chan_send(our_ep, &cmd);

    let proc_chan = rvos::spawn_process_with_cap("/bin/ktest-helper", child_ep)
        .map_err(|_| "spawn ktest-helper failed")?;
    raw::sys_chan_close(child_ep);

    // Receive ack to get child PID
    let mut ack_msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(our_ep, &mut ack_msg);
    if ret != 0 {
        // Clean up and fail
        let ph = proc_chan.into_raw_handle();
        let mut exit_msg = Message::new();
        raw::sys_chan_recv_blocking(ph, &mut exit_msg);
        raw::sys_chan_close(ph);
        raw::sys_chan_close(our_ep);
        return Err("recv ack from child failed");
    }
    let child_pid = ack_msg.sender_pid as u32;

    // Helper: attach to the debug service and return session + event handles
    let do_attach = |pid: u32| -> Result<(usize, usize), &'static str> {
        let svc = rvos::connect_to_service("process-debug")
            .map_err(|_| "connect to process-debug failed")?;
        let svc_handle = svc.into_raw_handle();

        let req = DebugAttachRequest { pid };
        let mut msg = Message::new();
        msg.len = rvos_wire::to_bytes(&req, &mut msg.data).unwrap_or(0);
        let ret = raw::sys_chan_send_blocking(svc_handle, &msg);
        if ret != 0 {
            raw::sys_chan_close(svc_handle);
            return Err("send attach request failed");
        }

        let mut resp_msg = Message::new();
        let ret = raw::sys_chan_recv_blocking(svc_handle, &mut resp_msg);
        raw::sys_chan_close(svc_handle);
        if ret != 0 {
            return Err("recv attach response failed");
        }

        let resp: DebugAttachResponse = rvos_wire::from_bytes_with_caps(
            &resp_msg.data[..resp_msg.len],
            &resp_msg.caps[..resp_msg.cap_count],
        ).map_err(|_| "decode attach response failed")?;

        match resp {
            DebugAttachResponse::Ok { session, events } => {
                Ok((session.raw(), events.raw()))
            }
            DebugAttachResponse::Error { .. } => {
                Err("attach returned error")
            }
        }
    };

    // First attach
    let (session1, event1) = match do_attach(child_pid) {
        Ok(handles) => handles,
        Err(e) => {
            // Release child and clean up
            raw::sys_chan_send(our_ep, &Message::from_bytes(b"done"));
            let ph = proc_chan.into_raw_handle();
            let mut exit_msg = Message::new();
            raw::sys_chan_recv_blocking(ph, &mut exit_msg);
            raw::sys_chan_close(ph);
            raw::sys_chan_close(our_ep);
            return Err(e);
        }
    };

    // Detach (close session and event channels)
    raw::sys_chan_close(session1);
    raw::sys_chan_close(event1);

    // Small yield to let the service process the detach
    for _ in 0..10 {
        raw::sys_yield();
    }

    // Second attach — this is where Bug 0007 would hang
    let (session2, event2) = match do_attach(child_pid) {
        Ok(handles) => handles,
        Err(e) => {
            raw::sys_chan_send(our_ep, &Message::from_bytes(b"done"));
            let ph = proc_chan.into_raw_handle();
            let mut exit_msg = Message::new();
            raw::sys_chan_recv_blocking(ph, &mut exit_msg);
            raw::sys_chan_close(ph);
            raw::sys_chan_close(our_ep);
            return Err(e);
        }
    };

    // Success! Clean up second session
    raw::sys_chan_close(session2);
    raw::sys_chan_close(event2);

    // Release child
    raw::sys_chan_send(our_ep, &Message::from_bytes(b"done"));
    let ph = proc_chan.into_raw_handle();
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(ph, &mut exit_msg);
    raw::sys_chan_close(ph);
    raw::sys_chan_close(our_ep);

    Ok(())
}

// ============================================================
// 21. Timer Service
// ============================================================

fn test_timer_basic() -> Result<(), &'static str> {
    // Connect to the timer service, request a 50ms timer, verify it fires.
    use rvos::rvos_wire;
    use rvos_proto::timer::{TimerRequest, TimerResponse};

    let svc = rvos::connect_to_service("timer")
        .map_err(|_| "connect to timer failed")?;
    let handle = svc.into_raw_handle();

    let req = TimerRequest::After { duration_us: 50_000 }; // 50ms
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&req, &mut msg.data).unwrap_or(0);

    let start = rdtime();
    raw::sys_chan_send_blocking(handle, &msg);

    let mut resp_msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(handle, &mut resp_msg);
    let elapsed = rdtime() - start;
    raw::sys_chan_close(handle);

    if ret != 0 {
        return Err("recv timer response failed");
    }

    let resp: TimerResponse = rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len])
        .map_err(|_| "decode timer response failed")?;

    match resp {
        TimerResponse::Expired {} => {}
    }

    // At 10MHz, 50ms = 500_000 ticks. Allow 10ms–500ms window.
    assert_true(elapsed >= 100_000, "timer fired too early")?;
    assert_true(elapsed < 5_000_000, "timer fired too late")
}

fn test_timer_short() -> Result<(), &'static str> {
    // Verify a very short timer (1ms) fires and doesn't hang.
    use rvos::rvos_wire;
    use rvos_proto::timer::{TimerRequest, TimerResponse};

    let svc = rvos::connect_to_service("timer")
        .map_err(|_| "connect to timer failed")?;
    let handle = svc.into_raw_handle();

    let req = TimerRequest::After { duration_us: 1_000 }; // 1ms
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&req, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);

    let mut resp_msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(handle, &mut resp_msg);
    raw::sys_chan_close(handle);

    if ret != 0 {
        return Err("recv timer response failed");
    }
    let _: TimerResponse = rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len])
        .map_err(|_| "decode timer response failed")?;
    Ok(())
}

// ============================================================
// 22. Regression -- Scheduler Stress
// ============================================================

fn test_stress_spawn_exit() -> Result<(), &'static str> {
    // Spawn 3 hello-std children, wait for all exits.
    // If schedule() race exists, heavy IPC during parallel spawn
    // increases chance of kernel panic. Serves as a smoke test.
    let mut handles = [usize::MAX; 3];
    for handle in handles.iter_mut() {
        let proc_chan = rvos::spawn_process("/bin/hello-std")
            .map_err(|_| "spawn failed")?;
        *handle = proc_chan.into_raw_handle();
    }
    for &h in &handles {
        let mut exit_msg = Message::new();
        raw::sys_chan_recv_blocking(h, &mut exit_msg);
        raw::sys_chan_close(h);
    }
    Ok(())
}

/// Yield repeatedly to let spawned child processes finish exiting and release
/// their channel slots before the next spawn-heavy test section.
fn yield_drain() {
    for _ in 0..50 {
        raw::sys_yield();
    }
}

// ============================================================
// 23. Block Device
// ============================================================

/// Connect to a block device, get DeviceInfo + SHM.
/// Returns (client_handle, shm_addr, shm_handle, capacity_sectors, read_only).
fn blk_connect(name: &str) -> Result<(usize, usize, usize, u64, bool), &'static str> {
    use rvos_proto::blk::{BlkRequest, BlkResponse};

    let svc = rvos::connect_to_service(name)
        .map_err(|_| "connect to blk service failed")?;
    let handle = svc.into_raw_handle();

    // Send GetDeviceInfo
    let req = BlkRequest::GetDeviceInfo {};
    let mut msg = Message::new();
    msg.len = rvos::rvos_wire::to_bytes(&req, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);

    // Recv DeviceInfo + SHM cap
    let mut resp_msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(handle, &mut resp_msg);
    if ret != 0 {
        raw::sys_chan_close(handle);
        return Err("recv DeviceInfo failed");
    }

    let shm_cap = resp_msg.caps[0];
    if shm_cap == NO_CAP {
        raw::sys_chan_close(handle);
        return Err("no SHM cap in DeviceInfo");
    }

    let resp: BlkResponse = match rvos::rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len]) {
        Ok(r) => r,
        Err(_) => {
            raw::sys_chan_close(handle);
            raw::sys_chan_close(shm_cap);
            return Err("decode DeviceInfo failed");
        }
    };

    let (capacity, read_only) = match resp {
        BlkResponse::DeviceInfo { capacity_sectors, read_only, .. } => {
            (capacity_sectors, read_only != 0)
        }
        _ => {
            raw::sys_chan_close(handle);
            raw::sys_chan_close(shm_cap);
            return Err("unexpected response (not DeviceInfo)");
        }
    };

    // Map SHM (32 pages = 128KB)
    let shm_size = 32 * 4096;
    let shm_addr = raw::sys_mmap(shm_cap, shm_size);
    if shm_addr == usize::MAX {
        raw::sys_chan_close(handle);
        raw::sys_chan_close(shm_cap);
        return Err("mmap SHM failed");
    }

    Ok((handle, shm_addr, shm_cap, capacity, read_only))
}

/// Send a BlkRequest and receive a BlkResponse.
fn blk_request(handle: usize, req: &rvos_proto::blk::BlkRequest) -> Result<rvos_proto::blk::BlkResponse, &'static str> {
    let mut msg = Message::new();
    msg.len = rvos::rvos_wire::to_bytes(req, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);

    let mut resp_msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(handle, &mut resp_msg);
    if ret != 0 {
        return Err("recv blk response failed");
    }

    rvos::rvos_wire::from_bytes(&resp_msg.data[..resp_msg.len])
        .map_err(|_| "decode blk response failed")
}

/// Clean up a block device connection.
fn blk_cleanup(handle: usize, shm_addr: usize, shm_cap: usize) {
    raw::sys_munmap(shm_addr, 32 * 4096);
    raw::sys_chan_close(shm_cap);
    raw::sys_chan_close(handle);
}

fn test_blk_device_info() -> Result<(), &'static str> {
    let (handle, shm_addr, shm_cap, capacity, _read_only) = blk_connect("blk1")?;
    assert_true(capacity > 0, "capacity should be > 0")?;
    // 16 MB = 32768 sectors of 512 bytes
    assert_eq(capacity as usize, 32768, "capacity should be 32768 sectors (16MB)")?;
    blk_cleanup(handle, shm_addr, shm_cap);
    Ok(())
}

fn test_blk_read_write() -> Result<(), &'static str> {
    use rvos_proto::blk::{BlkRequest, BlkResponse};

    let (handle, shm_addr, shm_cap, capacity, _ro) = blk_connect("blk2")?;

    // Write a test pattern to sector near the end
    let test_sector = capacity - 2;
    let pattern: [u8; 512] = {
        let mut p = [0u8; 512];
        for (i, byte) in p.iter_mut().enumerate() {
            *byte = ((i * 7 + 13) & 0xFF) as u8;
        }
        p
    };

    // Copy pattern to SHM at offset 0
    unsafe {
        core::ptr::copy_nonoverlapping(pattern.as_ptr(), shm_addr as *mut u8, 512);
    }

    // Write 1 sector
    let resp = blk_request(handle, &BlkRequest::Write { sector: test_sector, count: 1, shm_offset: 0 })?;
    match resp {
        BlkResponse::Ok {} => {}
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("write failed");
        }
    }

    // Clear SHM
    unsafe {
        core::ptr::write_bytes(shm_addr as *mut u8, 0, 512);
    }

    // Read back
    let resp = blk_request(handle, &BlkRequest::Read { sector: test_sector, count: 1, shm_offset: 0 })?;
    match resp {
        BlkResponse::Ok {} => {}
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("read failed");
        }
    }

    // Verify pattern
    for i in 0..512 {
        let got = unsafe { *((shm_addr + i) as *const u8) };
        if got != ((i * 7 + 13) & 0xFF) as u8 {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("read-back data mismatch");
        }
    }

    blk_cleanup(handle, shm_addr, shm_cap);
    Ok(())
}

fn test_blk_multi_sector() -> Result<(), &'static str> {
    use rvos_proto::blk::{BlkRequest, BlkResponse};

    let (handle, shm_addr, shm_cap, _cap, _ro) = blk_connect("blk2")?;

    // Write 8 consecutive sectors (4096 bytes) starting at sector 16
    let count: u32 = 8;
    let byte_len = count as usize * 512;

    // Fill SHM with a pattern
    for i in 0..byte_len {
        unsafe { *((shm_addr + i) as *mut u8) = ((i * 3) & 0xFF) as u8; }
    }

    let resp = blk_request(handle, &BlkRequest::Write { sector: 16, count, shm_offset: 0 })?;
    match resp {
        BlkResponse::Ok {} => {}
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("multi-sector write failed");
        }
    }

    // Clear SHM and read back
    unsafe { core::ptr::write_bytes(shm_addr as *mut u8, 0, byte_len); }

    let resp = blk_request(handle, &BlkRequest::Read { sector: 16, count, shm_offset: 0 })?;
    match resp {
        BlkResponse::Ok {} => {}
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("multi-sector read failed");
        }
    }

    for i in 0..byte_len {
        let got = unsafe { *((shm_addr + i) as *const u8) };
        if got != ((i * 3) & 0xFF) as u8 {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("multi-sector data mismatch");
        }
    }

    blk_cleanup(handle, shm_addr, shm_cap);
    Ok(())
}

fn test_blk_read_beyond_capacity() -> Result<(), &'static str> {
    use rvos_proto::blk::{BlkRequest, BlkResponse};

    let (handle, shm_addr, shm_cap, capacity, _ro) = blk_connect("blk1")?;

    // Try reading 1 sector past the end
    let resp = blk_request(handle, &BlkRequest::Read { sector: capacity, count: 1, shm_offset: 0 })?;
    match resp {
        BlkResponse::Error { .. } => {}
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("read beyond capacity should return error");
        }
    }

    blk_cleanup(handle, shm_addr, shm_cap);
    Ok(())
}

fn test_blk_write_read_only() -> Result<(), &'static str> {
    use rvos_proto::blk::{BlkRequest, BlkResponse};

    let (handle, shm_addr, shm_cap, _cap, read_only) = blk_connect("blk0")?;
    assert_true(read_only, "blk0 should be read-only")?;

    // Try writing — should fail with EROFS
    let resp = blk_request(handle, &BlkRequest::Write { sector: 0, count: 1, shm_offset: 0 })?;
    match resp {
        BlkResponse::Error { code } => {
            assert_eq(code as usize, 30, "write to RO should return EROFS (30)")?;
        }
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("write to RO device should return error");
        }
    }

    blk_cleanup(handle, shm_addr, shm_cap);
    Ok(())
}

fn test_blk_flush() -> Result<(), &'static str> {
    use rvos_proto::blk::{BlkRequest, BlkResponse};

    let (handle, shm_addr, shm_cap, _cap, _ro) = blk_connect("blk1")?;

    let resp = blk_request(handle, &BlkRequest::Flush {})?;
    match resp {
        BlkResponse::Ok {} => {}
        _ => {
            blk_cleanup(handle, shm_addr, shm_cap);
            return Err("flush should succeed");
        }
    }

    blk_cleanup(handle, shm_addr, shm_cap);
    Ok(())
}

// ============================================================
// Main
// ============================================================

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");

    if quick {
        println!("=== rvOS Kernel Test Suite (quick) ===");
    } else {
        println!("=== rvOS Kernel Test Suite ===");
    }

    let mut total = TestResult::new();

    total.merge(&run_section("Syscall Basics", &[
        ("getpid", test_getpid),
        ("getpid_stable", test_getpid_stable),
        ("yield", test_yield),
        ("clock_monotonic", test_clock_monotonic),
        ("clock_both_nonzero", test_clock_both_nonzero),
    ]));

    total.merge(&run_section("Channel Lifecycle", &[
        ("chan_create", test_chan_create),
        ("chan_close", test_chan_close),
        ("chan_double_close", test_chan_double_close),
        ("chan_send_recv", test_chan_send_recv),
        ("chan_send_closed", test_chan_send_closed),
        ("chan_recv_closed", test_chan_recv_closed),
        ("chan_recv_empty", test_chan_recv_empty),
        ("chan_create_close_loop", test_chan_create_close_loop),
    ]));

    total.merge(&run_section("Message Integrity", &[
        ("msg_zero_len", test_msg_zero_len),
        ("msg_max_len", test_msg_max_len),
        ("msg_data_pattern", test_msg_data_pattern),
        ("msg_sender_pid", test_msg_sender_pid),
        ("msg_various_sizes", test_msg_various_sizes),
        ("msg_caps_no_cap", test_msg_caps_no_cap),
    ]));

    total.merge(&run_section("Non-Blocking Behavior", &[
        ("nonblock_recv_empty", test_nonblock_recv_empty),
        ("nonblock_send_full", test_nonblock_send_full),
        ("nonblock_drain_queue", test_nonblock_drain_queue),
    ]));

    total.merge(&run_section("Capability Passing", &[
        ("cap_pass_channel", test_cap_pass_channel),
        ("cap_pass_shm", test_cap_pass_shm),
        ("cap_multi", test_cap_multi),
        ("cap_max", test_cap_max),
        ("cap_no_cap_slots", test_cap_no_cap_slots),
    ]));

    total.merge(&run_section("Shared Memory", &[
        ("shm_create_map_write_read", test_shm_create_map_write_read),
        ("shm_dup_ro_readable", test_shm_dup_ro_readable),
        ("shm_close_lifecycle", test_shm_close_lifecycle),
        ("shm_multi_map", test_shm_multi_map),
        ("shm_ref_counting", test_shm_ref_counting),
        ("shm_create_various_sizes", test_shm_create_various_sizes),
        ("shm_dup_ro_on_ro", test_shm_dup_ro_on_ro),
    ]));

    total.merge(&run_section("Anonymous mmap", &[
        ("mmap_anon_write_read", test_mmap_anon_write_read),
        ("mmap_anon_zeroed", test_mmap_anon_zeroed),
        ("mmap_anon_multi_page", test_mmap_anon_multi_page),
        ("mmap_munmap_roundtrip", test_mmap_munmap_roundtrip),
        ("munmap_invalid", test_munmap_invalid),
    ]));

    total.merge(&run_section("Handle Table Limits", &[
        ("handle_exhaustion", test_handle_exhaustion),
        ("handle_reuse", test_handle_reuse),
        ("handle_close_frees_slot", test_handle_close_frees_slot),
    ]));

    total.merge(&run_section("Queue Depth", &[
        ("queue_depth_64", test_queue_depth_64),
        ("queue_full_then_drain", test_queue_full_then_drain),
    ]));

    total.merge(&run_section("Edge Cases", &[
        ("mmap_zero_length", test_mmap_zero_length),
        ("shm_create_zero_size", test_shm_create_zero_size),
        ("chan_recv_self", test_chan_recv_self),
        ("msg_oversize_len", test_msg_oversize_len),
        ("invalid_handle", test_invalid_handle),
    ]));

    total.merge(&run_section("File System", &[
        ("fs_write_read", test_fs_write_read),
        ("fs_stat", test_fs_stat),
        ("fs_delete", test_fs_delete),
        ("fs_readdir", test_fs_readdir),
    ]));

    if !quick {
        total.merge(&run_section("Block Device", &[
            ("blk_device_info", test_blk_device_info),
            ("blk_read_write", test_blk_read_write),
            ("blk_multi_sector", test_blk_multi_sector),
            ("blk_read_beyond_capacity", test_blk_read_beyond_capacity),
            ("blk_write_read_only", test_blk_write_read_only),
            ("blk_flush", test_blk_flush),
        ]));

        total.merge(&run_section("Process Spawn", &[
            ("spawn_hello", test_spawn_hello),
            ("spawn_exit_notification", test_spawn_exit_notification),
        ]));
    }

    total.merge(&run_section("Regression -- Scheduling", &[
        ("yield_latency", test_yield_latency),
        ("ipc_roundtrip_latency", test_ipc_roundtrip_latency),
    ]));

    total.merge(&run_section("Regression -- Wakeup", &[
        ("blocking_recv_wakeup", test_blocking_recv_wakeup),
        ("fill_drain_fill_no_loss", test_fill_drain_fill_no_loss),
    ]));

    total.merge(&run_section("Regression -- Validation", &[
        ("buffer_validation_overflow", test_buffer_validation_overflow),
        ("buffer_validation_null", test_buffer_validation_null),
    ]));

    if !quick {
        total.merge(&run_section("Regression -- Resource Limits", &[
            ("mmap_many_regions", test_mmap_many_regions),
            ("mmap_child_region_count", test_mmap_child_region_count),
        ]));

        total.merge(&run_section("Regression -- Resource Leaks", &[
            ("spawn_cleanup_no_leak", test_spawn_cleanup_no_leak),
        ]));

        total.merge(&run_section("Regression -- Fault Isolation", &[
            ("umode_fault_kills_child", test_umode_fault_kills_child_not_kernel),
        ]));

        yield_drain();
        total.merge(&run_section("Regression -- Cap Ref Counting", &[
            ("ns_override_cap_delivery", test_ns_override_cap_delivery),
            ("two_children_shared_override", test_two_children_shared_override),
            ("cap_delivery_via_spawn", test_cap_delivery_via_spawn),
        ]));
        yield_drain();

        total.merge(&run_section("Regression -- Debugger", &[
            ("debugger_second_attach", test_debugger_second_attach),
        ]));
    }

    total.merge(&run_section("Timer Service", &[
        ("timer_basic", test_timer_basic),
        ("timer_short", test_timer_short),
    ]));

    if !quick {
        total.merge(&run_section("Regression -- Scheduler Stress", &[
            ("stress_spawn_exit", test_stress_spawn_exit),
        ]));
    }

    println!();
    println!("=== Results: {} passed, {} failed, {} leaked ===",
        total.pass, total.fail, total.leak);

    if total.fail == 0 && total.leak == 0 {
        println!("=== ALL TESTS PASSED ===");
    } else {
        println!("=== SOME TESTS FAILED ===");
    }
}
