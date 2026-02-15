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
// Main
// ============================================================

fn main() {
    println!("=== rvOS Kernel Test Suite ===");

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

    total.merge(&run_section("Process Spawn", &[
        ("spawn_hello", test_spawn_hello),
        ("spawn_exit_notification", test_spawn_exit_notification),
    ]));

    println!();
    println!("=== Results: {} passed, {} failed, {} leaked ===",
        total.pass, total.fail, total.leak);

    if total.fail == 0 && total.leak == 0 {
        println!("=== ALL TESTS PASSED ===");
    } else {
        println!("=== SOME TESTS FAILED ===");
    }
}
