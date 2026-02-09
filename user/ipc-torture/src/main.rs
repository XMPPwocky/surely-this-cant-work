// IPC Torture Test for rvOS
//
// A single binary that acts as both parent and child:
//   - Parent mode: spawns N children, runs 5 test phases over IPC channels
//   - Child mode: handle 1 is a channel to parent; responds to commands
//
// Every message carries a globally unique 32-bit ID (role_prefix | counter).
// Every send/recv is traced via SYS_TRACE for post-mortem debugging.

extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire::{Reader, Writer};

// --- Protocol tags (each unique for unambiguous tracing) ---
const TAG_HELLO: u8 = 1;
const TAG_PING: u8 = 2;
const TAG_PONG: u8 = 3;
const TAG_FLOOD_START: u8 = 4;
const TAG_FLOOD_MSG: u8 = 5;
const TAG_FLOOD_DONE: u8 = 6;
const TAG_FLOOD_ACK: u8 = 7;
const TAG_VARSIZE: u8 = 8;
const TAG_VARSIZE_ACK: u8 = 9;
const TAG_CAP_PASS: u8 = 10;
const TAG_CAP_ECHO: u8 = 11;
const TAG_CAP_ACK: u8 = 12;
const TAG_CLOSE_TEST: u8 = 13;
const TAG_CLOSE_OK: u8 = 14;
const TAG_EXIT: u8 = 15;

const NUM_CHILDREN: usize = 3;
const PING_COUNT: usize = 10;
const FLOOD_COUNT: usize = 100;
const VARSIZE_COUNT: usize = 20;
const MAX_VARSIZE: usize = 1013;

// --- Message ID generator ---
// Format: [role:8][counter:24]. Role 0 = parent, 1..N = children (by PID hash).
struct MsgIdGen {
    next_id: u32,
}

impl MsgIdGen {
    fn new(role: u32) -> Self {
        MsgIdGen {
            next_id: (role & 0xFF) << 24 | 1,
        }
    }

    fn next(&mut self) -> u32 {
        let id = self.next_id;
        // Increment counter portion (low 24 bits), keep role prefix
        let prefix = self.next_id & 0xFF00_0000;
        let counter = (self.next_id & 0x00FF_FFFF) + 1;
        self.next_id = prefix | (counter & 0x00FF_FFFF);
        id
    }
}

// --- Xorshift64 PRNG ---
struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Xorshift64 {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

// --- Trace helpers ---
fn tag_name(tag: u8) -> &'static str {
    match tag {
        TAG_HELLO => "HELLO",
        TAG_PING => "PING",
        TAG_PONG => "PONG",
        TAG_FLOOD_START => "FSTART",
        TAG_FLOOD_MSG => "FMSG",
        TAG_FLOOD_DONE => "FDONE",
        TAG_FLOOD_ACK => "FACK",
        TAG_VARSIZE => "VSIZE",
        TAG_VARSIZE_ACK => "VACK",
        TAG_CAP_PASS => "CPASS",
        TAG_CAP_ECHO => "CECHO",
        TAG_CAP_ACK => "CACK",
        TAG_CLOSE_TEST => "CTEST",
        TAG_CLOSE_OK => "COK",
        TAG_EXIT => "EXIT",
        _ => "???",
    }
}

// Format trace into stack buffer, no heap allocation.
fn write_trace(buf: &mut [u8], dir: u8, msg_id: u32, tag: u8, handle: usize) -> usize {
    let mut p = 0usize;
    // "T:" prefix
    buf[p] = b'T';
    p += 1;
    buf[p] = dir;
    p += 1;
    buf[p] = b' ';
    p += 1;
    // msg_id as 8-char hex
    for i in (0..8).rev() {
        let nibble = ((msg_id >> (i * 4)) & 0xF) as u8;
        buf[p] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        p += 1;
    }
    buf[p] = b' ';
    p += 1;
    // tag name
    let name = tag_name(tag).as_bytes();
    let nlen = name.len().min(8);
    buf[p..p + nlen].copy_from_slice(&name[..nlen]);
    p += nlen;
    buf[p] = b' ';
    p += 1;
    // "h" + decimal handle
    buf[p] = b'h';
    p += 1;
    if handle >= 100 {
        buf[p] = b'0' + (handle / 100 % 10) as u8;
        p += 1;
    }
    if handle >= 10 {
        buf[p] = b'0' + (handle / 10 % 10) as u8;
        p += 1;
    }
    buf[p] = b'0' + (handle % 10) as u8;
    p += 1;
    p
}

fn trace_send(msg_id: u32, tag: u8, handle: usize) {
    let mut buf = [0u8; 48];
    let len = write_trace(&mut buf, b'S', msg_id, tag, handle);
    raw::sys_trace(&buf[..len]);
}

fn trace_recv(msg_id: u32, tag: u8, handle: usize) {
    let mut buf = [0u8; 48];
    let len = write_trace(&mut buf, b'R', msg_id, tag, handle);
    raw::sys_trace(&buf[..len]);
}

// --- Message helpers ---

/// Build a message with [tag:u8][msg_id:u32][payload...], send blocking, trace.
fn build_and_send<F>(handle: usize, tag: u8, msg_id: u32, cap: usize, f: F)
where
    F: FnOnce(&mut Writer<'_>),
{
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(tag);
    let _ = w.write_u32(msg_id);
    f(&mut w);
    msg.len = w.position();
    msg.set_cap(cap);
    trace_send(msg_id, tag, handle);
    raw::sys_chan_send_blocking(handle, &msg);
}

/// Blocking receive. Returns (tag, msg_id) or Err(syscall_error_code).
fn recv_msg(handle: usize, msg: &mut Message) -> Result<(u8, u32), usize> {
    let ret = raw::sys_chan_recv_blocking(handle, msg);
    if ret != 0 {
        return Err(ret);
    }
    let tag = if msg.len > 0 { msg.data[0] } else { 0 };
    let msg_id = if msg.len >= 5 {
        u32::from_le_bytes([msg.data[1], msg.data[2], msg.data[3], msg.data[4]])
    } else {
        0
    };
    trace_recv(msg_id, tag, handle);
    Ok((tag, msg_id))
}

// --- Checksum ---
fn checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &b in data {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

// --- Mode detection ---
fn main() {
    // Detect mode by checking handle 2.
    //
    // After std init connects stdio, handle layout is:
    //   Parent: h0=boot, h1=stdio          (no h2)
    //   Child:  h0=boot, h1=extra_cap, h2=stdio
    //
    // So if handle 2 is valid, we're a child (h1 is parent's command channel).
    // If handle 2 is invalid, we're the parent (h1 is stdio, not a command channel).
    let mut probe = Message::new();
    let ret = raw::sys_chan_recv(2, &mut probe);

    if ret == usize::MAX {
        run_parent();
    } else {
        run_child();
    }
}

// ========================================================================
// PARENT
// ========================================================================

fn run_parent() {
    println!("=== IPC Torture Test ===");

    let mut ids = MsgIdGen::new(0);
    let mut pass: u32 = 0;
    let mut fail: u32 = 0;

    // Spawn children, each gets a direct channel via cap on Spawn
    println!("[parent] Spawning {} children...", NUM_CHILDREN);
    let mut child_handles: [usize; NUM_CHILDREN] = [usize::MAX; NUM_CHILDREN];

    for i in 0..NUM_CHILDREN {
        let (my_ep, child_ep) = raw::sys_chan_create();
        child_handles[i] = my_ep;

        match rvos::spawn_process_with_cap("/bin/ipc-torture", child_ep) {
            Ok(proc_handle) => {
                println!("[parent] Child {} spawned", i);
                // Don't need the process handle channel; drop it
                drop(proc_handle);
            }
            Err(_) => {
                println!("[parent] FATAL: failed to spawn child {}", i);
                return;
            }
        }

        // Child owns child_ep via the cap transfer; close our local copy
        raw::sys_chan_close(child_ep);
    }

    // Wait for HELLO from each child
    for i in 0..NUM_CHILDREN {
        let mut msg = Message::new();
        match recv_msg(child_handles[i], &mut msg) {
            Ok((TAG_HELLO, _)) => println!("[parent] Child {} ready", i),
            Ok((tag, _)) => {
                println!("[parent] Child {} unexpected tag {}", i, tag);
                fail += 1;
            }
            Err(e) => {
                println!("[parent] Child {} recv error {}", i, e);
                fail += 1;
            }
        }
    }

    // --- Phase 1: Ping-pong ---
    println!("[test] Phase 1: Ping-pong");
    let (p, f) = phase_ping_pong(&mut ids, &child_handles);
    println!("[test]   ping-pong: {} pass, {} fail", p, f);
    pass += p;
    fail += f;

    // --- Phase 2: Flood ---
    println!("[test] Phase 2: Flood ({} messages)", FLOOD_COUNT);
    let (p, f) = phase_flood(&mut ids, &child_handles);
    println!("[test]   flood: {} pass, {} fail", p, f);
    pass += p;
    fail += f;

    // --- Phase 3: Variable-size integrity ---
    println!("[test] Phase 3: Variable-size integrity");
    let (p, f) = phase_varsize(&mut ids, &child_handles);
    println!("[test]   varsize: {} pass, {} fail", p, f);
    pass += p;
    fail += f;

    // --- Phase 4: Capability passing ---
    println!("[test] Phase 4: Capability passing");
    let (p, f) = phase_cap_pass(&mut ids, &child_handles);
    println!("[test]   cap-pass: {} pass, {} fail", p, f);
    pass += p;
    fail += f;

    // --- Phase 5: Close detection ---
    println!("[test] Phase 5: Close detection");
    let (p, f) = phase_close_detect(&mut ids, &mut child_handles);
    println!("[test]   close-detect: {} pass, {} fail", p, f);
    pass += p;
    fail += f;

    // Send EXIT to remaining children
    for i in 0..NUM_CHILDREN {
        if child_handles[i] != usize::MAX {
            let mid = ids.next();
            build_and_send(child_handles[i], TAG_EXIT, mid, NO_CAP, |_| {});
            raw::sys_chan_close(child_handles[i]);
            child_handles[i] = usize::MAX;
        }
    }

    // Summary
    println!("=== Results: {} passed, {} failed ===", pass, fail);
    if fail == 0 {
        println!("=== ALL TESTS PASSED ===");
    } else {
        println!("=== SOME TESTS FAILED ===");
    }
}

// Phase 1: Send PING with seq#, child echoes PONG with same seq, verify.
fn phase_ping_pong(ids: &mut MsgIdGen, handles: &[usize; NUM_CHILDREN]) -> (u32, u32) {
    let mut pass = 0u32;
    let mut fail = 0u32;

    for i in 0..NUM_CHILDREN {
        for seq in 0..PING_COUNT {
            let mid = ids.next();
            build_and_send(handles[i], TAG_PING, mid, NO_CAP, |w| {
                let _ = w.write_u32(seq as u32);
            });

            let mut reply = Message::new();
            match recv_msg(handles[i], &mut reply) {
                Ok((TAG_PONG, rmid)) => {
                    let mut r = Reader::new(&reply.data[5..reply.len]);
                    let rseq = r.read_u32().unwrap_or(u32::MAX);
                    if rmid == mid && rseq == seq as u32 {
                        pass += 1;
                    } else {
                        fail += 1;
                        println!(
                            "[test]   FAIL ping c={} s={} mid={:08x}/{:08x} seq={}/{}",
                            i, seq, mid, rmid, seq, rseq
                        );
                    }
                }
                Ok((tag, _)) => {
                    fail += 1;
                    println!("[test]   FAIL ping c={} s={} bad tag={}", i, seq, tag);
                }
                Err(e) => {
                    fail += 1;
                    println!("[test]   FAIL ping c={} s={} err={}", i, seq, e);
                }
            }
        }
    }

    (pass, fail)
}

// Phase 2: Send FLOOD_START, 100 FLOOD_MSG, FLOOD_DONE. Child counts, returns total.
fn phase_flood(ids: &mut MsgIdGen, handles: &[usize; NUM_CHILDREN]) -> (u32, u32) {
    let mut pass = 0u32;
    let mut fail = 0u32;

    for i in 0..NUM_CHILDREN {
        let start_mid = ids.next();
        build_and_send(handles[i], TAG_FLOOD_START, start_mid, NO_CAP, |_| {});

        for _ in 0..FLOOD_COUNT {
            let mid = ids.next();
            build_and_send(handles[i], TAG_FLOOD_MSG, mid, NO_CAP, |_| {});
        }

        let done_mid = ids.next();
        build_and_send(handles[i], TAG_FLOOD_DONE, done_mid, NO_CAP, |_| {});

        let mut reply = Message::new();
        match recv_msg(handles[i], &mut reply) {
            Ok((TAG_FLOOD_ACK, _)) => {
                let mut r = Reader::new(&reply.data[5..reply.len]);
                let count = r.read_u32().unwrap_or(0);
                if count == FLOOD_COUNT as u32 {
                    pass += 1;
                } else {
                    fail += 1;
                    println!("[test]   FAIL flood c={} count={}/{}", i, count, FLOOD_COUNT);
                }
            }
            Ok((tag, _)) => {
                fail += 1;
                println!("[test]   FAIL flood c={} bad tag={}", i, tag);
            }
            Err(e) => {
                fail += 1;
                println!("[test]   FAIL flood c={} err={}", i, e);
            }
        }
    }

    (pass, fail)
}

// Phase 3: Send random-sized payloads, child checksums and echoes back.
fn phase_varsize(ids: &mut MsgIdGen, handles: &[usize; NUM_CHILDREN]) -> (u32, u32) {
    let mut pass = 0u32;
    let mut fail = 0u32;

    for i in 0..NUM_CHILDREN {
        let mut rng = Xorshift64::new((i as u64 + 1) * 12345);

        for _ in 0..VARSIZE_COUNT {
            let mid = ids.next();
            let size = (rng.next_u64() % MAX_VARSIZE as u64 + 1) as usize;

            // Generate deterministic payload
            let mut payload = vec![0u8; size];
            for b in payload.iter_mut() {
                *b = rng.next_u8();
            }
            let expected_cksum = checksum(&payload);

            // Send: [TAG_VARSIZE][msg_id][bytes(u16-prefixed)]
            build_and_send(handles[i], TAG_VARSIZE, mid, NO_CAP, |w| {
                let _ = w.write_bytes(&payload);
            });

            // Receive VARSIZE_ACK with checksum
            let mut reply = Message::new();
            match recv_msg(handles[i], &mut reply) {
                Ok((TAG_VARSIZE_ACK, rmid)) => {
                    let mut r = Reader::new(&reply.data[5..reply.len]);
                    let recv_cksum = r.read_u32().unwrap_or(0);
                    if rmid == mid && recv_cksum == expected_cksum {
                        pass += 1;
                    } else {
                        fail += 1;
                        println!(
                            "[test]   FAIL varsize c={} exp={} got={} mid={:08x}/{:08x}",
                            i, expected_cksum, recv_cksum, mid, rmid
                        );
                    }
                }
                Ok((tag, _)) => {
                    fail += 1;
                    println!("[test]   FAIL varsize c={} bad tag={}", i, tag);
                }
                Err(e) => {
                    fail += 1;
                    println!("[test]   FAIL varsize c={} err={}", i, e);
                }
            }
        }
    }

    (pass, fail)
}

// Phase 4: Create new channel, send as cap to child, echo on new channel.
fn phase_cap_pass(ids: &mut MsgIdGen, handles: &[usize; NUM_CHILDREN]) -> (u32, u32) {
    let mut pass = 0u32;
    let mut fail = 0u32;

    for i in 0..NUM_CHILDREN {
        let mid = ids.next();
        let (my_new_ep, child_new_ep) = raw::sys_chan_create();

        // Send CAP_PASS with new endpoint as cap
        build_and_send(handles[i], TAG_CAP_PASS, mid, child_new_ep, |_| {});
        raw::sys_chan_close(child_new_ep); // child gets it via cap

        // Send CAP_ECHO on the new channel with magic number
        let echo_mid = ids.next();
        let magic: u32 = 0xDEAD_BEEF;
        build_and_send(my_new_ep, TAG_CAP_ECHO, echo_mid, NO_CAP, |w| {
            let _ = w.write_u32(magic);
        });

        // Wait for CAP_ACK on new channel
        let mut reply = Message::new();
        match recv_msg(my_new_ep, &mut reply) {
            Ok((TAG_CAP_ACK, _)) => {
                let mut r = Reader::new(&reply.data[5..reply.len]);
                let recv_magic = r.read_u32().unwrap_or(0);
                if recv_magic == magic {
                    pass += 1;
                } else {
                    fail += 1;
                    println!(
                        "[test]   FAIL cap c={} magic={:08x}/{:08x}",
                        i, magic, recv_magic
                    );
                }
            }
            Ok((tag, _)) => {
                fail += 1;
                println!("[test]   FAIL cap c={} bad tag={}", i, tag);
            }
            Err(e) => {
                fail += 1;
                println!("[test]   FAIL cap c={} err={}", i, e);
            }
        }

        raw::sys_chan_close(my_new_ep);
    }

    (pass, fail)
}

// Phase 5: Send CLOSE_TEST with a report channel as cap, close main channel,
// child detects ChannelClosed and reports success on the report channel.
fn phase_close_detect(ids: &mut MsgIdGen, handles: &mut [usize; NUM_CHILDREN]) -> (u32, u32) {
    let mut pass = 0u32;
    let mut fail = 0u32;

    let i = NUM_CHILDREN - 1; // test on last child
    let mid = ids.next();

    // Create report channel
    let (my_report, child_report) = raw::sys_chan_create();

    // Send CLOSE_TEST with report endpoint as cap
    build_and_send(handles[i], TAG_CLOSE_TEST, mid, child_report, |_| {});
    raw::sys_chan_close(child_report);

    // Close the main channel to trigger ChannelClosed on child side
    raw::sys_chan_close(handles[i]);
    handles[i] = usize::MAX; // mark as closed

    // Wait for success report
    let mut reply = Message::new();
    match recv_msg(my_report, &mut reply) {
        Ok((TAG_CLOSE_OK, _)) => {
            pass += 1;
        }
        Ok((tag, _)) => {
            fail += 1;
            println!("[test]   FAIL close tag={}", tag);
        }
        Err(e) => {
            fail += 1;
            println!("[test]   FAIL close err={}", e);
        }
    }

    raw::sys_chan_close(my_report);

    (pass, fail)
}

// ========================================================================
// CHILD
// ========================================================================

fn run_child() {
    let handle: usize = 1; // parent command channel

    // Use PID as role for unique message IDs
    let (pid, _) = raw::syscall0(raw::SYS_GETPID);
    let mut ids = MsgIdGen::new((pid & 0xFF) as u32);

    // Send Hello
    let mid = ids.next();
    build_and_send(handle, TAG_HELLO, mid, NO_CAP, |_| {});

    // Command loop
    let mut flood_count: u32 = 0;
    let mut in_flood = false;
    let mut report_handle: usize = usize::MAX;

    loop {
        let mut msg = Message::new();
        let ret = raw::sys_chan_recv_blocking(handle, &mut msg);

        // Channel closed?
        if ret == 2 {
            // Close detection succeeded — report on report channel if available
            if report_handle != usize::MAX {
                let mid = ids.next();
                build_and_send(report_handle, TAG_CLOSE_OK, mid, NO_CAP, |_| {});
                raw::sys_chan_close(report_handle);
            }
            break;
        }

        if ret != 0 {
            break; // unexpected error
        }

        let tag = if msg.len > 0 { msg.data[0] } else { continue };
        let msg_id = if msg.len >= 5 {
            u32::from_le_bytes([msg.data[1], msg.data[2], msg.data[3], msg.data[4]])
        } else {
            0
        };
        trace_recv(msg_id, tag, handle);

        match tag {
            TAG_PING => {
                // Echo back as PONG with same msg_id and seq
                let mut r = Reader::new(&msg.data[5..msg.len]);
                let seq = r.read_u32().unwrap_or(0);
                build_and_send(handle, TAG_PONG, msg_id, NO_CAP, |w| {
                    let _ = w.write_u32(seq);
                });
            }

            TAG_FLOOD_START => {
                flood_count = 0;
                in_flood = true;
            }

            TAG_FLOOD_MSG => {
                if in_flood {
                    flood_count += 1;
                }
            }

            TAG_FLOOD_DONE => {
                in_flood = false;
                let mid = ids.next();
                build_and_send(handle, TAG_FLOOD_ACK, mid, NO_CAP, |w| {
                    let _ = w.write_u32(flood_count);
                });
            }

            TAG_VARSIZE => {
                // Read u16-prefixed payload, compute checksum, respond
                let mut r = Reader::new(&msg.data[5..msg.len]);
                let payload = r.read_bytes().unwrap_or(&[]);
                let cksum = checksum(payload);
                build_and_send(handle, TAG_VARSIZE_ACK, msg_id, NO_CAP, |w| {
                    let _ = w.write_u32(cksum);
                });
            }

            TAG_CAP_PASS => {
                // Receive new channel endpoint from cap
                if msg.cap() != NO_CAP {
                    let new_handle = msg.cap();
                    // Wait for CAP_ECHO on new channel
                    let mut echo_msg = Message::new();
                    let ret = raw::sys_chan_recv_blocking(new_handle, &mut echo_msg);
                    if ret == 0 {
                        let etag = if echo_msg.len > 0 { echo_msg.data[0] } else { 0 };
                        let emid = if echo_msg.len >= 5 {
                            u32::from_le_bytes([
                                echo_msg.data[1],
                                echo_msg.data[2],
                                echo_msg.data[3],
                                echo_msg.data[4],
                            ])
                        } else {
                            0
                        };
                        trace_recv(emid, etag, new_handle);

                        if etag == TAG_CAP_ECHO {
                            let mut r = Reader::new(&echo_msg.data[5..echo_msg.len]);
                            let magic = r.read_u32().unwrap_or(0);
                            let mid = ids.next();
                            build_and_send(new_handle, TAG_CAP_ACK, mid, NO_CAP, |w| {
                                let _ = w.write_u32(magic);
                            });
                        }
                    }
                    raw::sys_chan_close(new_handle);
                }
            }

            TAG_CLOSE_TEST => {
                // Store report handle from cap; next recv will get ChannelClosed
                if msg.cap() != NO_CAP {
                    report_handle = msg.cap();
                }
                // Continue loop — the parent will close our main channel
            }

            TAG_EXIT => {
                break;
            }

            _ => {} // ignore unknown tags
        }
    }
}
