extern crate rvos_rt;

use rvos::raw;
use rvos::Message;

/// Minimal child binary for ktest regression tests.
///
/// Behavior depends on command-line arguments:
///   "crash" → dereference null pointer (tests U-mode fault handling)
///   "exit"  → exit cleanly
///   (none)  → check handle 1 for a command-byte protocol:
///     Byte 1 → send "ktest-ok" back on handle 1
///     Byte 2 → allocate 64 mmap regions, report count on handle 1
///
/// Handle layout when spawned with cap:
///   h0=boot, h1=extra_cap, h2=stdin, h3=stdout
fn main() {
    let args: Vec<String> = std::env::args().collect();

    if !args.is_empty() {
        match args[0].as_str() {
            "crash" => {
                // Null pointer dereference — should kill this process, not the kernel
                unsafe { core::ptr::read_volatile(core::ptr::null::<u8>()); }
            }
            "exit" => {
                return;
            }
            _ => {}
        }
    }

    // No args (or unrecognized): protocol mode on handle 1
    let cap_handle: usize = 1;

    // Try to recv a command byte
    let mut msg = Message::new();
    let ret = raw::sys_chan_recv_blocking(cap_handle, &mut msg);
    if ret != 0 {
        // Channel closed or error — just send "ktest-ok" and exit
        let reply = Message::from_bytes(b"ktest-ok");
        raw::sys_chan_send(cap_handle, &reply);
        return;
    }

    if msg.len > 0 {
        match msg.data[0] {
            1 => {
                // Command 1: echo "ktest-ok"
                let reply = Message::from_bytes(b"ktest-ok");
                raw::sys_chan_send(cap_handle, &reply);
            }
            2 => {
                // Command 2: allocate 64 anonymous mmap regions, report count
                let mut count: u32 = 0;
                for _ in 0..64 {
                    let addr = raw::sys_mmap(0, 4096);
                    if addr == usize::MAX {
                        break;
                    }
                    count += 1;
                    // Don't unmap — we want to test that 64 regions can coexist
                }
                let mut reply = Message::new();
                let bytes = count.to_le_bytes();
                reply.data[..4].copy_from_slice(&bytes);
                reply.len = 4;
                raw::sys_chan_send(cap_handle, &reply);
            }
            _ => {
                let reply = Message::from_bytes(b"ktest-ok");
                raw::sys_chan_send(cap_handle, &reply);
            }
        }
    } else {
        let reply = Message::from_bytes(b"ktest-ok");
        raw::sys_chan_send(cap_handle, &reply);
    }
}
