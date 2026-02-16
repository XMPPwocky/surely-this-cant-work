//! Process debugger kernel service.
//!
//! Provides attach/detach, suspend/resume, register/memory inspection,
//! breakpoint management, and backtrace for user processes.

use crate::ipc;
use crate::ipc::OwnedEndpoint;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::debug::*;

static CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    CONTROL_EP.store(ep, Ordering::Relaxed);
}

/// Translate a user VA to a PA using a specific process's page table.
/// Returns None if unmapped or not a user page (no U bit).
fn translate_va_for_pid(pid: usize, va: usize) -> Option<usize> {
    use crate::mm::address::{PhysPageNum, VirtPageNum, PAGE_SIZE};
    use crate::mm::page_table::{PageTable, PTE_U};

    let satp = crate::task::process_user_satp_by_pid(pid);
    if satp == 0 {
        return None;
    }
    let root_ppn = PhysPageNum(satp & ((1usize << 44) - 1));
    let pt = PageTable::from_root(root_ppn);
    let vpn = VirtPageNum(va / PAGE_SIZE);

    // Walk the page table manually to check the U bit
    let indices = vpn.indices();
    let mut current_ppn = root_ppn;

    for level in (1..3).rev() {
        let pte_table = current_ppn.as_page_table();
        let idx = indices[level];
        if !pte_table[idx].is_valid() {
            return None;
        }
        if pte_table[idx].is_leaf() {
            // Superpage — check U bit
            if pte_table[idx].flags() & PTE_U == 0 {
                return None;
            }
            return Some(pte_table[idx].ppn().0 * PAGE_SIZE + (va % PAGE_SIZE));
        }
        current_ppn = pte_table[idx].ppn();
    }

    let pte_table = current_ppn.as_page_table();
    let idx = indices[0];
    if !pte_table[idx].is_valid() {
        return None;
    }
    if pte_table[idx].flags() & PTE_U == 0 {
        return None;
    }
    // Use the translate method for the final lookup (identity mapping: PA == VA for user pages)
    pt.translate(vpn).map(|ppn| ppn.0 * PAGE_SIZE + (va % PAGE_SIZE))
}

/// Main service entry point — runs as a kernel task.
pub fn proc_debug_service() {
    let control_ep = CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    loop {
        // Accept a client connection on the control channel
        let accepted = ipc::accept_client(control_ep, my_pid);
        let client_ep = OwnedEndpoint::new(accepted.endpoint);

        // Receive DebugAttachRequest
        let msg = match ipc::channel_recv_blocking(client_ep.raw(), my_pid) {
            Some(m) => m,
            None => continue, // client disconnected
        };

        let req: DebugAttachRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
            Ok(r) => r,
            Err(_) => continue, // bad request, drop client
        };

        let target_pid = req.pid as usize;

        // Validate target
        if !crate::task::process_is_user(target_pid) {
            send_attach_error(client_ep.raw(), my_pid, DebugError::NotFound {});
            continue;
        }
        if crate::task::process_debug_attached(target_pid) {
            send_attach_error(client_ep.raw(), my_pid, DebugError::AlreadyAttached {});
            continue;
        }

        // Create session + event channel pairs
        let (session_a, session_b) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                send_attach_error(client_ep.raw(), my_pid, DebugError::NoResources {});
                continue;
            }
        };
        let (event_a, event_b) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                ipc::channel_close(session_a);
                ipc::channel_close(session_b);
                send_attach_error(client_ep.raw(), my_pid, DebugError::NoResources {});
                continue;
            }
        };

        // Mark the target as debugged (event_a is the service's endpoint)
        crate::task::set_process_debug_state(target_pid, true, event_a);

        // Send DebugAttachResponse::Ok with session_b + event_b to client
        let resp = DebugAttachResponse::Ok {
            session: rvos_wire::RawChannelCap::new(session_b),
            events: rvos_wire::RawChannelCap::new(event_b),
        };
        let mut resp_msg = ipc::Message::new();
        let (data_len, cap_count) = rvos_wire::to_bytes_with_caps(
            &resp,
            &mut resp_msg.data,
            &mut resp_msg.caps,
        )
        .unwrap_or((0, 0));
        resp_msg.len = data_len;
        resp_msg.cap_count = cap_count;
        // Inc ref for each cap we're sending
        if cap_count > 0 {
            for i in 0..cap_count {
                if resp_msg.caps[i] != ipc::NO_CAP {
                    let ep = match ipc::decode_cap(resp_msg.caps[i]) {
                        ipc::DecodedCap::Channel(ep) => ep,
                        _ => continue,
                    };
                    ipc::channel_inc_ref(ep);
                }
            }
        }
        // Actually the caps from to_bytes_with_caps are raw handles, need to encode them
        // Let me use KernelTransport instead for correct cap handling
        // Actually, looking at the wire format more closely, to_bytes_with_caps writes
        // the RawChannelCap handle values into the caps array. For kernel-side sending,
        // we need to encode them as channel caps and inc_ref.
        // Reset and do it properly:
        resp_msg = ipc::Message::new();
        resp_msg.len = rvos_wire::to_bytes(&DebugAttachResponse::Ok {
            session: rvos_wire::RawChannelCap::new(0), // placeholder
            events: rvos_wire::RawChannelCap::new(0),  // placeholder
        }, &mut resp_msg.data).unwrap_or(0);
        // Put the actual caps in the sideband
        resp_msg.caps[0] = ipc::encode_cap_channel(session_b);
        resp_msg.caps[1] = ipc::encode_cap_channel(event_b);
        resp_msg.cap_count = 2;
        ipc::channel_inc_ref(session_b);
        ipc::channel_inc_ref(event_b);

        if ipc::channel_send_blocking(client_ep.raw(), &resp_msg, my_pid).is_err() {
            // Client disconnected before receiving response
            ipc::channel_close(session_a);
            ipc::channel_close(session_b);
            ipc::channel_close(event_a);
            ipc::channel_close(event_b);
            crate::task::set_process_debug_state(target_pid, false, 0);
            continue;
        }

        // Drop the service's original references to the B endpoints.
        // The inc_ref calls above created a second reference for the client;
        // the service only uses the A endpoints from here on.
        ipc::channel_close(session_b);
        ipc::channel_close(event_b);

        // Enter session loop
        let session_ep = OwnedEndpoint::new(session_a);
        handle_debug_session(session_ep.raw(), target_pid, event_a, my_pid);

        // Session ended — detach
        detach_process(target_pid, event_a);
        // session_ep drops here, closing session_a
        // event_a is closed in detach_process
    }
}

fn send_attach_error(client_ep: usize, pid: usize, code: DebugError) {
    let resp = DebugAttachResponse::Error { code };
    let mut msg = ipc::Message::new();
    msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
    let _ = ipc::channel_send_blocking(client_ep, &msg, pid);
}

fn handle_debug_session(session_ep: usize, target_pid: usize, _event_ep: usize, my_pid: usize) {
    use crate::mm::address::PAGE_SIZE;

    loop {
        let msg = match ipc::channel_recv_blocking(session_ep, my_pid) {
            Some(m) => m,
            None => return, // session channel closed — detach
        };

        let req: SessionRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
            Ok(r) => r,
            Err(_) => {
                send_session_error(session_ep, my_pid, "bad request");
                continue;
            }
        };

        match req {
            SessionRequest::Suspend {} => {
                crate::task::set_debug_suspend_pending(target_pid);
                send_session_ok(session_ep, my_pid);
            }

            SessionRequest::Resume {} => {
                // Restore breakpoint original bytes if we hit one
                // (The sepc still points at the c.ebreak instruction.
                // The service must restore original bytes before resuming.)
                // Actually per the design, "resuming from a breakpoint clears it"
                // so we restore original bytes for any bp at sepc, then resume.
                if let Some(tf) = crate::task::read_debug_trap_frame(target_pid) {
                    let sepc = tf.sepc;
                    let (bps, count) = crate::task::process_debug_breakpoints(target_pid);
                    let mut new_bps = bps;
                    let mut new_count = count;
                    for i in 0..count {
                        if bps[i].0 == sepc {
                            // Restore original bytes at this breakpoint
                            let addr = bps[i].0;
                            let orig = bps[i].1;
                            if let Some(pa) = translate_va_for_pid(target_pid, addr) {
                                unsafe {
                                    core::ptr::write(pa as *mut u16, orig);
                                    core::arch::asm!("fence.i");
                                }
                            }
                            // Remove this breakpoint from the table
                            new_bps[i] = new_bps[new_count - 1];
                            new_bps[new_count - 1] = (0, 0);
                            new_count -= 1;
                            crate::task::set_process_debug_breakpoints(
                                target_pid,
                                new_bps,
                                new_count,
                            );
                            break;
                        }
                    }
                }
                crate::task::clear_debug_suspended(target_pid);
                crate::task::wake_process(target_pid);
                send_session_ok(session_ep, my_pid);
            }

            SessionRequest::ReadRegisters {} => {
                match crate::task::read_debug_trap_frame(target_pid) {
                    Some(tf) => {
                        // Pack pc + 32 regs as little-endian u64s = 33 * 8 = 264 bytes
                        let mut buf = [0u8; 264];
                        buf[0..8].copy_from_slice(&(tf.sepc as u64).to_le_bytes());
                        for i in 0..32 {
                            let off = 8 + i * 8;
                            buf[off..off + 8]
                                .copy_from_slice(&(tf.regs[i] as u64).to_le_bytes());
                        }
                        send_session_registers(session_ep, my_pid, &buf);
                    }
                    None => {
                        send_session_error(session_ep, my_pid, "not suspended");
                    }
                }
            }

            SessionRequest::WriteRegister { reg, value } => {
                if reg < 32 {
                    if crate::task::write_debug_register(
                        target_pid,
                        reg,
                        value as usize,
                    ) {
                        send_session_ok(session_ep, my_pid);
                    } else {
                        send_session_error(session_ep, my_pid, "not suspended");
                    }
                } else if reg == 32 {
                    // reg 32 = sepc (PC)
                    crate::task::write_debug_sepc(target_pid, value as usize);
                    send_session_ok(session_ep, my_pid);
                } else {
                    send_session_error(session_ep, my_pid, "invalid register");
                }
            }

            SessionRequest::ReadMemory { addr, len } => {
                let addr = addr as usize;
                let len = (len as usize).min(512);
                if len == 0 {
                    send_session_error(session_ep, my_pid, "zero length");
                    continue;
                }

                // Read one page at a time, validate each
                let mut buf = [0u8; 512];
                let mut offset = 0;
                let mut ok = true;
                while offset < len {
                    let va = addr + offset;
                    let page_offset = va % PAGE_SIZE;
                    let chunk = (PAGE_SIZE - page_offset).min(len - offset);

                    match translate_va_for_pid(target_pid, va) {
                        Some(pa) => {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    pa as *const u8,
                                    buf[offset..].as_mut_ptr(),
                                    chunk,
                                );
                            }
                            offset += chunk;
                        }
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }

                if ok {
                    send_session_memory(session_ep, my_pid, &buf[..len]);
                } else {
                    send_session_error(session_ep, my_pid, "unmapped address");
                }
            }

            SessionRequest::WriteMemory { addr, data } => {
                let addr = addr as usize;
                let len = data.len().min(512);
                if len == 0 {
                    send_session_ok(session_ep, my_pid);
                    continue;
                }

                let mut offset = 0;
                let mut ok = true;
                while offset < len {
                    let va = addr + offset;
                    let page_offset = va % PAGE_SIZE;
                    let chunk = (PAGE_SIZE - page_offset).min(len - offset);

                    match translate_va_for_pid(target_pid, va) {
                        Some(pa) => {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    data[offset..].as_ptr(),
                                    pa as *mut u8,
                                    chunk,
                                );
                            }
                            offset += chunk;
                        }
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }

                if ok {
                    unsafe { core::arch::asm!("fence.i"); }
                    send_session_ok(session_ep, my_pid);
                } else {
                    send_session_error(session_ep, my_pid, "unmapped address");
                }
            }

            SessionRequest::SetBreakpoint { addr } => {
                let addr = addr as usize;
                let (mut bps, count) =
                    crate::task::process_debug_breakpoints(target_pid);

                if count >= crate::task::process::MAX_BREAKPOINTS {
                    send_session_error(session_ep, my_pid, "too many breakpoints");
                    continue;
                }

                // Check for duplicate
                let dup = bps.iter().take(count).any(|bp| bp.0 == addr);
                if dup {
                    send_session_ok(session_ep, my_pid);
                    continue;
                }

                // Save original 2 bytes and write c.ebreak (0x9002)
                match translate_va_for_pid(target_pid, addr) {
                    Some(pa) => {
                        let orig = unsafe { core::ptr::read(pa as *const u16) };
                        unsafe {
                            core::ptr::write(pa as *mut u16, 0x9002);
                            core::arch::asm!("fence.i");
                        }
                        bps[count] = (addr, orig);
                        crate::task::set_process_debug_breakpoints(
                            target_pid,
                            bps,
                            count + 1,
                        );
                        send_session_ok(session_ep, my_pid);
                    }
                    None => {
                        send_session_error(session_ep, my_pid, "unmapped address");
                    }
                }
            }

            SessionRequest::ClearBreakpoint { addr } => {
                let addr = addr as usize;
                let (mut bps, count) =
                    crate::task::process_debug_breakpoints(target_pid);

                let mut found = false;
                for i in 0..count {
                    if bps[i].0 == addr {
                        // Restore original bytes
                        if let Some(pa) = translate_va_for_pid(target_pid, addr) {
                            unsafe {
                                core::ptr::write(pa as *mut u16, bps[i].1);
                                core::arch::asm!("fence.i");
                            }
                        }
                        // Remove from table
                        bps[i] = bps[count - 1];
                        bps[count - 1] = (0, 0);
                        crate::task::set_process_debug_breakpoints(
                            target_pid,
                            bps,
                            count - 1,
                        );
                        found = true;
                        break;
                    }
                }
                if found {
                    send_session_ok(session_ep, my_pid);
                } else {
                    send_session_error(session_ep, my_pid, "breakpoint not found");
                }
            }

            SessionRequest::Backtrace {} => {
                match crate::task::read_debug_trap_frame(target_pid) {
                    Some(tf) => {
                        // Walk frame pointer chain starting from s0 (x8)
                        let mut fp = tf.regs[8]; // s0 = frame pointer
                        let mut frames_buf = [0u8; 512]; // up to 32 frames * 16 bytes
                        let mut count = 0usize;
                        const MAX_FRAMES: usize = 32;

                        while count < MAX_FRAMES {
                            // Validate fp is accessible user memory and aligned
                            if fp == 0 || fp % 8 != 0 {
                                break;
                            }
                            // Read ra = [fp - 8], prev_fp = [fp - 16]
                            let ra_pa = translate_va_for_pid(target_pid, fp.wrapping_sub(8));
                            let fp_pa = translate_va_for_pid(target_pid, fp.wrapping_sub(16));
                            match (ra_pa, fp_pa) {
                                (Some(ra_pa), Some(fp_pa)) => {
                                    let ra =
                                        unsafe { core::ptr::read(ra_pa as *const usize) };
                                    let prev_fp =
                                        unsafe { core::ptr::read(fp_pa as *const usize) };
                                    let off = count * 16;
                                    frames_buf[off..off + 8]
                                        .copy_from_slice(&(ra as u64).to_le_bytes());
                                    frames_buf[off + 8..off + 16]
                                        .copy_from_slice(&(fp as u64).to_le_bytes());
                                    count += 1;
                                    if prev_fp == 0 || prev_fp == fp {
                                        break;
                                    }
                                    fp = prev_fp;
                                }
                                _ => break,
                            }
                        }

                        send_session_backtrace(
                            session_ep,
                            my_pid,
                            &frames_buf[..count * 16],
                        );
                    }
                    None => {
                        send_session_error(session_ep, my_pid, "not suspended");
                    }
                }
            }
        }
    }
}

fn detach_process(target_pid: usize, event_ep: usize) {
    // Restore all breakpoints
    let (bps, count) = crate::task::process_debug_breakpoints(target_pid);
    for bp in bps.iter().take(count) {
        if let Some(pa) = translate_va_for_pid(target_pid, bp.0) {
            unsafe {
                core::ptr::write(pa as *mut u16, bp.1);
            }
        }
    }
    if count > 0 {
        unsafe { core::arch::asm!("fence.i"); }
        crate::task::set_process_debug_breakpoints(target_pid, [(0, 0); 8], 0);
    }

    // Clear debug state and resume if suspended
    let was_suspended = crate::task::read_debug_trap_frame(target_pid).is_some();
    crate::task::set_process_debug_state(target_pid, false, 0);
    if was_suspended {
        crate::task::clear_debug_suspended(target_pid);
        crate::task::wake_process(target_pid);
    }

    // Close event channel
    ipc::channel_close(event_ep);
}

// ---- Response helpers ----

fn send_session_ok(ep: usize, pid: usize) {
    let resp = SessionResponse::Ok {};
    let mut msg = ipc::Message::new();
    msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

fn send_session_error(ep: usize, pid: usize, message: &str) {
    let resp = SessionResponse::Error { message };
    let mut msg = ipc::Message::new();
    msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

fn send_session_registers(ep: usize, pid: usize, data: &[u8]) {
    let resp = SessionResponse::Registers { data };
    let mut msg = ipc::Message::new();
    msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

fn send_session_memory(ep: usize, pid: usize, data: &[u8]) {
    let resp = SessionResponse::Memory { data };
    let mut msg = ipc::Message::new();
    msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

fn send_session_backtrace(ep: usize, pid: usize, frames: &[u8]) {
    let resp = SessionResponse::Backtrace { frames };
    let mut msg = ipc::Message::new();
    msg.len = rvos_wire::to_bytes(&resp, &mut msg.data).unwrap_or(0);
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}
