//! Network IPC server — kernel task that wraps VirtIO net access.
//!
//! Registers as the "net-raw" service. A single client (the net-stack)
//! connects and receives device info (MAC, MTU) plus a SHM capability
//! for a ring buffer used for bulk frame data transfer. IPC messages
//! serve as doorbells to signal new RX/TX data availability.

use crate::ipc::{self, Message, Cap};
use crate::mm::frame;
use crate::mm::address::PhysAddr;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::net::{NetRawRequest, NetRawResponse};

// ── SHM ring buffer layout constants ────────────────────────────

const CTRL_OFFSET: usize = 0;
const RX_RING_OFFSET: usize = 0x0040;
const TX_RING_OFFSET: usize = 0x3040;
const RX_SLOT_SIZE: usize = 1536;
const TX_SLOT_SIZE: usize = 1536;
const RX_SLOTS: usize = 8;
const TX_SLOTS: usize = 4;
const CTRL_RX_HEAD: usize = CTRL_OFFSET;
const CTRL_RX_TAIL: usize = CTRL_OFFSET + 0x04;
const CTRL_TX_HEAD: usize = CTRL_OFFSET + 0x08;
const CTRL_TX_TAIL: usize = CTRL_OFFSET + 0x0C;
const SHM_PAGE_COUNT: usize = 5;

// Compile-time check: SHM ring layout must fit within allocated pages
const _: () = assert!(
    TX_RING_OFFSET + TX_SLOTS * TX_SLOT_SIZE <= SHM_PAGE_COUNT * 4096,
    "SHM ring layout exceeds allocated size"
);

/// Control endpoint for net service (set by kmain before spawn)
static NET_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_control_ep(ep: usize) {
    NET_CONTROL_EP.store(ep, Ordering::Relaxed);
}

// ── Volatile SHM access helpers ────────────────────────────────

fn shm_read_u32(base: usize, offset: usize) -> u32 {
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn shm_write_u32(base: usize, offset: usize, val: u32) {
    unsafe { ((base + offset) as *mut u32).write_volatile(val) }
}

fn shm_read_u16(base: usize, offset: usize) -> u16 {
    unsafe { ((base + offset) as *const u16).read_volatile() }
}

fn shm_write_u16(base: usize, offset: usize, val: u16) {
    unsafe { ((base + offset) as *mut u16).write_volatile(val) }
}

// ── Net server entry point ──────────────────────────────────────

pub fn net_server() {
    let control_ep = NET_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register so network IRQs wake this task
    crate::drivers::virtio::net::set_wake_pid(my_pid);

    // Allocate contiguous physical pages for the SHM ring buffer
    let shm_ppn = frame::frame_alloc_contiguous(SHM_PAGE_COUNT)
        .expect("net_server: failed to allocate contiguous pages for SHM ring");

    // Compute the kernel virtual address of the SHM region.
    // (In rvOS the kernel identity-maps physical memory, so PhysAddr == VirtAddr.)
    let shm_base: usize = PhysAddr::from(shm_ppn).into();

    // Zero the entire SHM region so control block indices start at 0
    unsafe {
        core::ptr::write_bytes(shm_base as *mut u8, 0, SHM_PAGE_COUNT * 4096);
    }

    // Create the SHM IPC region
    let shm = ipc::shm_create(shm_ppn, SHM_PAGE_COUNT)
        .expect("net_server: failed to create SHM region");

    // Read MAC address from the driver
    let mac = crate::drivers::virtio::net::mac_address()
        .expect("net_server: no net device");

    crate::println!(
        "[net-server] ready (mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, shm_base={:#x}, shm={:?})",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], shm_base, shm
    );

    // Wait for a client endpoint from init (via control channel)
    let accepted = ipc::accept_client(control_ep, my_pid);
    let client = accepted.endpoint;
    let client_ep = client.raw();

    crate::println!("[net-server] client connected");

    // Track whether we have sent DeviceInfo (the SHM cap is only sent once)
    let mut device_info_sent = false;

    // Main loop: service IPC messages, poll RX, drain TX
    loop {
        let mut did_work = false;

        // ── Check for incoming IPC messages (non-blocking) ──────
        loop {
            let (msg, send_wake) = ipc::channel_recv(client_ep);
            if send_wake != 0 {
                crate::task::wake_process(send_wake);
            }
            match msg {
                Some(msg) => {
                    did_work = true;
                    if msg.len == 0 {
                        continue;
                    }
                    let req: NetRawRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    match req {
                        NetRawRequest::GetDeviceInfo {} => {
                            let resp = NetRawResponse::DeviceInfo {
                                mac0: mac[0],
                                mac1: mac[1],
                                mac2: mac[2],
                                mac3: mac[3],
                                mac4: mac[4],
                                mac5: mac[5],
                                mtu: 1500,
                            };
                            let mut resp_msg = Message::new();
                            resp_msg.len = rvos_wire::to_bytes(&resp, &mut resp_msg.data).unwrap_or(0);
                            resp_msg.sender_pid = my_pid;
                            if !device_info_sent {
                                // Attach SHM capability (RW) — clone creates a new
                                // reference for the receiver
                                resp_msg.caps[0] = Cap::Shm { owned: shm.clone(), rw: true };
                                resp_msg.cap_count = 1;
                                device_info_sent = true;
                            }
                            if ipc::channel_send_blocking(client_ep, resp_msg, my_pid).is_err() {
                                crate::println!("[net-server] client disconnected (send DeviceInfo)");
                                return;
                            }
                        }
                        NetRawRequest::TxReady {} => {
                            // Client signals new TX frames — handled below in the TX path
                        }
                        NetRawRequest::RxConsumed {} => {
                            // Client consumed RX frames — more room in the RX ring
                        }
                    }
                }
                None => break,
            }
        }

        // ── RX path: poll driver for received frames, copy to SHM ring ──
        while let Some((frame_ptr, frame_len, desc_idx)) = crate::drivers::virtio::net::poll_rx() {
            did_work = true;

            let rx_head = shm_read_u32(shm_base, CTRL_RX_HEAD);
            let rx_tail = shm_read_u32(shm_base, CTRL_RX_TAIL);

            if (rx_head.wrapping_sub(rx_tail)) < RX_SLOTS as u32 {
                let slot_idx = (rx_head % RX_SLOTS as u32) as usize;
                let slot_offset = RX_RING_OFFSET + slot_idx * RX_SLOT_SIZE;

                // Write frame length and data into the SHM slot
                let copy_len = frame_len.min(RX_SLOT_SIZE - 2);
                shm_write_u16(shm_base, slot_offset, copy_len as u16);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame_ptr as *const u8,
                        (shm_base + slot_offset + 2) as *mut u8,
                        copy_len,
                    );
                }

                // Ensure data is visible before advancing the head pointer
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                shm_write_u32(shm_base, CTRL_RX_HEAD, rx_head.wrapping_add(1));

                // Requeue the driver RX descriptor
                crate::drivers::virtio::net::requeue_rx(desc_idx);

                // Send RxReady doorbell (non-blocking)
                send_doorbell(client_ep, &NetRawResponse::RxReady {}, my_pid);
            } else {
                // RX ring full — requeue the driver buffer and stop polling.
                // The client will send RxConsumed when it drains slots.
                crate::drivers::virtio::net::requeue_rx(desc_idx);
                break;
            }
        }

        // ── TX path: read frames from SHM ring, transmit via driver ─────
        let tx_head = shm_read_u32(shm_base, CTRL_TX_HEAD);
        let mut tx_tail = shm_read_u32(shm_base, CTRL_TX_TAIL);
        let tx_tail_start = tx_tail;

        while tx_tail != tx_head {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

            did_work = true;

            let slot_idx = (tx_tail % TX_SLOTS as u32) as usize;
            let slot_offset = TX_RING_OFFSET + slot_idx * TX_SLOT_SIZE;
            let frame_len = shm_read_u16(shm_base, slot_offset) as usize;

            // Copy frame data to a stack buffer
            let mut frame_buf = [0u8; 1534];
            let copy_len = frame_len.min(1534);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (shm_base + slot_offset + 2) as *const u8,
                    frame_buf.as_mut_ptr(),
                    copy_len,
                );
            }

            crate::drivers::virtio::net::transmit(&frame_buf[..copy_len]);

            tx_tail = tx_tail.wrapping_add(1);
            shm_write_u32(shm_base, CTRL_TX_TAIL, tx_tail);
        }

        // If we consumed any TX slots, notify the client
        if tx_tail != tx_tail_start {
            send_doorbell(client_ep, &NetRawResponse::TxConsumed {}, my_pid);
        }

        // ── No work: block until IRQ or IPC wakes us ───────────────
        if !did_work {
            if !ipc::channel_is_active(client_ep) {
                crate::println!("[net-server] client disconnected");
                return;
            }
            ipc::channel_set_blocked(client_ep, my_pid);
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}

/// Send a non-blocking doorbell message. If the channel is full or closed,
/// the doorbell is silently dropped (fire-and-forget).
fn send_doorbell(ep: usize, resp: &NetRawResponse, my_pid: usize) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(resp, &mut msg.data).unwrap_or(0);
    msg.sender_pid = my_pid;
    match ipc::channel_send(ep, msg) {
        Ok(wake) => {
            if wake != 0 {
                crate::task::wake_process(wake);
            }
        }
        Err(_) => {
            // Doorbell dropped — client will poll or re-request
        }
    }
}
