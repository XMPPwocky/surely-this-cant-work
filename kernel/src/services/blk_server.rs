//! Block device IPC server — kernel task that wraps VirtIO blk access.
//!
//! One instance per block device. Registers as "blk0", "blk1", etc.
//! A single client connects and receives device info (capacity, sector size,
//! RO flag) plus an SHM capability for bulk data transfer. Subsequent
//! Read/Write/Flush requests reference offsets within that SHM region.

use crate::ipc::{self, Message, Cap};
use crate::mm::frame;
use crate::mm::address::PhysAddr;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::blk::{BlkRequest, BlkResponse};

/// SHM region: 32 pages = 128 KB for bulk data transfer.
const SHM_PAGE_COUNT: usize = 32;

/// Maximum number of blk_server instances.
const MAX_BLK_SERVERS: usize = 4;

/// Control endpoint for each blk_server instance (set by kmain before spawn).
static BLK_CONTROL_EPS: [AtomicUsize; MAX_BLK_SERVERS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_BLK_SERVERS];

/// Device index for each blk_server instance (set by kmain before spawn).
static BLK_DEVICE_INDICES: [AtomicUsize; MAX_BLK_SERVERS] =
    [const { AtomicUsize::new(usize::MAX) }; MAX_BLK_SERVERS];

/// Set the control endpoint for blk_server instance `server_idx`.
pub fn set_control_ep(server_idx: usize, ep: usize) {
    BLK_CONTROL_EPS[server_idx].store(ep, Ordering::Relaxed);
}

/// Set the device index for blk_server instance `server_idx`.
pub fn set_device_index(server_idx: usize, device_idx: usize) {
    BLK_DEVICE_INDICES[server_idx].store(device_idx, Ordering::Relaxed);
}

/// Entry point for blk_server instance 0.
pub fn blk_server_0() { blk_server(0); }
/// Entry point for blk_server instance 1.
pub fn blk_server_1() { blk_server(1); }
/// Entry point for blk_server instance 2.
pub fn blk_server_2() { blk_server(2); }
/// Entry point for blk_server instance 3.
pub fn blk_server_3() { blk_server(3); }

/// Array of entry points indexed by server_idx.
pub const BLK_SERVER_ENTRIES: [fn(); MAX_BLK_SERVERS] = [
    blk_server_0, blk_server_1, blk_server_2, blk_server_3,
];

fn blk_server(server_idx: usize) {
    let control_ep = BLK_CONTROL_EPS[server_idx].load(Ordering::Relaxed);
    let device_idx = BLK_DEVICE_INDICES[server_idx].load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register so block device IRQs wake this task
    crate::drivers::virtio::blk::set_wake_pid(device_idx, my_pid);

    // Allocate contiguous physical pages for the SHM region
    let Some(shm_ppn) = frame::frame_alloc_contiguous(SHM_PAGE_COUNT) else {
        crate::println!("[blk{}] OOM: cannot allocate SHM pages", device_idx);
        return;
    };

    let shm_base: usize = PhysAddr::from(shm_ppn).into();

    // Zero the SHM region
    unsafe {
        core::ptr::write_bytes(shm_base as *mut u8, 0, SHM_PAGE_COUNT * 4096);
    }

    // Create the SHM IPC region
    let Some(shm) = ipc::shm_create(shm_ppn, SHM_PAGE_COUNT) else {
        crate::println!("[blk{}] failed to create SHM region", device_idx);
        return;
    };

    let capacity = crate::drivers::virtio::blk::capacity(device_idx);
    let read_only = crate::drivers::virtio::blk::is_read_only(device_idx);

    crate::println!(
        "[blk{}] ready (capacity={} sectors, {}, shm_base={:#x})",
        device_idx, capacity, if read_only { "RO" } else { "RW" }, shm_base,
    );

    // Outer loop: accept clients one at a time, re-accept after disconnect
    loop {
        // Wait for a client endpoint from init (via control channel)
        let accepted = ipc::accept_client(control_ep, my_pid);
        let client = accepted.endpoint;
        let client_ep = client.raw();

        crate::println!("[blk{}] client connected", device_idx);

        // Send SHM cap with the first DeviceInfo per client
        let mut device_info_sent = false;

        // Client loop
        'client: loop {
            let mut did_work = false;

            // Check for incoming IPC messages (non-blocking)
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
                        let req: BlkRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };
                        match req {
                            BlkRequest::GetDeviceInfo {} => {
                                let resp = BlkResponse::DeviceInfo {
                                    capacity_sectors: capacity,
                                    sector_size: crate::drivers::virtio::blk::SECTOR_SIZE as u32,
                                    read_only: if read_only { 1 } else { 0 },
                                };
                                let mut resp_msg = Message::new();
                                resp_msg.len = rvos_wire::to_bytes(&resp, &mut resp_msg.data).unwrap_or(0);
                                resp_msg.sender_pid = my_pid;
                                if !device_info_sent {
                                    resp_msg.caps[0] = Cap::Shm { owned: shm.clone(), rw: true };
                                    resp_msg.cap_count = 1;
                                    device_info_sent = true;
                                }
                                if ipc::channel_send_blocking(client_ep, resp_msg, my_pid).is_err() {
                                    crate::println!("[blk{}] client disconnected (send DeviceInfo)", device_idx);
                                    break 'client;
                                }
                            }
                            BlkRequest::Read { sector, count, shm_offset } => {
                                let resp = handle_read(device_idx, sector, count, shm_offset, shm_base, capacity, read_only);
                                if !send_response(client_ep, &resp, my_pid, device_idx) {
                                    break 'client;
                                }
                            }
                            BlkRequest::Write { sector, count, shm_offset } => {
                                let resp = handle_write(device_idx, sector, count, shm_offset, shm_base, capacity, read_only);
                                if !send_response(client_ep, &resp, my_pid, device_idx) {
                                    break 'client;
                                }
                            }
                            BlkRequest::Flush {} => {
                                let ok = crate::drivers::virtio::blk::flush(device_idx);
                                let resp = if ok {
                                    BlkResponse::Ok {}
                                } else {
                                    BlkResponse::Error { code: 5 } // EIO
                                };
                                if !send_response(client_ep, &resp, my_pid, device_idx) {
                                    break 'client;
                                }
                            }
                        }
                    }
                    None => break,
                }
            }

            if !did_work {
                if !ipc::channel_is_active(client_ep) {
                    crate::println!("[blk{}] client disconnected", device_idx);
                    break 'client;
                }
                ipc::channel_set_blocked(client_ep, my_pid);
                crate::task::block_process(my_pid);
                crate::task::schedule();
            }
        }
        // Client disconnected — OwnedEndpoint drops and closes the channel.
        // Loop back to accept the next client.
    }
}

/// Handle a Read request: read sectors from disk into the SHM region.
fn handle_read(
    device_idx: usize,
    sector: u64,
    count: u32,
    shm_offset: u32,
    shm_base: usize,
    capacity: u64,
    _read_only: bool,
) -> BlkResponse {
    let shm_size = SHM_PAGE_COUNT * 4096;
    let data_len = count as usize * crate::drivers::virtio::blk::SECTOR_SIZE;

    // Validate bounds
    if count == 0 || sector + count as u64 > capacity {
        return BlkResponse::Error { code: 22 }; // EINVAL
    }
    if shm_offset as usize + data_len > shm_size {
        return BlkResponse::Error { code: 22 }; // EINVAL
    }

    let dst = (shm_base + shm_offset as usize) as *mut u8;
    if crate::drivers::virtio::blk::read_sectors(device_idx, sector, count, dst) {
        BlkResponse::Ok {}
    } else {
        BlkResponse::Error { code: 5 } // EIO
    }
}

/// Handle a Write request: write sectors from the SHM region to disk.
fn handle_write(
    device_idx: usize,
    sector: u64,
    count: u32,
    shm_offset: u32,
    shm_base: usize,
    capacity: u64,
    read_only: bool,
) -> BlkResponse {
    if read_only {
        return BlkResponse::Error { code: 30 }; // EROFS
    }

    let shm_size = SHM_PAGE_COUNT * 4096;
    let data_len = count as usize * crate::drivers::virtio::blk::SECTOR_SIZE;

    if count == 0 || sector + count as u64 > capacity {
        return BlkResponse::Error { code: 22 }; // EINVAL
    }
    if shm_offset as usize + data_len > shm_size {
        return BlkResponse::Error { code: 22 }; // EINVAL
    }

    let src = (shm_base + shm_offset as usize) as *const u8;
    if crate::drivers::virtio::blk::write_sectors(device_idx, sector, count, src) {
        BlkResponse::Ok {}
    } else {
        BlkResponse::Error { code: 5 } // EIO
    }
}

/// Send a BlkResponse to the client. Returns false if the client disconnected.
fn send_response(client_ep: usize, resp: &BlkResponse, my_pid: usize, device_idx: usize) -> bool {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(resp, &mut msg.data).unwrap_or(0);
    msg.sender_pid = my_pid;
    if ipc::channel_send_blocking(client_ep, msg, my_pid).is_err() {
        crate::println!("[blk{}] client disconnected (send response)", device_idx);
        return false;
    }
    true
}
