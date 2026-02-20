//! ext2-server: User-space ext2 filesystem server.
//!
//! Speaks the FS protocol (FsRequest/FsResponse) to clients, backed by an
//! ext2 filesystem on a block device accessed via the blk protocol.
//!
//! Usage: ext2-server <blk_device> [ro]
//!   blk_device: name of the block device service (e.g., "blk0")
//!   ro: optional flag to mount read-only

// Scaffold: many fields/methods are defined but not yet called (Step 9 fills them in).
#![allow(dead_code)]

extern crate rvos_rt;
extern crate alloc;

mod blk_client;
mod block_cache;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::Channel;
use rvos::rvos_wire;
use rvos_proto::fs::{
    FsRequest, FsRequestMsg, FsResponse, FsEntryKind, FsError,
    FileRequest, FileRequestMsg, FileResponse, FileResponseMsg,
    FileOffset, ReaddirResponse,
};

use blk_client::BlkClient;
use block_cache::BlockCache;

// Control channel handle (set by kernel at spawn).
const CONTROL_HANDLE: usize = 1;

/// Maximum number of concurrent clients.
const MAX_CLIENTS: usize = 8;

/// Maximum number of open files across all clients.
const MAX_OPEN_FILES: usize = 16;

/// Per-client state.
struct ClientState {
    ctl: Option<Channel<FsResponse, FsRequestMsg>>,
    file_ch: Option<Channel<FileResponseMsg, FileRequestMsg>>,
    file_inode: u32,
}

impl ClientState {
    fn is_active(&self) -> bool {
        self.ctl.is_some() || self.file_ch.is_some()
    }
}

/// Per-open-file tracking.
struct OpenFile {
    endpoint_handle: usize,
    inode: u32,
    active: bool,
    append: bool,
    position: usize,
}

/// ext2 filesystem state (separate from client state for borrow splitting).
struct Ext2State {
    blk: BlkClient,
    cache: BlockCache,
    read_only: bool,
    open_files: [OpenFile; MAX_OPEN_FILES],
    open_count: usize,
    // ext2 superblock info (populated in Step 9)
    block_size: u32,
}

impl Ext2State {
    fn register_open_file(&mut self, endpoint_handle: usize, inode: u32, append: bool) -> bool {
        for of in &mut self.open_files {
            if !of.active {
                *of = OpenFile { endpoint_handle, inode, active: true, append, position: 0 };
                self.open_count += 1;
                return true;
            }
        }
        false
    }

    fn get_open_file_mut(&mut self, endpoint_handle: usize) -> Option<&mut OpenFile> {
        self.open_files.iter_mut().find(|of| of.active && of.endpoint_handle == endpoint_handle)
    }

    fn close_open_file(&mut self, endpoint_handle: usize) {
        for of in &mut self.open_files {
            if of.active && of.endpoint_handle == endpoint_handle {
                of.active = false;
                self.open_count -= 1;
                return;
            }
        }
    }
}

// --- Response helpers ---

fn send_error(ch: &Channel<FsResponse, FsRequestMsg>, code: FsError) {
    let _ = ch.send(&FsResponse::Error { code });
}

fn send_stat_ok(ch: &Channel<FsResponse, FsRequestMsg>, kind: FsEntryKind, size: u64) {
    let _ = ch.send(&FsResponse::Ok { kind, size });
}

fn send_file_error(ch: &Channel<FileResponseMsg, FileRequestMsg>, code: FsError) {
    let _ = ch.send(&FileResponse::Error { code });
}

fn send_data_chunk(ch: &Channel<FileResponseMsg, FileRequestMsg>, data: &[u8]) {
    let _ = ch.send(&FileResponse::Data { chunk: data });
}

fn send_data_sentinel(ch: &Channel<FileResponseMsg, FileRequestMsg>) {
    let _ = ch.send(&FileResponse::Data { chunk: &[] });
}

fn send_write_ok(ch: &Channel<FileResponseMsg, FileRequestMsg>, written: u32) {
    let _ = ch.send(&FileResponse::WriteOk { written });
}

fn send_dir_entry(handle: usize, kind: FsEntryKind, size: u64, name: &str) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &ReaddirResponse::Entry { kind, size, name },
        &mut msg.data,
    ).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

fn send_dir_sentinel(handle: usize) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&ReaddirResponse::End {}, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

// --- Stub FS operations (implemented in Step 9) ---

fn do_stat(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, _path: &[u8]) {
    let _ = ext2;
    send_error(ch, FsError::Io {});
}

fn do_open(ext2: &mut Ext2State, client: &mut ClientState, _flags: rvos_proto::fs::OpenFlags, _path: &[u8]) {
    let _ = ext2;
    send_error(client.ctl.as_ref().unwrap(), FsError::Io {});
}

fn do_readdir(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, _path: &[u8]) {
    let _ = ext2;
    send_error(ch, FsError::Io {});
}

fn do_delete(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, _path: &[u8]) {
    let _ = ext2;
    send_error(ch, FsError::Io {});
}

fn do_mkdir(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, _path: &[u8]) {
    let _ = ext2;
    send_error(ch, FsError::Io {});
}

fn handle_file_read(ext2: &mut Ext2State, ch: &Channel<FileResponseMsg, FileRequestMsg>, _inode: u32, _offset: FileOffset, _len: u32) {
    let _ = ext2;
    send_file_error(ch, FsError::Io {});
}

fn handle_file_write(ext2: &mut Ext2State, ch: &Channel<FileResponseMsg, FileRequestMsg>, _inode: u32, _offset: FileOffset, _data: &[u8]) {
    let _ = ext2;
    send_file_error(ch, FsError::Io {});
}

// --- Main ---

fn main() {
    let args: alloc::vec::Vec<alloc::string::String> = std::env::args().collect();

    let device_name = if args.len() > 1 {
        &args[1]
    } else {
        eprintln!("ext2-server: usage: ext2-server <blk_device> [ro]");
        return;
    };

    let force_ro = args.len() > 2 && args[2] == "ro";

    eprintln!("[ext2-server] connecting to {}{}", device_name, if force_ro { " (ro)" } else { "" });

    let blk = match BlkClient::connect(device_name) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ext2-server] failed to connect to {}: {}", device_name, e);
            return;
        }
    };

    let read_only = force_ro || blk.read_only;
    let capacity = blk.capacity_sectors;

    eprintln!(
        "[ext2-server] connected: {} sectors, {}",
        capacity,
        if read_only { "RO" } else { "RW" }
    );

    // TODO(step 9): Read and validate ext2 superblock, determine block_size.
    // For now, use default ext2 block size of 1024.
    let block_size = 1024u32;

    let cache = BlockCache::new(block_size);

    let mut ext2 = Ext2State {
        blk,
        cache,
        read_only,
        open_files: [const { OpenFile { endpoint_handle: 0, inode: 0, active: false, append: false, position: 0 } }; MAX_OPEN_FILES],
        open_count: 0,
        block_size,
    };

    let mut clients: [ClientState; MAX_CLIENTS] =
        [const { ClientState { ctl: None, file_ch: None, file_inode: 0 } }; MAX_CLIENTS];

    // Main event loop
    loop {
        let mut handled = false;

        // Accept new clients from control channel
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut msg);
            if ret != 0 { break; }
            handled = true;
            let cap = if msg.cap_count > 0 { msg.caps[0] } else { NO_CAP };
            if cap != NO_CAP {
                let slot = clients.iter_mut().find(|c| !c.is_active());
                if let Some(slot) = slot {
                    *slot = ClientState {
                        ctl: Some(Channel::from_raw_handle(cap)),
                        file_ch: None,
                        file_inode: 0,
                    };
                } else {
                    raw::sys_chan_close(cap);
                }
            }
        }

        // Poll each active client
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_CLIENTS {
            if !clients[i].is_active() { continue; }

            // Poll file channel
            if clients[i].file_ch.is_some() {
                let file_inode = clients[i].file_inode;
                let raw_h = clients[i].file_ch.as_ref().unwrap().raw_handle();

                // Phase 1: recv, copy borrowed data to stack
                let mut read_params: Option<(FileOffset, u32)> = None;
                let mut write_buf = [0u8; 1024];
                let mut write_params: Option<(FileOffset, usize)> = None;
                let mut file_closed = false;

                {
                    let ch = clients[i].file_ch.as_mut().unwrap();
                    match ch.try_recv() {
                        Ok(FileRequest::Read { offset, len }) => {
                            read_params = Some((offset, len));
                        }
                        Ok(FileRequest::Write { offset, data }) => {
                            let dlen = data.len().min(1024);
                            write_buf[..dlen].copy_from_slice(&data[..dlen]);
                            write_params = Some((offset, dlen));
                        }
                        Ok(FileRequest::Ioctl { .. }) => {
                            handled = true;
                            // ext2 doesn't support ioctls — respond inline
                        }
                        Err(rvos::RecvError::Closed) => {
                            file_closed = true;
                        }
                        Err(_) => {}
                    }
                }

                // Phase 2: act on extracted data (borrow released)
                if let Some((offset, len)) = read_params {
                    handled = true;
                    let ch = clients[i].file_ch.as_ref().unwrap();
                    handle_file_read(&mut ext2, ch, file_inode, offset, len);
                } else if let Some((offset, dlen)) = write_params {
                    handled = true;
                    let ch = clients[i].file_ch.as_ref().unwrap();
                    handle_file_write(&mut ext2, ch, file_inode, offset, &write_buf[..dlen]);
                } else if file_closed {
                    ext2.close_open_file(raw_h);
                    clients[i].file_ch = None;
                    clients[i].file_inode = 0;
                }
            }

            // Poll ctl channel
            if clients[i].ctl.is_some() {
                let mut path_buf = [0u8; 64];
                let mut path_len = 0usize;
                let mut open_flags: Option<rvos_proto::fs::OpenFlags> = None;
                let mut is_delete = false;
                let mut is_stat = false;
                let mut is_readdir = false;
                let mut is_mkdir = false;
                let mut ctl_closed = false;

                {
                    let ch = clients[i].ctl.as_mut().unwrap();
                    match ch.try_recv() {
                        Ok(FsRequest::Open { flags, path }) => {
                            path_len = path.len().min(64);
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            open_flags = Some(flags);
                        }
                        Ok(FsRequest::Delete { path }) => {
                            path_len = path.len().min(64);
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_delete = true;
                        }
                        Ok(FsRequest::Stat { path }) => {
                            path_len = path.len().min(64);
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_stat = true;
                        }
                        Ok(FsRequest::Readdir { path }) => {
                            path_len = path.len().min(64);
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_readdir = true;
                        }
                        Ok(FsRequest::Mount { .. }) => {
                            handled = true;
                            send_error(clients[i].ctl.as_ref().unwrap(), FsError::Io {});
                        }
                        Ok(FsRequest::Unmount { .. }) => {
                            handled = true;
                            send_error(clients[i].ctl.as_ref().unwrap(), FsError::Io {});
                        }
                        Ok(FsRequest::Mkdir { path }) => {
                            path_len = path.len().min(64);
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_mkdir = true;
                        }
                        Err(rvos::RecvError::Closed) => {
                            ctl_closed = true;
                        }
                        Err(_) => {}
                    }
                }

                // Phase 2: dispatch (ctl borrow released, ext2 and clients are separate)
                if let Some(flags) = open_flags {
                    handled = true;
                    do_open(&mut ext2, &mut clients[i], flags, &path_buf[..path_len]);
                } else if is_delete {
                    handled = true;
                    do_delete(&mut ext2, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if is_stat {
                    handled = true;
                    do_stat(&mut ext2, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if is_readdir {
                    handled = true;
                    do_readdir(&mut ext2, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if is_mkdir {
                    handled = true;
                    do_mkdir(&mut ext2, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if ctl_closed {
                    clients[i].ctl = None;
                }
            }
        }

        if !handled {
            // Register interest on all active channels, then block
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            for client in &clients {
                if let Some(ref ctl) = client.ctl {
                    ctl.poll_add();
                }
                if let Some(ref file_ch) = client.file_ch {
                    file_ch.poll_add();
                }
            }
            raw::sys_block();
        }
    }
}
