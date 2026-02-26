//! ext2-server: User-space ext2 filesystem server.
//!
//! Speaks the FS protocol (FsRequest/FsResponse) to clients, backed by an
//! ext2 filesystem on a block device accessed via the blk protocol.
//!
//! Usage: ext2-server <blk_device> [ro]
//!   blk_device: name of the block device service (e.g., "blk0")
//!   ro: optional flag to mount read-only

extern crate rvos_rt;
extern crate alloc;

mod blk_client;
mod block_cache;
mod ext2;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::Channel;
use rvos::rvos_wire;
use rvos_proto::fs::{
    FsRequest, FsRequestMsg, FsResponse, FsEntryKind, FsError, OpenFlags,
    FileRequest, FileRequestMsg, FileResponse, FileResponseMsg,
    FileOffset, ReaddirResponse,
};

use blk_client::BlkClient;
use block_cache::BlockCache;
use ext2::Superblock;

// Control channel handle (set by kernel at spawn).
const CONTROL_HANDLE: usize = 1;

/// Maximum number of concurrent clients.
const MAX_CLIENTS: usize = 8;

/// Maximum number of open files (flat, not per-client).
const MAX_OPEN_FILES: usize = 16;

/// Max data payload per chunk: MAX_MSG_SIZE(1024) - 3 (tag u8 + length u16).
const MAX_DATA_CHUNK: usize = 1021;

/// Per-client state (control channel only).
struct ClientState {
    ctl: Option<Channel<FsResponse, FsRequestMsg>>,
}

impl ClientState {
    fn is_active(&self) -> bool {
        self.ctl.is_some()
    }
}

/// An open file channel with its associated inode.
struct FileSlot {
    ch: Channel<FileResponseMsg, FileRequestMsg>,
    inode: u32,
}

/// Per-open-file position/state tracking (keyed by endpoint handle).
struct OpenFileState {
    endpoint_handle: usize,
    #[allow(dead_code)]
    inode: u32,
    active: bool,
    append: bool,
    position: usize,
}

/// ext2 filesystem state (separate from client state for borrow splitting).
struct Ext2State {
    blk: BlkClient,
    cache: BlockCache,
    sb: Superblock,
    read_only: bool,
    open_file_state: [OpenFileState; MAX_OPEN_FILES],
    open_count: usize,
}

impl Ext2State {
    fn register_open_file(&mut self, endpoint_handle: usize, inode: u32, append: bool) -> bool {
        for of in &mut self.open_file_state {
            if !of.active {
                *of = OpenFileState { endpoint_handle, inode, active: true, append, position: 0 };
                self.open_count += 1;
                return true;
            }
        }
        false
    }

    fn get_open_file_mut(&mut self, endpoint_handle: usize) -> Option<&mut OpenFileState> {
        self.open_file_state.iter_mut().find(|of| of.active && of.endpoint_handle == endpoint_handle)
    }

    fn close_open_file(&mut self, endpoint_handle: usize) {
        for of in &mut self.open_file_state {
            if of.active && of.endpoint_handle == endpoint_handle {
                of.active = false;
                self.open_count -= 1;
                return;
            }
        }
    }
}

// --- Error mapping ---

/// Map ext2 internal error strings to FsError codes.
/// Allocation failures ("no space", "no inodes") map to NoSpace;
/// everything else maps to Io.
fn map_ext2_error(e: &str) -> FsError {
    if e == "no space" || e == "no inodes" {
        FsError::NoSpace {}
    } else {
        FsError::Io {}
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

// --- Path helpers ---

/// Split a path into (parent, name). E.g., "/foo/bar" -> (b"/foo", b"bar").
fn split_parent_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.is_empty() || path[0] != b'/' {
        return None;
    }
    // Find last '/'
    let mut last_slash = 0;
    for (i, &b) in path.iter().enumerate().skip(1) {
        if b == b'/' {
            last_slash = i;
        }
    }
    if last_slash == 0 {
        // Name is directly under root
        Some((b"/", &path[1..]))
    } else {
        Some((&path[..last_slash], &path[last_slash + 1..]))
    }
}

// --- FS operations ---

fn do_stat(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, path: &[u8]) {
    if path.is_empty() || path[0] != b'/' {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    let ino = match ext2::resolve_path(&ext2.sb, path, &mut ext2.cache, &ext2.blk) {
        Ok(ino) => ino,
        Err(_) => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };

    let inode = match ext2::read_inode(&ext2.sb, ino, &mut ext2.cache, &ext2.blk) {
        Ok(i) => i,
        Err(_) => {
            send_error(ch, FsError::Io {});
            return;
        }
    };

    let kind = if inode.is_dir() {
        FsEntryKind::Directory {}
    } else {
        FsEntryKind::File {}
    };

    send_stat_ok(ch, kind, inode.size);
}

fn do_open(
    ext2: &mut Ext2State,
    ctl_ch: &Channel<FsResponse, FsRequestMsg>,
    file_slots: &mut [Option<FileSlot>; MAX_OPEN_FILES],
    flags: OpenFlags,
    path: &[u8],
) {
    if path.is_empty() || path[0] != b'/' {
        send_error(ctl_ch, FsError::InvalidPath {});
        return;
    }

    let create = flags.bits & OpenFlags::CREATE.bits != 0;
    let truncate = flags.bits & OpenFlags::TRUNCATE.bits != 0;

    // Resolve the path — or create if needed
    let ino = match ext2::resolve_path(&ext2.sb, path, &mut ext2.cache, &ext2.blk) {
        Ok(ino) => ino,
        Err(_) => {
            if create && !ext2.read_only {
                // Create the file
                let (parent_path, name) = match split_parent_name(path) {
                    Some(p) => p,
                    None => {
                        send_error(ctl_ch, FsError::InvalidPath {});
                        return;
                    }
                };
                if name.is_empty() {
                    send_error(ctl_ch, FsError::InvalidPath {});
                    return;
                }
                let parent_ino = match ext2::resolve_path(&ext2.sb, parent_path, &mut ext2.cache, &ext2.blk) {
                    Ok(ino) => ino,
                    Err(_) => {
                        send_error(ctl_ch, FsError::NotFound {});
                        return;
                    }
                };
                match ext2::create_file(&ext2.sb, parent_ino, name, &mut ext2.cache, &ext2.blk) {
                    Ok(ino) => {
                        ext2.cache.sync(&ext2.blk).ok();
                        ino
                    }
                    Err(e) => {
                        send_error(ctl_ch, map_ext2_error(e));
                        return;
                    }
                }
            } else {
                send_error(ctl_ch, FsError::NotFound {});
                return;
            }
        }
    };

    let mut inode = match ext2::read_inode(&ext2.sb, ino, &mut ext2.cache, &ext2.blk) {
        Ok(i) => i,
        Err(_) => {
            send_error(ctl_ch, FsError::Io {});
            return;
        }
    };

    if inode.is_dir() {
        send_error(ctl_ch, FsError::NotAFile {});
        return;
    }

    // Handle truncate
    if truncate && !ext2.read_only && inode.size > 0 {
        inode.size = 0;
        inode.i_blocks = 0;
        inode.blocks = [0u32; 15];
        if ext2::write_inode(&ext2.sb, ino, &inode, &mut ext2.cache, &ext2.blk).is_err() {
            send_error(ctl_ch, FsError::Io {});
            return;
        }
        ext2.cache.sync(&ext2.blk).ok();
    }

    // Find a free file slot
    let slot_idx = match file_slots.iter().position(|s| s.is_none()) {
        Some(idx) => idx,
        None => {
            send_error(ctl_ch, FsError::Io {});
            return;
        }
    };

    // Create channel pair for file I/O
    let (my_handle, client_file_handle) = raw::sys_chan_create();
    if my_handle == usize::MAX {
        send_error(ctl_ch, FsError::Io {});
        return;
    }

    let append = flags.bits & OpenFlags::APPEND.bits != 0;
    if !ext2.register_open_file(my_handle, ino, append) {
        raw::sys_chan_close(my_handle);
        raw::sys_chan_close(client_file_handle);
        send_error(ctl_ch, FsError::Io {});
        return;
    }

    // Send Opened with the file handle as capability
    let _ = ctl_ch.send(&FsResponse::Opened {
        kind: FsEntryKind::File {},
        size: inode.size,
        file: rvos_wire::RawChannelCap::new(client_file_handle),
    });
    // Close our reference to the client's endpoint (they hold their own via cap transfer)
    raw::sys_chan_close(client_file_handle);

    // Store file channel in the flat file slot array
    file_slots[slot_idx] = Some(FileSlot {
        ch: Channel::from_raw_handle(my_handle),
        inode: ino,
    });
}

fn do_readdir(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, path: &[u8]) {
    if path.is_empty() || path[0] != b'/' {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    let ino = match ext2::resolve_path(&ext2.sb, path, &mut ext2.cache, &ext2.blk) {
        Ok(ino) => ino,
        Err(_) => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };

    let dir_inode = match ext2::read_inode(&ext2.sb, ino, &mut ext2.cache, &ext2.blk) {
        Ok(i) => i,
        Err(_) => {
            send_error(ch, FsError::Io {});
            return;
        }
    };

    if !dir_inode.is_dir() {
        send_error(ch, FsError::NotAFile {});
        return;
    }

    let raw_handle = ch.raw_handle();

    // Collect entries into a buffer since readdir borrows the cache.
    // We'll store up to 128 entries.
    let mut entries: [(u32, u8, [u8; 64], usize); 128] = [(0, 0, [0; 64], 0); 128];
    let mut count = 0;

    let result = ext2::readdir(&ext2.sb, &dir_inode, &mut ext2.cache, &ext2.blk, |entry_ino, file_type, name| {
        if count < 128 {
            entries[count].0 = entry_ino;
            entries[count].1 = file_type;
            let nlen = name.len().min(64);
            entries[count].2[..nlen].copy_from_slice(&name[..nlen]);
            entries[count].3 = nlen;
            count += 1;
        }
    });

    if result.is_err() {
        send_error(ch, FsError::Io {});
        return;
    }

    // Send collected entries
    for entry in entries.iter().take(count) {
        let (entry_ino, file_type, ref name_buf, name_len) = *entry;
        let name_str = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("");

        // Get size for files
        let (kind, size) = match file_type {
            2 => (FsEntryKind::Directory {}, 0u64),
            _ => {
                // Try to read the inode for size
                if let Ok(entry_inode) = ext2::read_inode(&ext2.sb, entry_ino, &mut ext2.cache, &ext2.blk) {
                    let k = if entry_inode.is_dir() { FsEntryKind::Directory {} } else { FsEntryKind::File {} };
                    (k, entry_inode.size)
                } else {
                    (FsEntryKind::File {}, 0)
                }
            }
        };

        send_dir_entry(raw_handle, kind, size, name_str);
    }

    send_dir_sentinel(raw_handle);
}

fn do_delete(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, path: &[u8]) {
    if ext2.read_only {
        send_error(ch, FsError::Io {});
        return;
    }
    let (parent_path, name) = match split_parent_name(path) {
        Some(p) => p,
        None => {
            send_error(ch, FsError::InvalidPath {});
            return;
        }
    };
    if name.is_empty() {
        send_error(ch, FsError::InvalidPath {});
        return;
    }
    let parent_ino = match ext2::resolve_path(&ext2.sb, parent_path, &mut ext2.cache, &ext2.blk) {
        Ok(ino) => ino,
        Err(_) => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };
    match ext2::unlink(&ext2.sb, parent_ino, name, &mut ext2.cache, &ext2.blk) {
        Ok(()) => {
            ext2.cache.sync(&ext2.blk).ok();
            let _ = ch.send(&FsResponse::Ok {
                kind: FsEntryKind::File {},
                size: 0,
            });
        }
        Err(_) => {
            send_error(ch, FsError::Io {});
        }
    }
}

fn do_mkdir(ext2: &mut Ext2State, ch: &Channel<FsResponse, FsRequestMsg>, path: &[u8]) {
    if ext2.read_only {
        send_error(ch, FsError::Io {});
        return;
    }
    // Check if it already exists
    if ext2::resolve_path(&ext2.sb, path, &mut ext2.cache, &ext2.blk).is_ok() {
        send_error(ch, FsError::AlreadyExists {});
        return;
    }
    let (parent_path, name) = match split_parent_name(path) {
        Some(p) => p,
        None => {
            send_error(ch, FsError::InvalidPath {});
            return;
        }
    };
    if name.is_empty() {
        send_error(ch, FsError::InvalidPath {});
        return;
    }
    let parent_ino = match ext2::resolve_path(&ext2.sb, parent_path, &mut ext2.cache, &ext2.blk) {
        Ok(ino) => ino,
        Err(_) => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };
    match ext2::create_dir(&ext2.sb, parent_ino, name, &mut ext2.cache, &ext2.blk) {
        Ok(_) => {
            ext2.cache.sync(&ext2.blk).ok();
            let _ = ch.send(&FsResponse::Ok {
                kind: FsEntryKind::Directory {},
                size: 0,
            });
        }
        Err(e) => {
            send_error(ch, map_ext2_error(e));
        }
    }
}

fn handle_file_read(ext2: &mut Ext2State, ch: &Channel<FileResponseMsg, FileRequestMsg>, inode_num: u32, offset: FileOffset, len: u32) {
    let handle = ch.raw_handle();

    let explicit_offset = match offset {
        FileOffset::Explicit { offset } => Some(offset as usize),
        FileOffset::Stream {} => None,
    };

    let file_offset = match explicit_offset {
        Some(off) => off,
        None => {
            match ext2.get_open_file_mut(handle) {
                Some(of) => of.position,
                None => 0,
            }
        }
    };

    let inode = match ext2::read_inode(&ext2.sb, inode_num, &mut ext2.cache, &ext2.blk) {
        Ok(i) => i,
        Err(_) => {
            send_file_error(ch, FsError::Io {});
            return;
        }
    };

    if file_offset as u64 >= inode.size {
        send_data_sentinel(ch);
        return;
    }

    let available = (inode.size - file_offset as u64) as usize;
    let to_send = (len as usize).min(available);

    // Read in chunks via the block cache
    let mut sent = 0usize;
    let mut read_buf = [0u8; MAX_DATA_CHUNK];

    while sent < to_send {
        let chunk_size = MAX_DATA_CHUNK.min(to_send - sent);
        let n = match ext2::read_data(&ext2.sb, &inode, (file_offset + sent) as u64, &mut read_buf[..chunk_size], &mut ext2.cache, &ext2.blk) {
            Ok(n) => n,
            Err(_) => {
                send_file_error(ch, FsError::Io {});
                return;
            }
        };
        if n == 0 {
            break;
        }
        send_data_chunk(ch, &read_buf[..n]);
        sent += n;
    }

    send_data_sentinel(ch);

    // Update stream position
    if explicit_offset.is_none() {
        if let Some(of) = ext2.get_open_file_mut(handle) {
            of.position = file_offset + sent;
        }
    }
}

fn handle_file_write(ext2: &mut Ext2State, ch: &Channel<FileResponseMsg, FileRequestMsg>, inode_num: u32, offset: FileOffset, data: &[u8]) {
    if ext2.read_only {
        send_file_error(ch, FsError::Io {});
        return;
    }

    let handle = ch.raw_handle();

    let mut inode = match ext2::read_inode(&ext2.sb, inode_num, &mut ext2.cache, &ext2.blk) {
        Ok(i) => i,
        Err(_) => {
            send_file_error(ch, FsError::Io {});
            return;
        }
    };

    // Determine write offset
    let write_offset = match offset {
        FileOffset::Explicit { offset: off } => off,
        FileOffset::Stream {} => {
            let of = ext2.get_open_file_mut(handle);
            match of {
                Some(of) if of.append => inode.size,
                Some(of) => of.position as u64,
                None => inode.size,
            }
        }
    };

    let written = match ext2::write_data(&ext2.sb, &mut inode, write_offset, data, &mut ext2.cache, &ext2.blk) {
        Ok(n) => n,
        Err(e) => {
            send_file_error(ch, map_ext2_error(e));
            return;
        }
    };

    // Write back the inode
    if ext2::write_inode(&ext2.sb, inode_num, &inode, &mut ext2.cache, &ext2.blk).is_err() {
        send_file_error(ch, FsError::Io {});
        return;
    }
    ext2.cache.sync(&ext2.blk).ok();

    // Update stream position
    if let Some(of) = ext2.get_open_file_mut(handle) {
        of.position = write_offset as usize + written;
    }

    send_write_ok(ch, written as u32);
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

    // Read and validate ext2 superblock
    let sb = match ext2::read_superblock(&blk) {
        Ok(sb) => sb,
        Err(e) => {
            eprintln!("[ext2-server] superblock error: {}", e);
            return;
        }
    };

    eprintln!(
        "[ext2-server] ext2: {} blocks, {} inodes, block_size={}, inode_size={}",
        sb.blocks_count, sb.inodes_count, sb.block_size, sb.inode_size
    );

    let cache = BlockCache::new(sb.block_size);

    let mut ext2_state = Ext2State {
        blk,
        cache,
        sb,
        read_only,
        open_file_state: [const { OpenFileState { endpoint_handle: 0, inode: 0, active: false, append: false, position: 0 } }; MAX_OPEN_FILES],
        open_count: 0,
    };

    let mut clients: [ClientState; MAX_CLIENTS] =
        [const { ClientState { ctl: None } }; MAX_CLIENTS];

    // Flat array of open file channels (not per-client).
    let mut file_slots: [Option<FileSlot>; MAX_OPEN_FILES] =
        [const { None }; MAX_OPEN_FILES];

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
                    };
                } else {
                    raw::sys_chan_close(cap);
                }
            }
        }

        // Poll all open file channels
        for slot in &mut file_slots {
            let Some(file) = slot.as_mut() else { continue };

            let file_inode = file.inode;
            let raw_h = file.ch.raw_handle();

            // Phase 1: recv, copy borrowed data to stack
            let mut read_params: Option<(FileOffset, u32)> = None;
            let mut write_buf = [0u8; 1024];
            let mut write_params: Option<(FileOffset, usize)> = None;
            let mut ioctl = false;
            let mut file_closed = false;

            match file.ch.try_recv() {
                Ok(FileRequest::Read { offset, len }) => {
                    read_params = Some((offset, len));
                }
                Ok(FileRequest::Write { offset, data }) => {
                    let dlen = data.len().min(1024);
                    write_buf[..dlen].copy_from_slice(&data[..dlen]);
                    write_params = Some((offset, dlen));
                }
                Ok(FileRequest::Ioctl { .. }) => {
                    ioctl = true;
                }
                Err(rvos::RecvError::Closed) => {
                    file_closed = true;
                }
                Err(_) => {}
            }

            // Phase 2: act on extracted data
            if let Some((offset, len)) = read_params {
                handled = true;
                handle_file_read(&mut ext2_state, &file.ch, file_inode, offset, len);
            } else if let Some((offset, dlen)) = write_params {
                handled = true;
                handle_file_write(&mut ext2_state, &file.ch, file_inode, offset, &write_buf[..dlen]);
            } else if ioctl {
                handled = true;
                send_file_error(&file.ch, FsError::Io {});
            } else if file_closed {
                ext2_state.close_open_file(raw_h);
                *slot = None; // Drop closes the channel handle via RAII
            }
        }

        // Poll each active client's ctl channel
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_CLIENTS {
            if !clients[i].is_active() { continue; }

            let mut path_buf = [0u8; 64];
            let mut path_len = 0usize;
            let mut open_flags: Option<OpenFlags> = None;
            let mut is_delete = false;
            let mut is_stat = false;
            let mut is_readdir = false;
            let mut is_mkdir = false;
            let mut path_too_long = false;
            let mut ctl_closed = false;

            {
                let ch = clients[i].ctl.as_mut().unwrap();
                match ch.try_recv() {
                    Ok(FsRequest::Open { flags, path }) => {
                        if path.len() > path_buf.len() {
                            path_too_long = true;
                        } else {
                            path_len = path.len();
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            open_flags = Some(flags);
                        }
                    }
                    Ok(FsRequest::Delete { path }) => {
                        if path.len() > path_buf.len() {
                            path_too_long = true;
                        } else {
                            path_len = path.len();
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_delete = true;
                        }
                    }
                    Ok(FsRequest::Stat { path }) => {
                        if path.len() > path_buf.len() {
                            path_too_long = true;
                        } else {
                            path_len = path.len();
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_stat = true;
                        }
                    }
                    Ok(FsRequest::Readdir { path }) => {
                        if path.len() > path_buf.len() {
                            path_too_long = true;
                        } else {
                            path_len = path.len();
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_readdir = true;
                        }
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
                        if path.len() > path_buf.len() {
                            path_too_long = true;
                        } else {
                            path_len = path.len();
                            path_buf[..path_len].copy_from_slice(path.as_bytes());
                            is_mkdir = true;
                        }
                    }
                    Err(rvos::RecvError::Closed) => {
                        ctl_closed = true;
                    }
                    Err(_) => {}
                }
            }

            // Phase 2: dispatch (ctl borrow released, ext2 and clients are separate)
            if path_too_long {
                handled = true;
                send_error(clients[i].ctl.as_ref().unwrap(), FsError::InvalidPath {});
            } else if let Some(flags) = open_flags {
                handled = true;
                let ctl_ch = clients[i].ctl.as_ref().unwrap();
                do_open(&mut ext2_state, ctl_ch, &mut file_slots, flags, &path_buf[..path_len]);
            } else if is_delete {
                handled = true;
                do_delete(&mut ext2_state, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
            } else if is_stat {
                handled = true;
                do_stat(&mut ext2_state, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
            } else if is_readdir {
                handled = true;
                do_readdir(&mut ext2_state, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
            } else if is_mkdir {
                handled = true;
                do_mkdir(&mut ext2_state, clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
            } else if ctl_closed {
                clients[i].ctl = None;
            }
        }

        if !handled {
            // Register interest on all active channels, then block
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            for client in &clients {
                if let Some(ref ctl) = client.ctl {
                    ctl.poll_add();
                }
            }
            for file in file_slots.iter().flatten() {
                file.ch.poll_add();
            }
            raw::sys_block();
        }
    }
}
