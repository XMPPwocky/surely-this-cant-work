extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::Channel;
use rvos::rvos_wire;
use rvos_proto::fs::{
    FsRequest, FsRequestMsg, FsResponse, FsEntryKind, FsError, OpenFlags,
    FileRequest, FileRequestMsg, FileResponse, FileResponseMsg,
    FileOffset, ReaddirResponse,
};

// --- Constants ---

const MAX_FILES: usize = 160;
const MAX_FILE_SIZE: usize = 4096;
const MAX_NAME_LEN: usize = 32;
const MAX_CHILDREN: usize = 128;
const MAX_OPEN_FILES: usize = 16;
const MAX_MOUNTS: usize = 8;

// Max data payload per chunk: MAX_MSG_SIZE(1024) - 3 (tag u8 + length u16)
const MAX_DATA_CHUNK: usize = 1021;

// Control channel handle (set by kernel at spawn)
const CONTROL_HANDLE: usize = 1;

// --- Filesystem data structures ---

#[derive(Clone, Copy, PartialEq)]
enum InodeKind {
    File,
    Dir,
}

struct DirEntry {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    inode: usize,
}

impl DirEntry {
    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

struct Inode {
    kind: InodeKind,
    // File data (only used if kind == File)
    data: [u8; MAX_FILE_SIZE],
    data_len: usize,
    // Directory children (only used if kind == Dir)
    children: [Option<DirEntry>; MAX_CHILDREN],
    child_count: usize,
    active: bool,
}

impl Inode {
    const fn new_empty() -> Self {
        Inode {
            kind: InodeKind::File,
            data: [0u8; MAX_FILE_SIZE],
            data_len: 0,
            children: [const { None }; MAX_CHILDREN],
            child_count: 0,
            active: false,
        }
    }

    fn init_file(&mut self) {
        self.kind = InodeKind::File;
        self.data_len = 0;
        self.child_count = 0;
        self.active = true;
    }

    fn init_dir(&mut self) {
        self.kind = InodeKind::Dir;
        self.data_len = 0;
        self.child_count = 0;
        self.active = true;
    }

    fn find_child(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.child_count {
            if let Some(ref entry) = self.children[i] {
                if entry.name_bytes() == name {
                    return Some(entry.inode);
                }
            }
        }
        None
    }

    fn add_child(&mut self, name: &[u8], inode: usize) -> bool {
        if self.child_count >= MAX_CHILDREN {
            return false;
        }
        let mut entry = DirEntry {
            name: [0u8; MAX_NAME_LEN],
            name_len: name.len(),
            inode,
        };
        entry.name[..name.len()].copy_from_slice(name);
        // Find empty slot (could be a gap from deletion)
        for i in 0..MAX_CHILDREN {
            if self.children[i].is_none() {
                self.children[i] = Some(entry);
                self.child_count += 1;
                return true;
            }
        }
        false
    }

    fn remove_child(&mut self, name: &[u8]) -> Option<usize> {
        for i in 0..MAX_CHILDREN {
            if let Some(ref entry) = self.children[i] {
                if entry.name_bytes() == name {
                    let inode = entry.inode;
                    self.children[i] = None;
                    self.child_count -= 1;
                    return Some(inode);
                }
            }
        }
        None
    }
}

struct OpenFile {
    endpoint_handle: usize,
    inode: usize,
    active: bool,
    append: bool,
    position: usize,
}

// --- VFS mount table ---

use rvos::transport::UserTransport;

struct MountEntry {
    path: [u8; 64],
    path_len: usize,
    /// Backend ctl channel (RAII — closed on drop/unmount).
    /// Typed as client-side (sends requests, receives responses).
    /// Actual RPC uses UserTransport + rpc_call on the raw handle.
    backend: Channel<FsRequestMsg, FsResponse>,
    #[allow(dead_code)] // used later for RO mount enforcement
    flags: u32,
}

struct Filesystem {
    inodes: [Inode; MAX_FILES],
    open_files: [OpenFile; MAX_OPEN_FILES],
    open_count: usize,
    mounts: [Option<MountEntry>; MAX_MOUNTS],
}

impl Filesystem {
    fn new() -> Self {
        let mut fs = Filesystem {
            inodes: [const { Inode::new_empty() }; MAX_FILES],
            open_files: [const { OpenFile { endpoint_handle: 0, inode: 0, active: false, append: false, position: 0 } }; MAX_OPEN_FILES],
            open_count: 0,
            mounts: [const { None }; MAX_MOUNTS],
        };
        // Inode 0 is the root directory
        fs.inodes[0].init_dir();
        fs
    }

    fn alloc_inode(&mut self) -> Option<usize> {
        (1..MAX_FILES).find(|&i| !self.inodes[i].active)
    }

    /// Resolve a path to an inode index. Returns None if not found.
    fn resolve_path(&self, path: &[u8]) -> Option<usize> {
        if path.is_empty() || path[0] != b'/' {
            return None;
        }
        let path = &path[1..]; // strip leading /
        if path.is_empty() {
            return Some(0); // root
        }
        // Strip trailing slash
        let path = if path.last() == Some(&b'/') { &path[..path.len()-1] } else { path };

        let mut current = 0usize; // root inode
        for component in split_path(path) {
            if component.is_empty() {
                continue;
            }
            if self.inodes[current].kind != InodeKind::Dir {
                return None;
            }
            match self.inodes[current].find_child(component) {
                Some(child) => current = child,
                None => return None,
            }
        }
        Some(current)
    }

    /// Resolve parent directory of a path, returning (parent_inode, filename).
    fn resolve_parent<'a>(&self, path: &'a [u8]) -> Option<(usize, &'a [u8])> {
        if path.is_empty() || path[0] != b'/' {
            return None;
        }
        let path = &path[1..];
        // Strip trailing slash
        let path = if !path.is_empty() && path.last() == Some(&b'/') { &path[..path.len()-1] } else { path };

        if path.is_empty() {
            return None; // root has no parent in this context
        }

        // Find last '/'
        let mut last_slash = None;
        for (i, &byte) in path.iter().enumerate() {
            if byte == b'/' {
                last_slash = Some(i);
            }
        }

        match last_slash {
            None => {
                // File in root directory
                Some((0, path))
            }
            Some(pos) => {
                let dir_path = &path[..pos];
                let filename = &path[pos+1..];
                if filename.is_empty() {
                    return None;
                }
                // Resolve directory path
                let mut current = 0usize;
                for component in split_path(dir_path) {
                    if component.is_empty() {
                        continue;
                    }
                    if self.inodes[current].kind != InodeKind::Dir {
                        return None;
                    }
                    match self.inodes[current].find_child(component) {
                        Some(child) => current = child,
                        None => return None,
                    }
                }
                Some((current, filename))
            }
        }
    }

    /// Create intermediate directories along a path (mkdir -p behavior).
    /// Returns the inode of the parent directory and the filename component.
    fn ensure_parent_dirs<'a>(&mut self, path: &'a [u8]) -> Option<(usize, &'a [u8])> {
        if path.is_empty() || path[0] != b'/' {
            return None;
        }
        let path = &path[1..];
        let path = if !path.is_empty() && path.last() == Some(&b'/') { &path[..path.len()-1] } else { path };

        if path.is_empty() {
            return None;
        }

        // Collect component boundaries
        let mut components: [(&[u8], usize, usize); 16] = [(&[], 0, 0); 16];
        let mut comp_count = 0;
        {
            let mut start = 0;
            for i in 0..path.len() {
                if path[i] == b'/' {
                    if i > start
                        && comp_count < 16 {
                            components[comp_count] = (&path[start..i], start, i);
                            comp_count += 1;
                        }
                    start = i + 1;
                }
            }
            if start < path.len()
                && comp_count < 16 {
                    components[comp_count] = (&path[start..], start, path.len());
                    comp_count += 1;
                }
        }

        if comp_count == 0 {
            return None;
        }

        let filename = components[comp_count - 1].0;

        // Create directories for all but the last component
        let mut current = 0usize; // root
        for comp in components[..comp_count - 1].iter() {
            let name = comp.0;
            if name.is_empty() {
                continue;
            }
            if self.inodes[current].kind != InodeKind::Dir {
                return None;
            }
            match self.inodes[current].find_child(name) {
                Some(child) => {
                    current = child;
                }
                None => {
                    // Create the intermediate directory
                    let new_inode = self.alloc_inode()?;
                    self.inodes[new_inode].init_dir();
                    if !self.inodes[current].add_child(name, new_inode) {
                        self.inodes[new_inode].active = false;
                        return None;
                    }
                    current = new_inode;
                }
            }
        }

        Some((current, filename))
    }

    fn register_open_file(&mut self, endpoint_handle: usize, inode: usize, append: bool) -> bool {
        for i in 0..MAX_OPEN_FILES {
            if !self.open_files[i].active {
                self.open_files[i] = OpenFile { endpoint_handle, inode, active: true, append, position: 0 };
                self.open_count += 1;
                return true;
            }
        }
        false
    }

    fn is_append(&self, endpoint_handle: usize) -> bool {
        for i in 0..MAX_OPEN_FILES {
            if self.open_files[i].active && self.open_files[i].endpoint_handle == endpoint_handle {
                return self.open_files[i].append;
            }
        }
        false
    }

    fn get_open_file_mut(&mut self, endpoint_handle: usize) -> Option<&mut OpenFile> {
        for i in 0..MAX_OPEN_FILES {
            if self.open_files[i].active && self.open_files[i].endpoint_handle == endpoint_handle {
                return Some(&mut self.open_files[i]);
            }
        }
        None
    }

    fn close_open_file(&mut self, endpoint_handle: usize) {
        for i in 0..MAX_OPEN_FILES {
            if self.open_files[i].active && self.open_files[i].endpoint_handle == endpoint_handle {
                self.open_files[i].active = false;
                self.open_count -= 1;
                return;
            }
        }
    }
}

/// Split path bytes by '/' returning an iterator of components.
fn split_path(path: &[u8]) -> PathSplitter<'_> {
    PathSplitter { path, pos: 0 }
}

struct PathSplitter<'a> {
    path: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for PathSplitter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.path.len() {
            return None;
        }
        // Skip leading slashes
        while self.pos < self.path.len() && self.path[self.pos] == b'/' {
            self.pos += 1;
        }
        if self.pos >= self.path.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.path.len() && self.path[self.pos] != b'/' {
            self.pos += 1;
        }
        Some(&self.path[start..self.pos])
    }
}

// --- Typed message helpers ---

fn send_error(ch: &Channel<FsResponse, FsRequestMsg>, code: FsError) {
    let _ = ch.send(&FsResponse::Error { code });
}

fn send_stat_ok(ch: &Channel<FsResponse, FsRequestMsg>, kind: FsEntryKind, size: u64) {
    let _ = ch.send(&FsResponse::Ok { kind, size });
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

fn send_file_error(ch: &Channel<FileResponseMsg, FileRequestMsg>, code: FsError) {
    let _ = ch.send(&FileResponse::Error { code });
}

// Readdir helpers stay raw — ReaddirResponse is a different type than FsResponse,
// so it can't be sent via the typed Channel<FsResponse, FsRequestMsg>.
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

// --- VFS mount helpers ---

/// Find the longest-prefix mount entry for a path.
/// Returns (mount_index, relative_path) where relative_path starts with '/'.
fn find_mount(path: &[u8]) -> Option<(usize, &[u8])> {
    let fs = fs();
    let mut best: Option<(usize, usize)> = None; // (index, mount_path_len)
    for (i, m) in fs.mounts.iter().enumerate() {
        if let Some(ref entry) = m {
            let mp = &entry.path[..entry.path_len];
            // Match exact or with trailing '/'
            if (path == mp || (path.len() > mp.len() && path.starts_with(mp) && path[mp.len()] == b'/'))
                && (best.is_none() || mp.len() > best.unwrap().1)
            {
                best = Some((i, mp.len()));
            }
        }
    }
    if let Some((idx, mp_len)) = best {
        let rel = if path.len() == mp_len {
            b"/" as &[u8]
        } else {
            &path[mp_len..] // starts with '/'
        };
        Some((idx, rel))
    } else {
        None
    }
}

/// Forward a single-RPC request to a mount backend and relay the response.
fn forward_rpc(
    mount_idx: usize,
    client_ch: &Channel<FsResponse, FsRequestMsg>,
    request: &impl rvos_wire::Serialize,
) {
    let handle = fs().mounts[mount_idx].as_ref().unwrap().backend.raw_handle();
    let mut transport = UserTransport::new(handle);
    let mut buf = [0u8; rvos_wire::MAX_MSG_SIZE];
    match rvos_wire::rpc_call::<_, _, FsResponse>(&mut transport, request, &mut buf) {
        Ok(resp) => { let _ = client_ch.send(&resp); }
        Err(_) => send_error(client_ch, FsError::Io {}),
    }
}

/// Forward a Stat request to a mount backend.
fn forward_stat(mount_idx: usize, ch: &Channel<FsResponse, FsRequestMsg>, rel_path: &[u8]) {
    let path = core::str::from_utf8(rel_path).unwrap_or("/");
    forward_rpc(mount_idx, ch, &FsRequest::Stat { path });
}

/// Forward a Delete request to a mount backend.
fn forward_delete(mount_idx: usize, ch: &Channel<FsResponse, FsRequestMsg>, rel_path: &[u8]) {
    let path = core::str::from_utf8(rel_path).unwrap_or("/");
    forward_rpc(mount_idx, ch, &FsRequest::Delete { path });
}

/// Forward a Mkdir request to a mount backend.
fn forward_mkdir(mount_idx: usize, ch: &Channel<FsResponse, FsRequestMsg>, rel_path: &[u8]) {
    let path = core::str::from_utf8(rel_path).unwrap_or("/");
    forward_rpc(mount_idx, ch, &FsRequest::Mkdir { path });
}

/// Forward an Open request to a mount backend, relaying the Opened response
/// (including file channel cap) to the client.
fn forward_open(mount_idx: usize, ch: &Channel<FsResponse, FsRequestMsg>, flags: OpenFlags, rel_path: &[u8]) {
    let handle = fs().mounts[mount_idx].as_ref().unwrap().backend.raw_handle();
    let path = core::str::from_utf8(rel_path).unwrap_or("/");
    let mut transport = UserTransport::new(handle);
    let mut buf = [0u8; rvos_wire::MAX_MSG_SIZE];
    match rvos_wire::rpc_call::<_, _, FsResponse>(
        &mut transport,
        &FsRequest::Open { flags, path },
        &mut buf,
    ) {
        Ok(resp) => {
            // Extract file cap handle before sending (send will inc_ref for receiver)
            let cap_handle = if let FsResponse::Opened { ref file, .. } = resp {
                Some(file.raw())
            } else {
                None
            };
            let _ = ch.send(&resp);
            // Close our reference to the file cap (client now has their own)
            if let Some(h) = cap_handle {
                raw::sys_chan_close(h);
            }
        }
        Err(_) => send_error(ch, FsError::Io {}),
    }
}

/// Forward a Readdir request to a mount backend, relaying the streaming
/// response (Entry... End) to the client.
///
/// Uses raw messages because ReaddirResponse is a different type than FsResponse
/// and can't go through the typed client channel.
fn forward_readdir(mount_idx: usize, client_handle: usize, rel_path: &[u8]) {
    let backend_handle = fs().mounts[mount_idx].as_ref().unwrap().backend.raw_handle();
    let path = core::str::from_utf8(rel_path).unwrap_or("/");

    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FsRequest::Readdir { path }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(backend_handle, &msg);

    // Relay streaming responses until we see End, Error, or decode failure
    loop {
        let mut resp = Message::new();
        let ret = raw::sys_chan_recv_blocking(backend_handle, &mut resp);
        if ret != 0 { break; }

        raw::sys_chan_send_blocking(client_handle, &resp);

        // Check if this was a terminal message
        let is_terminal = !matches!(
            rvos_wire::from_bytes::<ReaddirResponse>(&resp.data[..resp.len]),
            Ok(ReaddirResponse::Entry { .. })
        );
        if is_terminal { break; }
    }
}

/// Handle a Mount request: store backend cap in mount table.
fn do_mount(ch: &Channel<FsResponse, FsRequestMsg>, target: &[u8], flags: u32, cap: usize) {
    if cap == NO_CAP {
        send_error(ch, FsError::Io {});
        return;
    }

    // Take RAII ownership of the backend cap immediately.
    // If we don't store it, Channel::drop will close it.
    let backend = Channel::<FsRequestMsg, FsResponse>::from_raw_handle(cap);

    let fs = fs();

    // Ensure the mount point exists as a directory in tmpfs
    if target != b"/"
        && fs.resolve_path(target).is_none()
    {
        // Auto-create the mount point directory
        if let Some((parent_inode, dirname)) = fs.resolve_parent(target) {
            if fs.inodes[parent_inode].kind == InodeKind::Dir {
                if let Some(new_inode) = fs.alloc_inode() {
                    fs.inodes[new_inode].init_dir();
                    if !fs.inodes[parent_inode].add_child(dirname, new_inode) {
                        fs.inodes[new_inode].active = false;
                    }
                }
            }
        }
    }

    // Find a free mount slot
    let slot = fs.mounts.iter_mut().find(|m| m.is_none());
    if let Some(slot) = slot {
        let mut entry = MountEntry {
            path: [0u8; 64],
            path_len: target.len(),
            backend,
            flags,
        };
        entry.path[..target.len()].copy_from_slice(target);
        *slot = Some(entry);

        let _ = ch.send(&FsResponse::MountOk {});
    } else {
        // backend dropped here — Channel::drop closes the cap
        send_error(ch, FsError::NoSpace {});
    }
}

/// Handle an Unmount request: remove from mount table and close backend channel.
fn do_unmount(ch: &Channel<FsResponse, FsRequestMsg>, target: &[u8]) {
    let fs = fs();
    for mount in &mut fs.mounts {
        if let Some(ref entry) = mount {
            if &entry.path[..entry.path_len] == target {
                *mount = None; // Channel::drop closes the backend handle
                send_stat_ok(ch, FsEntryKind::Directory {}, 0);
                return;
            }
        }
    }
    send_error(ch, FsError::NotFound {});
}

// --- Main server ---

use core::cell::UnsafeCell;

struct FsCell(UnsafeCell<Option<Filesystem>>);
unsafe impl Sync for FsCell {}

static FS: FsCell = FsCell(UnsafeCell::new(None));

fn fs() -> &'static mut Filesystem {
    unsafe { (*FS.0.get()).as_mut().unwrap() }
}

fn handle_read(ch: &Channel<FileResponseMsg, FileRequestMsg>, inode_idx: usize, offset: FileOffset, len: u32) {
    let explicit_offset = match offset {
        FileOffset::Explicit { offset } => Some(offset as usize),
        FileOffset::Stream {} => None,
    };

    let len = len as usize;
    let handle = ch.raw_handle();

    let fs = fs();

    let offset = match explicit_offset {
        Some(off) => off,
        None => {
            // Stream mode: use server-tracked position
            match fs.get_open_file_mut(handle) {
                Some(of) => of.position,
                None => 0,
            }
        }
    };

    let inode = &fs.inodes[inode_idx];

    if offset >= inode.data_len {
        // At or past EOF - send sentinel immediately
        send_data_sentinel(ch);
        return;
    }

    let available = inode.data_len - offset;
    let to_send = if len < available { len } else { available };

    let data_slice: &[u8] = &inode.data[offset..offset + to_send];

    let mut sent = 0;
    while sent < to_send {
        let chunk_end = if sent + MAX_DATA_CHUNK < to_send { sent + MAX_DATA_CHUNK } else { to_send };
        send_data_chunk(ch, &data_slice[sent..chunk_end]);
        sent = chunk_end;
    }

    // Send sentinel
    send_data_sentinel(ch);

    // Advance server-side position for stream mode
    if explicit_offset.is_none() {
        if let Some(of) = fs.get_open_file_mut(handle) {
            of.position = offset + to_send;
        }
    }
}

fn handle_write(ch: &Channel<FileResponseMsg, FileRequestMsg>, inode_idx: usize, offset: FileOffset, data: &[u8]) {
    let explicit_offset = match offset {
        FileOffset::Explicit { offset } => Some(offset as usize),
        FileOffset::Stream {} => None,
    };

    let handle = ch.raw_handle();
    let fs = fs();
    let is_append_mode = fs.is_append(handle);

    // Resolve offset: append > stream > explicit
    let offset = if is_append_mode {
        fs.inodes[inode_idx].data_len
    } else {
        match explicit_offset {
            Some(off) => off,
            None => {
                // Stream mode: use server-tracked position
                match fs.get_open_file_mut(handle) {
                    Some(of) => of.position,
                    None => 0,
                }
            }
        }
    };

    let inode = &mut fs.inodes[inode_idx];

    let end = offset + data.len();
    let written;
    if end > MAX_FILE_SIZE {
        // Truncate to max
        let can_write = MAX_FILE_SIZE.saturating_sub(offset);
        if can_write == 0 {
            send_file_error(ch, FsError::Io {});
            return;
        }
        // Zero-fill gap if needed
        if offset > inode.data_len {
            let fill_end = if offset < MAX_FILE_SIZE { offset } else { MAX_FILE_SIZE };
            for i in inode.data_len..fill_end {
                inode.data[i] = 0;
            }
        }
        inode.data[offset..offset + can_write].copy_from_slice(&data[..can_write]);
        if offset + can_write > inode.data_len {
            inode.data_len = offset + can_write;
        }
        written = can_write;
        send_write_ok(ch, can_write as u32);
    } else {
        // Zero-fill gap if needed
        if offset > inode.data_len {
            for i in inode.data_len..offset {
                inode.data[i] = 0;
            }
        }
        inode.data[offset..end].copy_from_slice(data);
        if end > inode.data_len {
            inode.data_len = end;
        }
        written = data.len();
        send_write_ok(ch, data.len() as u32);
    }

    // Advance server-side position for stream mode
    if explicit_offset.is_none() {
        if let Some(of) = fs.get_open_file_mut(handle) {
            of.position = offset + written;
        }
    }
}

fn do_stat(ch: &Channel<FsResponse, FsRequestMsg>, path_bytes: &[u8]) {
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    // Check mounts first
    if let Some((mount_idx, rel_path)) = find_mount(path_bytes) {
        forward_stat(mount_idx, ch, rel_path);
        return;
    }

    let fs = fs();
    match fs.resolve_path(path_bytes) {
        Some(idx) => {
            let kind = if fs.inodes[idx].kind == InodeKind::Dir {
                FsEntryKind::Directory {}
            } else {
                FsEntryKind::File {}
            };
            let size = if fs.inodes[idx].kind == InodeKind::File { fs.inodes[idx].data_len as u64 } else { 0u64 };
            send_stat_ok(ch, kind, size);
        }
        None => {
            send_error(ch, FsError::NotFound {});
        }
    }
}

fn do_readdir(ch: &Channel<FsResponse, FsRequestMsg>, path_bytes: &[u8]) {
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    // Check mounts first
    if let Some((mount_idx, rel_path)) = find_mount(path_bytes) {
        forward_readdir(mount_idx, ch.raw_handle(), rel_path);
        return;
    }

    let raw_handle = ch.raw_handle();
    let fs = fs();
    let idx = match fs.resolve_path(path_bytes) {
        Some(i) => i,
        None => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };

    if fs.inodes[idx].kind != InodeKind::Dir {
        send_error(ch, FsError::NotAFile {});
        return;
    }

    // Send each child entry (raw — ReaddirResponse is a different type)
    for i in 0..MAX_CHILDREN {
        if let Some(ref entry) = fs.inodes[idx].children[i] {
            let child_inode = entry.inode;
            let kind = if fs.inodes[child_inode].kind == InodeKind::Dir {
                FsEntryKind::Directory {}
            } else {
                FsEntryKind::File {}
            };
            let size = if fs.inodes[child_inode].kind == InodeKind::File {
                fs.inodes[child_inode].data_len as u64
            } else {
                0u64
            };
            let name = core::str::from_utf8(entry.name_bytes()).unwrap_or("");
            send_dir_entry(raw_handle, kind, size, name);
        }
    }

    // Send sentinel
    send_dir_sentinel(raw_handle);
}

// --- Multiplexed client state ---

const MAX_CLIENTS: usize = 8;

struct ClientState {
    ctl: Option<Channel<FsResponse, FsRequestMsg>>,
    file_ch: Option<Channel<FileResponseMsg, FileRequestMsg>>,
    file_inode: usize,
}

impl ClientState {
    fn is_active(&self) -> bool {
        self.ctl.is_some() || self.file_ch.is_some()
    }
}

fn main() {
    // Initialize filesystem
    unsafe {
        *FS.0.get() = Some(Filesystem::new());
    }

    // The fs server has:
    // Handle 0: boot channel (for requesting stdio from init)
    // Handle 1: fs control channel (receives new client endpoints from init)

    let mut clients: [ClientState; MAX_CLIENTS] = [const { ClientState {
        ctl: None, file_ch: None, file_inode: 0,
    } }; MAX_CLIENTS];

    // Multiplexed event loop: poll control channel + all active client channels
    loop {
        let interval = raw::sys_heartbeat();
        let mut handled = false;

        // Accept new clients from control channel (raw — receives caps in sideband)
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut msg);
            if ret != 0 { break; }
            handled = true;
            let cap = if msg.cap_count > 0 { msg.caps[0] } else { rvos::NO_CAP };
            if cap != NO_CAP {
                // Find a free client slot
                let slot = clients.iter_mut().find(|c| !c.is_active());
                if let Some(slot) = slot {
                    *slot = ClientState {
                        ctl: Some(Channel::from_raw_handle(cap)),
                        file_ch: None,
                        file_inode: 0,
                    };
                } else {
                    // No free slots — close the endpoint
                    raw::sys_chan_close(cap);
                }
            }
        }

        // Poll each active client
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_CLIENTS {
            if !clients[i].is_active() { continue; }

            // Poll file channel (two-phase pattern for borrowed Write data)
            if clients[i].file_ch.is_some() {
                let file_inode = clients[i].file_inode;
                let raw_h = clients[i].file_ch.as_ref().unwrap().raw_handle();

                // Phase 1: recv in inner block, copy borrowed data to stack
                let mut read_params: Option<(FileOffset, u32)> = None;
                let mut write_buf = [0u8; 1024];
                let mut write_params: Option<(FileOffset, usize)> = None;
                let mut ioctl = false;
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
                            ioctl = true;
                        }
                        Err(rvos::RecvError::Closed) => {
                            file_closed = true;
                        }
                        Err(_) => {}
                    }
                }

                // Phase 2: act on extracted data (channel borrow released)
                if let Some((offset, len)) = read_params {
                    handled = true;
                    let ch = clients[i].file_ch.as_ref().unwrap();
                    handle_read(ch, file_inode, offset, len);
                } else if let Some((offset, dlen)) = write_params {
                    handled = true;
                    let ch = clients[i].file_ch.as_ref().unwrap();
                    handle_write(ch, file_inode, offset, &write_buf[..dlen]);
                } else if ioctl {
                    handled = true;
                    let ch = clients[i].file_ch.as_ref().unwrap();
                    send_file_error(ch, FsError::Io {});
                } else if file_closed {
                    fs().close_open_file(raw_h);
                    clients[i].file_ch = None;
                    clients[i].file_inode = 0;
                    // If ctl also gone, client is fully cleaned up (is_active() = false)
                }
            }

            // Poll ctl channel (two-phase pattern for borrowed path strings)
            if clients[i].ctl.is_some() {
                // Phase 1: recv in inner block, copy path to stack buffer
                let mut path_buf = [0u8; 64];
                let mut path_len = 0usize;
                let mut open_flags: Option<OpenFlags> = None;
                let mut is_delete = false;
                let mut is_stat = false;
                let mut is_readdir = false;
                let mut is_mkdir = false;
                let mut mount_flags: Option<(u32, usize)> = None; // (flags, backend_cap)
                let mut is_unmount = false;
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
                        Ok(FsRequest::Mount { target, flags, backend }) => {
                            path_len = target.len().min(64);
                            path_buf[..path_len].copy_from_slice(target.as_bytes());
                            mount_flags = Some((flags, backend.raw()));
                        }
                        Ok(FsRequest::Unmount { target }) => {
                            path_len = target.len().min(64);
                            path_buf[..path_len].copy_from_slice(target.as_bytes());
                            is_unmount = true;
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

                // Phase 2: process (ctl borrow released)
                if let Some(flags) = open_flags {
                    handled = true;
                    let pb = &path_buf[..path_len];
                    if pb.is_empty() || pb[0] != b'/' || pb.len() > 60 {
                        send_error(clients[i].ctl.as_ref().unwrap(), FsError::InvalidPath {});
                    } else {
                        do_open(&mut clients[i], flags, pb);
                    }
                } else if is_delete {
                    handled = true;
                    do_delete(clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if is_stat {
                    handled = true;
                    do_stat(clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if is_readdir {
                    handled = true;
                    do_readdir(clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if let Some((flags, backend_cap)) = mount_flags {
                    handled = true;
                    do_mount(clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len], flags, backend_cap);
                } else if is_unmount {
                    handled = true;
                    do_unmount(clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if is_mkdir {
                    handled = true;
                    do_mkdir(clients[i].ctl.as_ref().unwrap(), &path_buf[..path_len]);
                } else if ctl_closed {
                    clients[i].ctl = None;
                    // If file channel also gone, client is fully cleaned up
                }
            }
        }

        if !handled {
            // Register interest on all active channels, then block
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            for client in clients.iter() {
                if let Some(ref ctl) = client.ctl {
                    ctl.poll_add();
                }
                if let Some(ref file_ch) = client.file_ch {
                    file_ch.poll_add();
                }
            }
            if interval > 0 {
                let now = raw::sys_clock().0;
                raw::sys_block_deadline(now + interval);
            } else {
                raw::sys_block();
            }
        }
    }
}

fn close_client_file(client: &mut ClientState) {
    if let Some(ref file_ch) = client.file_ch {
        fs().close_open_file(file_ch.raw_handle());
    }
    client.file_ch = None; // Drop closes the handle via RAII
    client.file_inode = 0;
}

fn do_open(client: &mut ClientState, flags: OpenFlags, path_bytes: &[u8]) {
    // Check mounts first — forward Open and relay the file cap directly
    if let Some((mount_idx, rel_path)) = find_mount(path_bytes) {
        forward_open(mount_idx, client.ctl.as_ref().unwrap(), flags, rel_path);
        return;
    }

    let create = flags.bits & OpenFlags::CREATE.bits != 0;
    let truncate = flags.bits & OpenFlags::TRUNCATE.bits != 0;
    let excl = flags.bits & OpenFlags::EXCL.bits != 0;
    let append = flags.bits & OpenFlags::APPEND.bits != 0;

    let fs = fs();

    let inode_idx = match fs.resolve_path(path_bytes) {
        Some(idx) => {
            if excl && create {
                send_error(client.ctl.as_ref().unwrap(), FsError::AlreadyExists {});
                return;
            }
            if fs.inodes[idx].kind == InodeKind::Dir {
                send_error(client.ctl.as_ref().unwrap(), FsError::NotAFile {});
                return;
            }
            if truncate {
                fs.inodes[idx].data_len = 0;
            }
            idx
        }
        None => {
            if !create {
                send_error(client.ctl.as_ref().unwrap(), FsError::NotFound {});
                return;
            }
            // Ensure parent dirs exist (mkdir -p) and get the parent and filename
            let (parent_inode, filename) = match fs.ensure_parent_dirs(path_bytes) {
                Some(v) => v,
                None => {
                    send_error(client.ctl.as_ref().unwrap(), FsError::InvalidPath {});
                    return;
                }
            };

            if filename.len() > MAX_NAME_LEN {
                send_error(client.ctl.as_ref().unwrap(), FsError::InvalidPath {});
                return;
            }

            // Could already exist after ensure_parent_dirs
            if let Some(idx) = fs.inodes[parent_inode].find_child(filename) {
                if excl {
                    send_error(client.ctl.as_ref().unwrap(), FsError::AlreadyExists {});
                    return;
                }
                if fs.inodes[idx].kind == InodeKind::Dir {
                    send_error(client.ctl.as_ref().unwrap(), FsError::NotAFile {});
                    return;
                }
                if truncate {
                    fs.inodes[idx].data_len = 0;
                }
                idx
            } else {
                let new_inode = match fs.alloc_inode() {
                    Some(i) => i,
                    None => {
                        send_error(client.ctl.as_ref().unwrap(), FsError::Io {});
                        return;
                    }
                };
                fs.inodes[new_inode].init_file();
                if !fs.inodes[parent_inode].add_child(filename, new_inode) {
                    fs.inodes[new_inode].active = false;
                    send_error(client.ctl.as_ref().unwrap(), FsError::Io {});
                    return;
                }
                new_inode
            }
        }
    };

    // Close any existing file channel for this client first
    close_client_file(client);

    // Create channel pair for file I/O
    let (my_handle, client_file_handle) = raw::sys_chan_create();

    if !fs.register_open_file(my_handle, inode_idx, append) {
        raw::sys_chan_close(my_handle);
        raw::sys_chan_close(client_file_handle);
        send_error(client.ctl.as_ref().unwrap(), FsError::Io {});
        return;
    }

    // Send Opened with the file handle as capability
    let _ = client.ctl.as_ref().unwrap().send(&FsResponse::Opened {
        kind: FsEntryKind::File {},
        size: 0,
        file: rvos_wire::RawChannelCap::new(client_file_handle),
    });
    // Close our local handle for the client's file endpoint. The channel
    // stays alive because the client still holds a reference (ref counting
    // was incremented when the capability was sent via IPC).
    raw::sys_chan_close(client_file_handle);

    // Store typed file channel in client state
    client.file_ch = Some(Channel::from_raw_handle(my_handle));
    client.file_inode = inode_idx;
}

fn do_delete(ch: &Channel<FsResponse, FsRequestMsg>, path_bytes: &[u8]) {
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    if path_bytes == b"/" {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    // Check mounts first
    if let Some((mount_idx, rel_path)) = find_mount(path_bytes) {
        forward_delete(mount_idx, ch, rel_path);
        return;
    }

    let fs = fs();

    let (parent_inode, filename) = match fs.resolve_parent(path_bytes) {
        Some(v) => v,
        None => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };

    let target_inode = match fs.inodes[parent_inode].find_child(filename) {
        Some(idx) => idx,
        None => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };

    if fs.inodes[target_inode].kind == InodeKind::Dir && fs.inodes[target_inode].child_count > 0 {
        send_error(ch, FsError::NotEmpty {});
        return;
    }

    fs.inodes[parent_inode].remove_child(filename);

    let has_open_ref = fs.open_files.iter().any(|of| of.active && of.inode == target_inode);
    if !has_open_ref {
        fs.inodes[target_inode].active = false;
    }

    send_stat_ok(ch, FsEntryKind::File {}, 0);
}

fn do_mkdir(ch: &Channel<FsResponse, FsRequestMsg>, path_bytes: &[u8]) {
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(ch, FsError::InvalidPath {});
        return;
    }

    if path_bytes == b"/" {
        send_error(ch, FsError::AlreadyExists {});
        return;
    }

    // Check mounts first
    if let Some((mount_idx, rel_path)) = find_mount(path_bytes) {
        forward_mkdir(mount_idx, ch, rel_path);
        return;
    }

    let fs = fs();

    // Check if it already exists
    if fs.resolve_path(path_bytes).is_some() {
        send_error(ch, FsError::AlreadyExists {});
        return;
    }

    let (parent_inode, dirname) = match fs.resolve_parent(path_bytes) {
        Some(v) => v,
        None => {
            send_error(ch, FsError::NotFound {});
            return;
        }
    };

    if fs.inodes[parent_inode].kind != InodeKind::Dir {
        send_error(ch, FsError::NotFound {});
        return;
    }

    let new_inode = match fs.alloc_inode() {
        Some(i) => i,
        None => {
            send_error(ch, FsError::NoSpace {});
            return;
        }
    };

    fs.inodes[new_inode].init_dir();
    if !fs.inodes[parent_inode].add_child(dirname, new_inode) {
        fs.inodes[new_inode].active = false;
        send_error(ch, FsError::NoSpace {});
        return;
    }

    send_stat_ok(ch, FsEntryKind::Directory {}, 0);
}
