extern crate rvos_rt;

use rvos::raw::{self, NO_CAP};
use rvos::Message;
use rvos::rvos_wire::{self};
use rvos_proto::fs::{
    FsRequest, FsResponse, FsEntryKind, FsError, OpenFlags,
    FileRequest, FileResponse, FileOffset, ReaddirResponse,
};

// --- Constants ---

const MAX_FILES: usize = 160;
const MAX_FILE_SIZE: usize = 4096;
const MAX_NAME_LEN: usize = 32;
const MAX_CHILDREN: usize = 128;
const MAX_OPEN_FILES: usize = 16;

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
    // Read-only static file backing (for files embedded via include_bytes!)
    read_only: bool,
    static_data: *const u8,
    static_data_len: usize,
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
            read_only: false,
            static_data: core::ptr::null(),
            static_data_len: 0,
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

struct Filesystem {
    inodes: [Inode; MAX_FILES],
    open_files: [OpenFile; MAX_OPEN_FILES],
    open_count: usize,
}

impl Filesystem {
    fn new() -> Self {
        let mut fs = Filesystem {
            inodes: [const { Inode::new_empty() }; MAX_FILES],
            open_files: [const { OpenFile { endpoint_handle: 0, inode: 0, active: false, append: false, position: 0 } }; MAX_OPEN_FILES],
            open_count: 0,
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

    /// Add a read-only file backed by static data (e.g. include_bytes!).
    /// Creates intermediate directories as needed (mkdir -p behavior).
    fn add_static_file(&mut self, path: &[u8], data: &'static [u8]) {
        let (parent_inode, filename) = self.ensure_parent_dirs(path)
            .expect("add_static_file: invalid path");
        let new_inode = self.alloc_inode().expect("add_static_file: no free inodes");
        self.inodes[new_inode].init_file();
        self.inodes[new_inode].read_only = true;
        self.inodes[new_inode].static_data = data.as_ptr();
        self.inodes[new_inode].static_data_len = data.len();
        self.inodes[new_inode].data_len = data.len();
        assert!(
            self.inodes[parent_inode].add_child(filename, new_inode),
            "add_static_file: failed to add child"
        );
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

// --- Message helpers ---

fn send_ok(handle: usize, cap: usize) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(
        &FsResponse::Ok { kind: FsEntryKind::File {}, size: 0 },
        &mut msg.data,
    ).unwrap_or(0);
    msg.caps[0] = cap;
    if cap != rvos::NO_CAP { msg.cap_count = 1; }
    raw::sys_chan_send_blocking(handle, &msg);
}

fn send_error(handle: usize, code: FsError) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FsResponse::Error { code }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

fn send_data_chunk(handle: usize, data: &[u8]) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FileResponse::Data { chunk: data }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_retry(handle, &msg);
}

fn send_data_sentinel(handle: usize) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FileResponse::Data { chunk: &[] }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_retry(handle, &msg);
}

fn send_write_ok(handle: usize, written: u32) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FileResponse::WriteOk { written }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

fn send_stat_ok(handle: usize, kind: FsEntryKind, size: u64) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FsResponse::Ok { kind, size }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
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

fn send_file_error(handle: usize, code: FsError) {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&FileResponse::Error { code }, &mut msg.data).unwrap_or(0);
    raw::sys_chan_send_blocking(handle, &msg);
}

// --- Main server ---

use core::cell::UnsafeCell;

struct FsCell(UnsafeCell<Option<Filesystem>>);
unsafe impl Sync for FsCell {}

static FS: FsCell = FsCell(UnsafeCell::new(None));

fn fs() -> &'static mut Filesystem {
    unsafe { (*FS.0.get()).as_mut().unwrap() }
}

fn handle_read(file_handle: usize, inode_idx: usize, offset: FileOffset, len: u32) {
    let explicit_offset = match offset {
        FileOffset::Explicit { offset } => Some(offset as usize),
        FileOffset::Stream {} => None,
    };

    let len = len as usize;

    let fs = fs();

    let offset = match explicit_offset {
        Some(off) => off,
        None => {
            // Stream mode: use server-tracked position
            match fs.get_open_file_mut(file_handle) {
                Some(of) => of.position,
                None => 0,
            }
        }
    };

    let inode = &fs.inodes[inode_idx];

    if offset >= inode.data_len {
        // At or past EOF - send sentinel immediately
        send_data_sentinel(file_handle);
        return;
    }

    let available = inode.data_len - offset;
    let to_send = if len < available { len } else { available };

    // Read from static data or mutable data buffer
    let data_slice: &[u8] = if inode.read_only {
        unsafe { core::slice::from_raw_parts(inode.static_data.add(offset), to_send) }
    } else {
        &inode.data[offset..offset + to_send]
    };

    let mut sent = 0;
    while sent < to_send {
        let chunk_end = if sent + MAX_DATA_CHUNK < to_send { sent + MAX_DATA_CHUNK } else { to_send };
        send_data_chunk(file_handle, &data_slice[sent..chunk_end]);
        sent = chunk_end;
    }

    // Send sentinel
    send_data_sentinel(file_handle);

    // Advance server-side position for stream mode
    if explicit_offset.is_none() {
        if let Some(of) = fs.get_open_file_mut(file_handle) {
            of.position = offset + to_send;
        }
    }
}

fn handle_write(file_handle: usize, inode_idx: usize, offset: FileOffset, data: &[u8]) {
    let explicit_offset = match offset {
        FileOffset::Explicit { offset } => Some(offset as usize),
        FileOffset::Stream {} => None,
    };

    let fs = fs();
    let is_append_mode = fs.is_append(file_handle);

    // Resolve offset: append > stream > explicit
    let offset = if is_append_mode {
        fs.inodes[inode_idx].data_len
    } else {
        match explicit_offset {
            Some(off) => off,
            None => {
                // Stream mode: use server-tracked position
                match fs.get_open_file_mut(file_handle) {
                    Some(of) => of.position,
                    None => 0,
                }
            }
        }
    };

    let inode = &mut fs.inodes[inode_idx];

    if inode.read_only {
        send_file_error(file_handle, FsError::Io {});
        return;
    }

    let end = offset + data.len();
    let written;
    if end > MAX_FILE_SIZE {
        // Truncate to max
        let can_write = MAX_FILE_SIZE.saturating_sub(offset);
        if can_write == 0 {
            send_file_error(file_handle, FsError::Io {});
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
        send_write_ok(file_handle, can_write as u32);
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
        send_write_ok(file_handle, data.len() as u32);
    }

    // Advance server-side position for stream mode
    if explicit_offset.is_none() {
        if let Some(of) = fs.get_open_file_mut(file_handle) {
            of.position = offset + written;
        }
    }
}

fn do_stat(client_handle: usize, path: &str) {
    let path_bytes = path.as_bytes();
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(client_handle, FsError::InvalidPath {});
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
            send_stat_ok(client_handle, kind, size);
        }
        None => {
            send_error(client_handle, FsError::NotFound {});
        }
    }
}

fn do_readdir(client_handle: usize, path: &str) {
    let path_bytes = path.as_bytes();
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(client_handle, FsError::InvalidPath {});
        return;
    }

    let fs = fs();
    let idx = match fs.resolve_path(path_bytes) {
        Some(i) => i,
        None => {
            send_error(client_handle, FsError::NotFound {});
            return;
        }
    };

    if fs.inodes[idx].kind != InodeKind::Dir {
        send_error(client_handle, FsError::NotAFile {});
        return;
    }

    // Send each child entry
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
            send_dir_entry(client_handle, kind, size, name);
        }
    }

    // Send sentinel
    send_dir_sentinel(client_handle);
}

static HELLO_STD_ELF: &[u8] = include_bytes!(
    "../../../user/hello/target/riscv64gc-unknown-rvos/release/hello"
);

static WINDOW_SERVER_ELF: &[u8] = include_bytes!(
    "../../../user/window-server/target/riscv64gc-unknown-rvos/release/window-server"
);

static WINCLIENT_ELF: &[u8] = include_bytes!(
    "../../../user/winclient/target/riscv64gc-unknown-rvos/release/winclient"
);

static IPC_TORTURE_ELF: &[u8] = include_bytes!(
    "../../../user/ipc-torture/target/riscv64gc-unknown-rvos/release/ipc-torture"
);

static FBCON_ELF: &[u8] = include_bytes!(
    "../../../user/fbcon/target/riscv64gc-unknown-rvos/release/fbcon"
);

static SHELL_ELF: &[u8] = include_bytes!(
    "../../../user/shell/target/riscv64gc-unknown-rvos/release/shell"
);

static BENCH_ELF: &[u8] = include_bytes!(
    "../../../user/bench/target/riscv64gc-unknown-rvos/release/bench"
);

static TRIANGLE_ELF: &[u8] = include_bytes!(
    "../../../user/triangle/target/riscv64gc-unknown-rvos/release/triangle"
);

static GUI_BENCH_ELF: &[u8] = include_bytes!(
    "../../../user/gui-bench/target/riscv64gc-unknown-rvos/release/gui-bench"
);

// --- Multiplexed client state ---

const MAX_CLIENTS: usize = 8;

struct ClientState {
    ctl_handle: usize,     // client's control channel handle
    file_handle: usize,    // 0 = no file open, otherwise handle to open file channel
    file_inode: usize,     // inode of the open file (valid when file_handle != 0)
    active: bool,
}

fn main() {
    // Initialize filesystem
    unsafe {
        *FS.0.get() = Some(Filesystem::new());
    }

    // Register read-only static files
    fs().add_static_file(b"/bin/hello-std", HELLO_STD_ELF);
    fs().add_static_file(b"/bin/window-server", WINDOW_SERVER_ELF);
    fs().add_static_file(b"/bin/winclient", WINCLIENT_ELF);
    fs().add_static_file(b"/bin/ipc-torture", IPC_TORTURE_ELF);
    fs().add_static_file(b"/bin/fbcon", FBCON_ELF);
    fs().add_static_file(b"/bin/shell", SHELL_ELF);
    fs().add_static_file(b"/bin/bench", BENCH_ELF);
    fs().add_static_file(b"/bin/triangle", TRIANGLE_ELF);
    fs().add_static_file(b"/bin/gui-bench", GUI_BENCH_ELF);

    // The fs server has:
    // Handle 0: boot channel (for requesting stdio from init)
    // Handle 1: fs control channel (receives new client endpoints from init)

    let mut clients: [ClientState; MAX_CLIENTS] = [const { ClientState {
        ctl_handle: 0, file_handle: 0, file_inode: 0, active: false,
    } }; MAX_CLIENTS];

    // Multiplexed event loop: poll control channel + all active client channels
    loop {
        let mut handled = false;

        // Accept new clients from control channel (non-blocking)
        loop {
            let mut msg = Message::new();
            let ret = raw::sys_chan_recv(CONTROL_HANDLE, &mut msg);
            if ret != 0 { break; }
            handled = true;
            let cap = if msg.cap_count > 0 { msg.caps[0] } else { rvos::NO_CAP };
            if cap != NO_CAP {
                // Find a free client slot (or reclaim an inactive one)
                let slot = clients.iter_mut().find(|c| !c.active);
                if let Some(slot) = slot {
                    *slot = ClientState {
                        ctl_handle: cap,
                        file_handle: 0,
                        file_inode: 0,
                        active: true,
                    };
                } else {
                    // No free slots — close the endpoint
                    raw::sys_chan_close(cap);
                }
            }
        }

        // Poll each active client
        for client in clients.iter_mut() {
            if !client.active { continue; }

            // If a file channel is open, poll it
            if client.file_handle != 0 {
                let mut msg = Message::new();
                let ret = raw::sys_chan_recv(client.file_handle, &mut msg);
                if ret == 0 {
                    handled = true;
                    if msg.len == 0 {
                        close_client_file(client);
                    } else {
                        let fh = client.file_handle;
                        let inode = client.file_inode;
                        match rvos_wire::from_bytes::<FileRequest>(&msg.data[..msg.len]) {
                            Ok(FileRequest::Read { offset, len }) => {
                                handle_read(fh, inode, offset, len);
                            }
                            Ok(FileRequest::Write { offset, data }) => {
                                handle_write(fh, inode, offset, data);
                            }
                            Ok(FileRequest::Ioctl { .. }) => {
                                send_file_error(fh, FsError::Io {});
                            }
                            Err(_) => {
                                send_file_error(fh, FsError::Io {});
                            }
                        }
                    }
                } else if ret == 2 {
                    // Channel closed by peer
                    close_client_file(client);
                    // If control channel is also gone, fully clean up
                    if client.ctl_handle == 0 {
                        client.active = false;
                    }
                }
            }

            // Poll client control channel (skip if already disconnected)
            if client.ctl_handle != 0 {
                let mut msg = Message::new();
                let ret = raw::sys_chan_recv(client.ctl_handle, &mut msg);
                if ret == 0 {
                    handled = true;
                    if msg.len == 0 {
                        close_client_full(client);
                    } else {
                        handle_ctl_msg(client, &msg);
                    }
                } else if ret == 2 {
                    // Client disconnected
                    close_client_full(client);
                }
            }
        }

        if !handled {
            // Register interest on all active channels, then block until
            // any of them receives a message. This eliminates busy-wait
            // polling (sys_yield) and lets the scheduler skip us entirely
            // when there's nothing to do.
            raw::sys_chan_poll_add(CONTROL_HANDLE);
            for client in clients.iter() {
                if !client.active { continue; }
                if client.ctl_handle != 0 {
                    raw::sys_chan_poll_add(client.ctl_handle);
                }
                if client.file_handle != 0 {
                    raw::sys_chan_poll_add(client.file_handle);
                }
            }
            raw::sys_block();
        }
    }
}

fn close_client_file(client: &mut ClientState) {
    if client.file_handle != 0 {
        fs().close_open_file(client.file_handle);
        raw::sys_chan_close(client.file_handle);
        client.file_handle = 0;
        client.file_inode = 0;
    }
}

fn close_client_full(client: &mut ClientState) {
    raw::sys_chan_close(client.ctl_handle);
    client.ctl_handle = 0;
    if client.file_handle == 0 {
        // No open file — fully clean up
        client.active = false;
    }
    // If a file handle is still open, keep client active to serve file I/O.
    // The client will be fully cleaned up when the file channel also closes.
}

fn handle_ctl_msg(client: &mut ClientState, msg: &Message) {
    match rvos_wire::from_bytes::<FsRequest>(&msg.data[..msg.len]) {
        Ok(FsRequest::Open { flags, path }) => {
            let path_bytes = path.as_bytes();
            if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
                send_error(client.ctl_handle, FsError::InvalidPath {});
                return;
            }
            do_open(client, flags, path_bytes);
        }
        Ok(FsRequest::Delete { path }) => {
            do_delete(client.ctl_handle, path.as_bytes());
        }
        Ok(FsRequest::Stat { path }) => {
            do_stat(client.ctl_handle, path);
        }
        Ok(FsRequest::Readdir { path }) => {
            do_readdir(client.ctl_handle, path);
        }
        Err(_) => {
            send_error(client.ctl_handle, FsError::Io {});
        }
    }
}

fn do_open(client: &mut ClientState, flags: OpenFlags, path_bytes: &[u8]) {
    let create = flags.bits & OpenFlags::CREATE.bits != 0;
    let truncate = flags.bits & OpenFlags::TRUNCATE.bits != 0;
    let excl = flags.bits & OpenFlags::EXCL.bits != 0;
    let append = flags.bits & OpenFlags::APPEND.bits != 0;

    let client_handle = client.ctl_handle;
    let fs = fs();

    let inode_idx = match fs.resolve_path(path_bytes) {
        Some(idx) => {
            if excl && create {
                send_error(client_handle, FsError::AlreadyExists {});
                return;
            }
            if fs.inodes[idx].kind == InodeKind::Dir {
                send_error(client_handle, FsError::NotAFile {});
                return;
            }
            if truncate && fs.inodes[idx].read_only {
                send_error(client_handle, FsError::Io {});
                return;
            }
            if truncate {
                fs.inodes[idx].data_len = 0;
            }
            idx
        }
        None => {
            if !create {
                send_error(client_handle, FsError::NotFound {});
                return;
            }
            // Ensure parent dirs exist (mkdir -p) and get the parent and filename
            let (parent_inode, filename) = match fs.ensure_parent_dirs(path_bytes) {
                Some(v) => v,
                None => {
                    send_error(client_handle, FsError::InvalidPath {});
                    return;
                }
            };

            if filename.len() > MAX_NAME_LEN {
                send_error(client_handle, FsError::InvalidPath {});
                return;
            }

            // Could already exist after ensure_parent_dirs
            if let Some(idx) = fs.inodes[parent_inode].find_child(filename) {
                if excl {
                    send_error(client_handle, FsError::AlreadyExists {});
                    return;
                }
                if fs.inodes[idx].kind == InodeKind::Dir {
                    send_error(client_handle, FsError::NotAFile {});
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
                        send_error(client_handle, FsError::Io {});
                        return;
                    }
                };
                fs.inodes[new_inode].init_file();
                if !fs.inodes[parent_inode].add_child(filename, new_inode) {
                    fs.inodes[new_inode].active = false;
                    send_error(client_handle, FsError::Io {});
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
        send_error(client_handle, FsError::Io {});
        return;
    }

    // Send Ok with the file handle as capability
    send_ok(client_handle, client_file_handle);
    // Close our local handle for the client's file endpoint. The channel
    // stays alive because the client still holds a reference (ref counting
    // was incremented when the capability was sent via IPC).
    raw::sys_chan_close(client_file_handle);

    // Store file channel in client state for multiplexed serving
    client.file_handle = my_handle;
    client.file_inode = inode_idx;
}

fn do_delete(client_handle: usize, path_bytes: &[u8]) {
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(client_handle, FsError::InvalidPath {});
        return;
    }

    if path_bytes == b"/" {
        send_error(client_handle, FsError::InvalidPath {});
        return;
    }

    let fs = fs();

    let (parent_inode, filename) = match fs.resolve_parent(path_bytes) {
        Some(v) => v,
        None => {
            send_error(client_handle, FsError::NotFound {});
            return;
        }
    };

    let target_inode = match fs.inodes[parent_inode].find_child(filename) {
        Some(idx) => idx,
        None => {
            send_error(client_handle, FsError::NotFound {});
            return;
        }
    };

    if fs.inodes[target_inode].kind == InodeKind::Dir && fs.inodes[target_inode].child_count > 0 {
        send_error(client_handle, FsError::NotEmpty {});
        return;
    }

    if fs.inodes[target_inode].read_only {
        send_error(client_handle, FsError::Io {});
        return;
    }

    fs.inodes[parent_inode].remove_child(filename);

    let has_open_ref = fs.open_files.iter().any(|of| of.active && of.inode == target_inode);
    if !has_open_ref {
        fs.inodes[target_inode].active = false;
    }

    send_stat_ok(client_handle, FsEntryKind::File {}, 0);
}
