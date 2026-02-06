extern crate rvos_rt;

mod syscall;

use syscall::{Message, NO_CAP};
use rvos_wire::{Reader, Writer};

// --- Constants ---

const MAX_FILES: usize = 32;
const MAX_FILE_SIZE: usize = 4096;
const MAX_NAME_LEN: usize = 32;
const MAX_CHILDREN: usize = 16;
const MAX_OPEN_FILES: usize = 16;

// Open flags
const FLAG_CREATE: u8 = 0x01;
const FLAG_TRUNCATE: u8 = 0x02;
const FLAG_EXCL: u8 = 0x04;

// Error codes
const ERR_NOT_FOUND: u8 = 1;
const ERR_ALREADY_EXISTS: u8 = 2;
const ERR_NOT_A_FILE: u8 = 3;
const ERR_NOT_EMPTY: u8 = 4;
const ERR_INVALID_PATH: u8 = 5;
// const ERR_NO_SPACE: u8 = 6;
const ERR_IO: u8 = 7;

// Max data payload per chunk (64 - 1 tag - 2 length prefix = 61)
const MAX_DATA_CHUNK: usize = 61;

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
            open_files: [const { OpenFile { endpoint_handle: 0, inode: 0, active: false } }; MAX_OPEN_FILES],
            open_count: 0,
        };
        // Inode 0 is the root directory
        fs.inodes[0].init_dir();
        fs
    }

    fn alloc_inode(&mut self) -> Option<usize> {
        for i in 1..MAX_FILES {
            if !self.inodes[i].active {
                return Some(i);
            }
        }
        None
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
        for i in 0..path.len() {
            if path[i] == b'/' {
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
                    if i > start {
                        if comp_count < 16 {
                            components[comp_count] = (&path[start..i], start, i);
                            comp_count += 1;
                        }
                    }
                    start = i + 1;
                }
            }
            if start < path.len() {
                if comp_count < 16 {
                    components[comp_count] = (&path[start..], start, path.len());
                    comp_count += 1;
                }
            }
        }

        if comp_count == 0 {
            return None;
        }

        let filename = components[comp_count - 1].0;

        // Create directories for all but the last component
        let mut current = 0usize; // root
        for i in 0..comp_count - 1 {
            let name = components[i].0;
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

    fn register_open_file(&mut self, endpoint_handle: usize, inode: usize) -> bool {
        for i in 0..MAX_OPEN_FILES {
            if !self.open_files[i].active {
                self.open_files[i] = OpenFile { endpoint_handle, inode, active: true };
                self.open_count += 1;
                return true;
            }
        }
        false
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
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(0); // tag: Ok
    msg.len = w.position();
    msg.cap = cap;
    syscall::sys_chan_send(handle, &msg);
}

fn send_error(handle: usize, code: u8) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(1); // tag: Error
    let _ = w.write_u8(code);
    msg.len = w.position();
    syscall::sys_chan_send(handle, &msg);
}

fn send_data_chunk(handle: usize, data: &[u8]) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(0); // tag: Data
    let _ = w.write_bytes(data);
    msg.len = w.position();
    syscall::sys_chan_send(handle, &msg);
}

fn send_data_sentinel(handle: usize) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(0); // tag: Data
    let _ = w.write_u16(0); // zero-length payload
    msg.len = w.position();
    syscall::sys_chan_send(handle, &msg);
}

fn send_write_ok(handle: usize, written: u32) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(1); // tag: Ok
    let _ = w.write_u32(written);
    msg.len = w.position();
    syscall::sys_chan_send(handle, &msg);
}

fn send_file_error(handle: usize, code: u8) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(2); // tag: Error
    let _ = w.write_u8(code);
    msg.len = w.position();
    syscall::sys_chan_send(handle, &msg);
}

// --- Main server ---

use core::cell::UnsafeCell;

struct FsCell(UnsafeCell<Option<Filesystem>>);
unsafe impl Sync for FsCell {}

static FS: FsCell = FsCell(UnsafeCell::new(None));

fn fs() -> &'static mut Filesystem {
    unsafe { (*FS.0.get()).as_mut().unwrap() }
}

fn handle_read(file_handle: usize, inode_idx: usize, r: &mut Reader) {
    let offset = match r.read_u64() {
        Ok(v) => v as usize,
        Err(_) => {
            send_file_error(file_handle, ERR_IO);
            return;
        }
    };

    let len = match r.read_u32() {
        Ok(v) => v as usize,
        Err(_) => {
            send_file_error(file_handle, ERR_IO);
            return;
        }
    };

    let fs = fs();
    let inode = &fs.inodes[inode_idx];

    if offset >= inode.data_len {
        // At or past EOF - send sentinel immediately
        send_data_sentinel(file_handle);
        return;
    }

    let available = inode.data_len - offset;
    let to_send = if len < available { len } else { available };
    let data = &inode.data[offset..offset + to_send];

    let mut sent = 0;
    while sent < to_send {
        let chunk_end = if sent + MAX_DATA_CHUNK < to_send { sent + MAX_DATA_CHUNK } else { to_send };
        send_data_chunk(file_handle, &data[sent..chunk_end]);
        sent = chunk_end;
    }

    // Send sentinel
    send_data_sentinel(file_handle);
}

fn handle_write(file_handle: usize, inode_idx: usize, r: &mut Reader) {
    let offset = match r.read_u64() {
        Ok(v) => v as usize,
        Err(_) => {
            send_file_error(file_handle, ERR_IO);
            return;
        }
    };

    let data = match r.read_bytes() {
        Ok(d) => d,
        Err(_) => {
            send_file_error(file_handle, ERR_IO);
            return;
        }
    };

    let fs = fs();
    let inode = &mut fs.inodes[inode_idx];

    let end = offset + data.len();
    if end > MAX_FILE_SIZE {
        // Truncate to max
        let can_write = if offset < MAX_FILE_SIZE { MAX_FILE_SIZE - offset } else { 0 };
        if can_write == 0 {
            send_file_error(file_handle, ERR_IO);
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
        send_write_ok(file_handle, data.len() as u32);
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

    // Main event loop: poll control channel and all open file channels
    loop {
        let mut handled = false;

        // Check control channel for new client requests
        {
            let mut msg = Message::new();
            // Try non-blocking recv on control channel first
            // Since we don't have non-blocking recv in user mode, we need a different approach.
            // The fs server's design: block waiting for ANY message.
            // We'll prioritize the control channel, then serve file requests.
            //
            // Simple approach: serve one control request, then serve all pending file requests,
            // then block on control channel again.
            //
            // But we need to also respond to file channel messages while waiting.
            // Since we can only block on one channel at a time, we'll poll:
            // 1. Block on control channel
            // 2. When woken, handle control request
            // 3. Serve file requests round-robin (non-blocking would be ideal but we only have blocking)
            //
            // Actually, the simplest correct approach for now:
            // We block on the control channel. When a new client comes in, we handle its
            // Open request and create a file channel. Then we serve that file channel
            // until the client closes it, then go back to control channel.
            //
            // But this is sequential - only one client at a time. That's OK for a simple tmpfs.
            // The sysinfo and math services also work this way.

            // Wait for a new client endpoint from init
            syscall::sys_chan_recv_blocking(CONTROL_HANDLE, &mut msg);

            if msg.cap != NO_CAP {
                let client_ctl_handle = msg.cap;
                // Serve this client until they disconnect
                serve_client(client_ctl_handle);
                handled = true;
            }
        }

        if !handled {
            // Nothing to do, will block on next recv
        }
    }
}

fn serve_client(client_handle: usize) {
    // Serve control channel requests from this client
    // The client can send multiple Open/Delete requests on the same control channel
    // For each Open, we also need to serve the resulting file channel

    // We'll handle requests in a loop. For each Open, we serve the file channel
    // until it closes, then return to waiting on the control channel.
    loop {
        let mut msg = Message::new();
        syscall::sys_chan_recv_blocking(client_handle, &mut msg);

        if msg.len == 0 {
            // Client probably closed the control channel
            break;
        }

        let mut r = Reader::new(&msg.data[..msg.len]);
        let tag = match r.read_u8() {
            Ok(t) => t,
            Err(_) => {
                send_error(client_handle, ERR_IO);
                continue;
            }
        };

        match tag {
            0 => {
                // Open - handle it and then serve the file channel
                let flags = match r.read_u8() {
                    Ok(f) => f,
                    Err(_) => {
                        send_error(client_handle, ERR_IO);
                        continue;
                    }
                };

                let path = match r.read_str() {
                    Ok(p) => p,
                    Err(_) => {
                        send_error(client_handle, ERR_INVALID_PATH);
                        continue;
                    }
                };

                let path_bytes = path.as_bytes();

                if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
                    send_error(client_handle, ERR_INVALID_PATH);
                    continue;
                }

                do_open(client_handle, flags, path_bytes);
            }
            1 => {
                // Delete
                let path = match r.read_str() {
                    Ok(p) => p,
                    Err(_) => {
                        send_error(client_handle, ERR_INVALID_PATH);
                        continue;
                    }
                };
                do_delete(client_handle, path.as_bytes());
            }
            _ => {
                send_error(client_handle, ERR_IO);
            }
        }
    }
}

fn do_open(client_handle: usize, flags: u8, path_bytes: &[u8]) {
    let create = flags & FLAG_CREATE != 0;
    let truncate = flags & FLAG_TRUNCATE != 0;
    let excl = flags & FLAG_EXCL != 0;

    let fs = fs();

    let inode_idx = match fs.resolve_path(path_bytes) {
        Some(idx) => {
            if excl && create {
                send_error(client_handle, ERR_ALREADY_EXISTS);
                return;
            }
            if fs.inodes[idx].kind == InodeKind::Dir {
                send_error(client_handle, ERR_NOT_A_FILE);
                return;
            }
            if truncate {
                fs.inodes[idx].data_len = 0;
            }
            idx
        }
        None => {
            if !create {
                send_error(client_handle, ERR_NOT_FOUND);
                return;
            }
            // Ensure parent dirs exist (mkdir -p) and get the parent and filename
            let (parent_inode, filename) = match fs.ensure_parent_dirs(path_bytes) {
                Some(v) => v,
                None => {
                    send_error(client_handle, ERR_INVALID_PATH);
                    return;
                }
            };

            if filename.len() > MAX_NAME_LEN {
                send_error(client_handle, ERR_INVALID_PATH);
                return;
            }

            // Could already exist after ensure_parent_dirs
            if let Some(idx) = fs.inodes[parent_inode].find_child(filename) {
                if excl {
                    send_error(client_handle, ERR_ALREADY_EXISTS);
                    return;
                }
                if fs.inodes[idx].kind == InodeKind::Dir {
                    send_error(client_handle, ERR_NOT_A_FILE);
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
                        send_error(client_handle, ERR_IO);
                        return;
                    }
                };
                fs.inodes[new_inode].init_file();
                if !fs.inodes[parent_inode].add_child(filename, new_inode) {
                    fs.inodes[new_inode].active = false;
                    send_error(client_handle, ERR_IO);
                    return;
                }
                new_inode
            }
        }
    };

    // Create channel pair for file I/O
    let (my_handle, client_file_handle) = syscall::sys_chan_create();

    if !fs.register_open_file(my_handle, inode_idx) {
        syscall::sys_chan_close(my_handle);
        syscall::sys_chan_close(client_file_handle);
        send_error(client_handle, ERR_IO);
        return;
    }

    // Send Ok with the file handle as capability
    send_ok(client_handle, client_file_handle);

    // Now serve this file channel until the client closes it
    serve_file_channel(my_handle, inode_idx);

    // Clean up
    fs.close_open_file(my_handle);
    syscall::sys_chan_close(my_handle);
}

fn serve_file_channel(file_handle: usize, inode_idx: usize) {
    loop {
        let mut msg = Message::new();
        syscall::sys_chan_recv_blocking(file_handle, &mut msg);

        // If recv returns with len=0, the channel may be closed
        if msg.len == 0 {
            break;
        }

        let mut r = Reader::new(&msg.data[..msg.len]);
        let tag = match r.read_u8() {
            Ok(t) => t,
            Err(_) => {
                send_file_error(file_handle, ERR_IO);
                continue;
            }
        };

        match tag {
            0 => handle_read(file_handle, inode_idx, &mut r),
            1 => handle_write(file_handle, inode_idx, &mut r),
            _ => send_file_error(file_handle, ERR_IO),
        }
    }
}

fn do_delete(client_handle: usize, path_bytes: &[u8]) {
    if path_bytes.is_empty() || path_bytes[0] != b'/' || path_bytes.len() > 60 {
        send_error(client_handle, ERR_INVALID_PATH);
        return;
    }

    if path_bytes == b"/" {
        send_error(client_handle, ERR_INVALID_PATH);
        return;
    }

    let fs = fs();

    let (parent_inode, filename) = match fs.resolve_parent(path_bytes) {
        Some(v) => v,
        None => {
            send_error(client_handle, ERR_NOT_FOUND);
            return;
        }
    };

    let target_inode = match fs.inodes[parent_inode].find_child(filename) {
        Some(idx) => idx,
        None => {
            send_error(client_handle, ERR_NOT_FOUND);
            return;
        }
    };

    if fs.inodes[target_inode].kind == InodeKind::Dir && fs.inodes[target_inode].child_count > 0 {
        send_error(client_handle, ERR_NOT_EMPTY);
        return;
    }

    fs.inodes[parent_inode].remove_child(filename);

    let has_open_ref = fs.open_files.iter().any(|of| of.active && of.inode == target_inode);
    if !has_open_ref {
        fs.inodes[target_inode].active = false;
    }

    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(0); // Ok
    msg.len = w.position();
    msg.cap = NO_CAP;
    syscall::sys_chan_send(client_handle, &msg);
}
