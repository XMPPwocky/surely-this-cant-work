use alloc::vec::Vec;
use crate::ipc::{self, Message, NO_CAP};
use crate::sync::SpinLock;
use crate::mm::heap::{InitAlloc, INIT_ALLOC};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Console type for routing stdio requests
#[derive(Clone, Copy, PartialEq)]
pub enum ConsoleType {
    Serial,
    Framebuffer,
}

/// A boot channel registration: the init server's end of a user process's boot channel.
struct BootRegistration {
    boot_ep_b: usize,        // init server's endpoint of the boot channel
    console_type: ConsoleType, // which console this process should use
    is_shell: bool,           // true = primary stdin recipient
}

/// A service registration: maps a name to a console control endpoint.
struct ServiceEntry {
    console_type: ConsoleType,
    control_ep: usize, // endpoint to the console server's control channel
}

const MAX_BOOT_REGS: usize = 16;
const MAX_CONSOLE_SERVICES: usize = 4;

/// Maximum number of named services (sysinfo, math, fs, compositor, etc.)
const MAX_NAMED_SERVICES: usize = 8;
const SERVICE_NAME_LEN: usize = 16;

/// A named service with an atomic control endpoint.
/// The name is matched against incoming service discovery requests.
/// Name fields use UnsafeCell because they are written during boot and read after.
struct NamedService {
    name: UnsafeCell<[u8; SERVICE_NAME_LEN]>,
    name_len: AtomicUsize,
    control_ep: AtomicUsize, // usize::MAX = not yet registered
}

// SAFETY: NamedService fields are only written during single-threaded boot,
// then read (immutably) by init_server after boot. AtomicUsize provides the
// necessary synchronization for name_len and control_ep.
unsafe impl Sync for NamedService {}

impl NamedService {
    const fn empty() -> Self {
        NamedService {
            name: UnsafeCell::new([0u8; SERVICE_NAME_LEN]),
            name_len: AtomicUsize::new(0),
            control_ep: AtomicUsize::new(usize::MAX),
        }
    }
}

static NAMED_SERVICES: [NamedService; MAX_NAMED_SERVICES] = [const { NamedService::empty() }; MAX_NAMED_SERVICES];
static NAMED_SERVICE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Register a named service's control endpoint (called from kmain before spawning init).
/// The name is matched against incoming boot-channel requests from user processes.
///
/// SAFETY: Must only be called during single-threaded boot (before init_server runs).
/// This writes to the name fields without a lock, relying on the fact that the init
/// server has not started yet.
pub fn register_service(name: &str, control_ep: usize) {
    let idx = NAMED_SERVICE_COUNT.fetch_add(1, Ordering::Relaxed);
    assert!(idx < MAX_NAMED_SERVICES, "Too many named services");
    let svc = &NAMED_SERVICES[idx];
    let bytes = name.as_bytes();
    let len = bytes.len().min(SERVICE_NAME_LEN);
    // SAFETY: called during single-threaded boot before init_server starts.
    // The name field is only written here and read later by init_server.
    unsafe {
        let name_ptr = svc.name.get() as *mut u8;
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), name_ptr, len);
    }
    svc.name_len.store(len, Ordering::Relaxed);
    svc.control_ep.store(control_ep, Ordering::Relaxed);
}

// Legacy compatibility wrappers — kmain calls these; they now delegate to register_service.
pub fn set_sysinfo_control_ep(ep: usize) { register_service("sysinfo", ep); }
pub fn set_math_control_ep(ep: usize) { register_service("math", ep); }
pub fn set_fs_control_ep(ep: usize) { register_service("fs", ep); }

struct InitConfig {
    boot_regs: [Option<BootRegistration>; MAX_BOOT_REGS],
    services: [Option<ServiceEntry>; MAX_CONSOLE_SERVICES],
}

impl InitConfig {
    const fn new() -> Self {
        InitConfig {
            boot_regs: [const { None }; MAX_BOOT_REGS],
            services: [const { None }; MAX_CONSOLE_SERVICES],
        }
    }
}

static INIT_CONFIG: SpinLock<InitConfig> = SpinLock::new(InitConfig::new());

/// Register a boot channel for a user process (called from kmain before spawning init).
/// If `is_shell` is true, the console server will direct keyboard input to this client.
pub fn register_boot(boot_ep_b: usize, console_type: ConsoleType, is_shell: bool) {
    let mut config = INIT_CONFIG.lock();
    for slot in config.boot_regs.iter_mut() {
        if slot.is_none() {
            *slot = Some(BootRegistration { boot_ep_b, console_type, is_shell });
            return;
        }
    }
    panic!("Too many boot registrations");
}

/// Register a console service endpoint (called from kmain before spawning init).
pub fn register_console(console_type: ConsoleType, control_ep: usize) {
    let mut config = INIT_CONFIG.lock();
    for slot in config.services.iter_mut() {
        if slot.is_none() {
            *slot = Some(ServiceEntry { console_type, control_ep });
            return;
        }
    }
    panic!("Too many service registrations");
}

/// Whether a GPU is present (set by kmain before init starts).
static GPU_PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Called by kmain to tell the init server whether a GPU is available.
pub fn set_gpu_present(present: bool) {
    GPU_PRESENT.store(present, core::sync::atomic::Ordering::Relaxed);
}

/// State machine for loading a program from the filesystem.
#[derive(Clone, Copy, PartialEq)]
enum FsLaunchState {
    /// Waiting for Stat response on ctl_ep
    WaitStat,
    /// Waiting for Open response on ctl_ep
    WaitOpen,
    /// Waiting for Read data on file_ep
    WaitRead,
    /// Done (success or failure)
    Done,
}

/// Tracks an in-progress fs-based program launch.
struct FsLaunchCtx {
    state: FsLaunchState,
    ctl_ep: usize,
    file_ep: usize,
    file_size: usize,
    data: Vec<u8, InitAlloc>,
    path: &'static [u8],
    name: &'static str,
    console_type: ConsoleType,
    /// If set, register this as a named service and give it a control channel as handle 1.
    service_name: Option<&'static str>,
}

const MAX_FS_LAUNCHES: usize = 8;

/// Init server kernel task.
/// Polls boot channel endpoints for service discovery requests from user processes,
/// and concurrently loads programs from the filesystem.
pub fn init_server() {
    let my_pid = crate::task::current_pid();
    // Set up fs launch state machines (non-blocking)
    let mut fs_launches: [Option<FsLaunchCtx>; MAX_FS_LAUNCHES] = [const { None }; MAX_FS_LAUNCHES];
    init_fs_launches(&mut fs_launches, my_pid);

    loop {
        // Snapshot boot registrations under the lock
        let mut endpoints = [(0usize, ConsoleType::Serial, false); MAX_BOOT_REGS];
        let mut count = 0;
        {
            let config = INIT_CONFIG.lock();
            for i in 0..MAX_BOOT_REGS {
                if let Some(ref reg) = config.boot_regs[i] {
                    endpoints[count] = (reg.boot_ep_b, reg.console_type, reg.is_shell);
                    count += 1;
                }
            }
        }

        // Poll all boot endpoints without holding the lock
        let mut handled = false;
        for i in 0..count {
            let (boot_ep_b, console_type, is_shell) = endpoints[i];
            let (msg, send_wake) = ipc::channel_recv(boot_ep_b);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(msg) = msg {
                handle_request(boot_ep_b, console_type, is_shell, &msg, my_pid);
                handled = true;
            }
        }

        // Poll fs launch endpoints
        for slot in fs_launches.iter_mut() {
            if let Some(ref mut ctx) = slot {
                if poll_fs_launch(ctx, my_pid) {
                    handled = true;
                }
                if ctx.state == FsLaunchState::Done {
                    *slot = None;
                }
            }
        }

        if !handled {
            // Register as blocked on ALL boot endpoints and fs launch endpoints
            for i in 0..count {
                ipc::channel_set_blocked(endpoints[i].0, my_pid);
            }
            for slot in fs_launches.iter() {
                if let Some(ref ctx) = slot {
                    let ep = match ctx.state {
                        FsLaunchState::WaitStat | FsLaunchState::WaitOpen => ctx.ctl_ep,
                        FsLaunchState::WaitRead => ctx.file_ep,
                        FsLaunchState::Done => continue,
                    };
                    ipc::channel_set_blocked(ep, my_pid);
                }
            }
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}

fn handle_request(boot_ep_b: usize, console_type: ConsoleType, is_shell: bool, msg: &Message, my_pid: usize) {
    crate::trace::trace_kernel(b"init-handle_req-enter");
    let request = &msg.data[..msg.len];

    if starts_with(request, b"stdio") {
        handle_stdio_request(boot_ep_b, console_type, is_shell, my_pid);
    } else if let Some(svc) = find_named_service(request) {
        handle_service_request(boot_ep_b, svc, my_pid);
    } else {
        // Unknown request - send error response
        let mut resp = Message::new();
        let err = b"unknown";
        resp.data[..err.len()].copy_from_slice(err);
        resp.len = err.len();
        resp.sender_pid = my_pid;
        send_and_wake(boot_ep_b, resp);
    }
    crate::trace::trace_kernel(b"init-handle_req-exit");
}

/// Find a named service whose name matches the request prefix.
fn find_named_service(request: &[u8]) -> Option<&'static NamedService> {
    let count = NAMED_SERVICE_COUNT.load(Ordering::Relaxed);
    for i in 0..count {
        let svc = &NAMED_SERVICES[i];
        let nlen = svc.name_len.load(Ordering::Relaxed);
        if nlen > 0 {
            // SAFETY: name was written during boot before init_server started.
            // After boot, it is only read here. name_len acts as synchronization.
            let name_slice = unsafe { &(&*svc.name.get())[..nlen] };
            if starts_with(request, name_slice) {
                return Some(svc);
            }
        }
    }
    None
}

/// Generic handler for any named service (sysinfo, math, fs, etc.).
/// Creates a channel pair, sends the server endpoint to the service's control channel,
/// and responds to the client with the client endpoint.
fn handle_service_request(boot_ep_b: usize, svc: &NamedService, my_pid: usize) {
    let (client_ep, server_ep) = ipc::channel_create_pair();

    let ctl_ep = svc.control_ep.load(Ordering::Relaxed);
    if ctl_ep != usize::MAX {
        // Send server endpoint to the service via its control channel
        let mut ctl_msg = Message::new();
        ctl_msg.cap = ipc::encode_cap_channel(server_ep);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(ctl_ep, ctl_msg);

        // Respond to client with client endpoint
        let mut resp = Message::new();
        resp.cap = ipc::encode_cap_channel(client_ep);
        resp.sender_pid = my_pid;
        let ok = b"ok";
        resp.data[..ok.len()].copy_from_slice(ok);
        resp.len = ok.len();
        send_and_wake(boot_ep_b, resp);
    }
}

fn handle_stdio_request(boot_ep_b: usize, console_type: ConsoleType, is_shell: bool, my_pid: usize) {
    // Create a new bidirectional channel for the client <-> console server
    let (client_ep, server_ep) = ipc::channel_create_pair();

    // Find the control endpoint for the appropriate console server
    let control_ep = {
        let config = INIT_CONFIG.lock();
        let mut found = None;
        for slot in config.services.iter() {
            if let Some(ref svc) = slot {
                if svc.console_type == console_type {
                    found = Some(svc.control_ep);
                    break;
                }
            }
        }
        found
    };

    if let Some(ctl_ep) = control_ep {
        // Send server endpoint to console server via its control channel.
        // data[0] = 1 means this client wants stdin (is a shell).
        let mut ctl_msg = Message::new();
        ctl_msg.cap = ipc::encode_cap_channel(server_ep);
        ctl_msg.data[0] = if is_shell { 1 } else { 0 };
        ctl_msg.len = 1;
        ctl_msg.sender_pid = my_pid;
        send_and_wake(ctl_ep, ctl_msg);

        // Respond to client with client endpoint as capability
        let mut resp = Message::new();
        resp.cap = ipc::encode_cap_channel(client_ep);
        resp.sender_pid = my_pid;
        let ok = b"ok";
        resp.data[..ok.len()].copy_from_slice(ok);
        resp.len = ok.len();
        send_and_wake(boot_ep_b, resp);
    }
}

/// Send a message and wake the receiver if one was blocked.
fn send_and_wake(endpoint: usize, msg: Message) {
    if let Ok(wake) = ipc::channel_send(endpoint, msg) {
        if wake != 0 {
            crate::task::wake_process(wake);
        }
    }
}

fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    &data[..prefix.len()] == prefix
}

// ============================================================
// Filesystem client: launch ELF binaries from the fs service
// ============================================================

/// Programs to launch from the filesystem at boot time.
/// (path, process name, console type, service_name, requires_gpu)
const FS_PROGRAMS: &[(&[u8], &str, ConsoleType, Option<&str>, bool)] = &[
    (b"/bin/hello-std", "hello-std", ConsoleType::Serial, None, false),
    (b"/bin/window-server", "window-srv", ConsoleType::Serial, Some("window"), true),
    (b"/bin/winclient", "winclient", ConsoleType::Serial, None, true),
];

/// Initialize fs launch state machines. For each program, create a client
/// connection to the fs server and send the initial Stat request (non-blocking).
fn init_fs_launches(launches: &mut [Option<FsLaunchCtx>; MAX_FS_LAUNCHES], my_pid: usize) {
    let fs_svc = match find_named_service(b"fs") {
        Some(svc) => svc,
        None => return,
    };
    let fs_init_ctl_ep = fs_svc.control_ep.load(Ordering::Relaxed);
    if fs_init_ctl_ep == usize::MAX {
        return;
    }

    let gpu = GPU_PRESENT.load(core::sync::atomic::Ordering::Relaxed);
    let mut slot_idx = 0;
    for &(path, name, console_type, service_name, requires_gpu) in FS_PROGRAMS.iter() {
        if slot_idx >= MAX_FS_LAUNCHES { break; }
        if requires_gpu && !gpu { continue; }

        let (my_ctl_ep, server_ep) = ipc::channel_create_pair();

        // Send the server endpoint to the fs service via its control channel
        let mut ctl_msg = Message::new();
        ctl_msg.cap = ipc::encode_cap_channel(server_ep);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(fs_init_ctl_ep, ctl_msg);

        // Send the initial Stat request
        let mut msg = Message::new();
        let mut pos = 0;
        pos = wire_write_u8(&mut msg.data, pos, 2); // tag: Stat
        pos = wire_write_str(&mut msg.data, pos, path);
        msg.len = pos;
        msg.sender_pid = my_pid;
        send_and_wake(my_ctl_ep, msg);

        launches[slot_idx] = Some(FsLaunchCtx {
            state: FsLaunchState::WaitStat,
            ctl_ep: my_ctl_ep,
            file_ep: 0,
            file_size: 0,
            data: Vec::new_in(INIT_ALLOC),
            path,
            name,
            console_type,
            service_name,
        });
        slot_idx += 1;
    }
}

/// Poll a single fs launch state machine. Returns true if progress was made.
fn poll_fs_launch(ctx: &mut FsLaunchCtx, my_pid: usize) -> bool {
    match ctx.state {
        FsLaunchState::WaitStat => {
            let (resp, send_wake) = ipc::channel_recv(ctx.ctl_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(resp) = resp {
                let tag = wire_read_u8(&resp.data, 0);
                if tag != 0 {
                    crate::println!("[init] fs: stat {} failed", ctx.name);
                    ipc::channel_close(ctx.ctl_ep);
                    ctx.state = FsLaunchState::Done;
                    return true;
                }
                // Ok response: u8(0) + u8(kind) + u64(size)
                ctx.file_size = wire_read_u64(&resp.data, 2) as usize;
                ctx.data = Vec::with_capacity_in(ctx.file_size, INIT_ALLOC);

                // Send Open request
                let mut msg = Message::new();
                let mut pos = 0;
                pos = wire_write_u8(&mut msg.data, pos, 0); // tag: Open
                pos = wire_write_u8(&mut msg.data, pos, 0); // flags: 0
                pos = wire_write_str(&mut msg.data, pos, ctx.path);
                msg.len = pos;
                msg.sender_pid = my_pid;
                send_and_wake(ctx.ctl_ep, msg);
                ctx.state = FsLaunchState::WaitOpen;
                return true;
            }
        }
        FsLaunchState::WaitOpen => {
            let (resp, send_wake) = ipc::channel_recv(ctx.ctl_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(resp) = resp {
                let tag = wire_read_u8(&resp.data, 0);
                if tag != 0 || resp.cap == NO_CAP {
                    crate::println!("[init] fs: open {} failed", ctx.name);
                    ipc::channel_close(ctx.ctl_ep);
                    ctx.state = FsLaunchState::Done;
                    return true;
                }
                // Decode the file channel endpoint from the cap
                match ipc::decode_cap_channel(resp.cap) {
                    Some(ep) => ctx.file_ep = ep,
                    None => {
                        crate::println!("[init] fs: open {} bad cap", ctx.name);
                        ipc::channel_close(ctx.ctl_ep);
                        ctx.state = FsLaunchState::Done;
                        return true;
                    }
                }

                // Send Read request for the whole file
                let mut msg = Message::new();
                let mut pos = 0;
                pos = wire_write_u8(&mut msg.data, pos, 0); // tag: Read
                pos = wire_write_u64(&mut msg.data, pos, 0); // offset: 0
                pos = wire_write_u32(&mut msg.data, pos, ctx.file_size as u32);
                msg.len = pos;
                msg.sender_pid = my_pid;
                send_and_wake(ctx.file_ep, msg);
                ctx.state = FsLaunchState::WaitRead;
                return true;
            }
        }
        FsLaunchState::WaitRead => {
            let mut progress = false;
            // Drain all available chunks in one go for throughput
            loop {
                let (resp, send_wake) = ipc::channel_recv(ctx.file_ep);
                if send_wake != 0 { crate::task::wake_process(send_wake); }
                match resp {
                    Some(resp) => {
                        progress = true;
                        if resp.len < 3 {
                            // Sentinel or malformed — end of data
                            finish_fs_launch(ctx, my_pid);
                            return true;
                        }
                        let tag = wire_read_u8(&resp.data, 0);
                        if tag == 2 {
                            // Error response
                            crate::println!("[init] fs: read {} error", ctx.name);
                            ipc::channel_close(ctx.file_ep);
                            ipc::channel_close(ctx.ctl_ep);
                            ctx.state = FsLaunchState::Done;
                            return true;
                        }
                        // Data chunk: u8(0) + u16(len) + bytes
                        let chunk_len = wire_read_u16(&resp.data, 1) as usize;
                        if chunk_len == 0 {
                            // Sentinel — all data received
                            finish_fs_launch(ctx, my_pid);
                            return true;
                        }
                        ctx.data.extend_from_slice(&resp.data[3..3 + chunk_len]);
                    }
                    None => break,
                }
            }
            return progress;
        }
        FsLaunchState::Done => {}
    }
    false
}

/// Complete an fs launch: close channels, spawn the process.
fn finish_fs_launch(ctx: &mut FsLaunchCtx, _my_pid: usize) {
    ipc::channel_close(ctx.file_ep);
    ipc::channel_close(ctx.ctl_ep);

    if ctx.data.is_empty() {
        crate::println!("[init] fs: {} empty, skipping", ctx.name);
        ctx.state = FsLaunchState::Done;
        return;
    }

    crate::println!("[init] Loaded {} from fs ({} bytes)", ctx.name, ctx.data.len());

    // Create boot channel
    let (boot_a, boot_b) = ipc::channel_create_pair();
    register_boot(boot_b, ctx.console_type, false);

    if let Some(svc_name) = ctx.service_name {
        // This program is a named service: give it a control channel as handle 1
        let (init_svc_ep, svc_ctl_ep) = ipc::channel_create_pair();
        register_service(svc_name, init_svc_ep);
        crate::task::spawn_user_elf_with_handles(&ctx.data, ctx.name, boot_a, svc_ctl_ep);
    } else {
        crate::task::spawn_user_elf_with_boot_channel(&ctx.data, ctx.name, boot_a);
    }

    ctx.state = FsLaunchState::Done;
}

// --- Wire protocol helpers (manual byte packing, no rvos-wire dependency) ---

/// Write a u16 little-endian length-prefixed string into buf at pos.
/// Returns the new position.
fn wire_write_str(buf: &mut [u8], pos: usize, s: &[u8]) -> usize {
    let len = s.len() as u16;
    buf[pos] = len as u8;
    buf[pos + 1] = (len >> 8) as u8;
    buf[pos + 2..pos + 2 + s.len()].copy_from_slice(s);
    pos + 2 + s.len()
}

/// Write a u8 into buf at pos. Returns new position.
fn wire_write_u8(buf: &mut [u8], pos: usize, v: u8) -> usize {
    buf[pos] = v;
    pos + 1
}

/// Write a u32 little-endian into buf at pos. Returns new position.
fn wire_write_u32(buf: &mut [u8], pos: usize, v: u32) -> usize {
    let bytes = v.to_le_bytes();
    buf[pos..pos + 4].copy_from_slice(&bytes);
    pos + 4
}

/// Write a u64 little-endian into buf at pos. Returns new position.
fn wire_write_u64(buf: &mut [u8], pos: usize, v: u64) -> usize {
    let bytes = v.to_le_bytes();
    buf[pos..pos + 8].copy_from_slice(&bytes);
    pos + 8
}

/// Read a u8 from buf at pos.
fn wire_read_u8(buf: &[u8], pos: usize) -> u8 {
    buf[pos]
}

/// Read a u16 little-endian from buf at pos.
fn wire_read_u16(buf: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([buf[pos], buf[pos + 1]])
}

/// Read a u64 little-endian from buf at pos.
fn wire_read_u64(buf: &[u8], pos: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[pos..pos + 8]);
    u64::from_le_bytes(bytes)
}

