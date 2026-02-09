use alloc::vec::Vec;
use crate::ipc::{self, Message, NO_CAP};
use crate::sync::SpinLock;
use crate::mm::heap::{InitAlloc, INIT_ALLOC};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::boot::{BootRequest, BootResponse};

/// Console type for routing stdio requests
#[derive(Clone, Copy, PartialEq)]
pub enum ConsoleType {
    Serial,
    Framebuffer,
    GpuConsole,
}

const MAX_ARGS_LEN: usize = 512;
const MAX_NS_OVERRIDES: usize = 4;

/// A single namespace override: maps a service name to a pre-established endpoint.
#[derive(Clone)]
struct NsOverride {
    name: [u8; SERVICE_NAME_LEN],
    name_len: usize,
    endpoint: usize, // global endpoint ID (decoded from cap)
}

/// A boot channel registration: the init server's end of a user process's boot channel.
struct BootRegistration {
    boot_ep_b: usize,        // init server's endpoint of the boot channel
    console_type: ConsoleType, // which console this process should use
    is_shell: bool,           // true = primary stdin recipient
    args: [u8; MAX_ARGS_LEN], // null-separated command-line args
    args_len: usize,          // length of args blob
    overrides: [Option<NsOverride>; MAX_NS_OVERRIDES],
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
pub fn register_boot(boot_ep_b: usize, console_type: ConsoleType, is_shell: bool) {
    register_boot_with_args(boot_ep_b, console_type, is_shell, &[]);
}

/// Register a boot channel with command-line arguments.
pub fn register_boot_with_args(boot_ep_b: usize, console_type: ConsoleType, is_shell: bool, args_blob: &[u8]) {
    register_boot_with_overrides(boot_ep_b, console_type, is_shell, args_blob, [const { None }; MAX_NS_OVERRIDES]);
}

/// Register a boot channel with args and namespace overrides.
fn register_boot_with_overrides(
    boot_ep_b: usize,
    console_type: ConsoleType,
    is_shell: bool,
    args_blob: &[u8],
    overrides: [Option<NsOverride>; MAX_NS_OVERRIDES],
) {
    let mut config = INIT_CONFIG.lock();
    for slot in config.boot_regs.iter_mut() {
        if slot.is_none() {
            let mut args = [0u8; MAX_ARGS_LEN];
            let args_len = args_blob.len().min(MAX_ARGS_LEN);
            args[..args_len].copy_from_slice(&args_blob[..args_len]);
            *slot = Some(BootRegistration { boot_ep_b, console_type, is_shell, args, args_len, overrides });
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

const PATH_BUF_LEN: usize = 64;
const NAME_BUF_LEN: usize = 16;

/// Tracks an in-progress fs-based program launch.
struct FsLaunchCtx {
    state: FsLaunchState,
    ctl_ep: usize,
    file_ep: usize,
    file_size: usize,
    data: Vec<u8, InitAlloc>,
    path_buf: [u8; PATH_BUF_LEN],
    path_len: usize,
    name_buf: [u8; NAME_BUF_LEN],
    name_len: usize,
    console_type: ConsoleType,
    /// If set, register this as a named service and give it a control channel as handle 1.
    service_name: Option<&'static str>,
    /// If nonzero, this is a dynamic spawn — send response on this endpoint when done.
    requester_ep: usize,
    /// If nonzero, global endpoint ID to give spawned process as handle 1.
    extra_cap: usize,
    /// If set, this process provides a console of the given type.
    /// Init will create a console control channel and register it.
    provides_console: Option<ConsoleType>,
    /// If true, register_boot with is_shell=true (so it gets stdin).
    is_shell: bool,
    /// Null-separated command-line arguments for the spawned process.
    args: [u8; MAX_ARGS_LEN],
    args_len: usize,
    /// Namespace overrides for the spawned process.
    ns_overrides: [Option<NsOverride>; MAX_NS_OVERRIDES],
}

impl FsLaunchCtx {
    fn path(&self) -> &[u8] {
        &self.path_buf[..self.path_len]
    }

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name_buf[..self.name_len]).unwrap_or("???")
    }
}

const MAX_FS_LAUNCHES: usize = 8;

/// Tracks a dynamically spawned process awaiting exit notification.
struct DynSpawn {
    /// Init's end of the kernel notification channel (receives exit code from kernel).
    notify_ep: usize,
    /// Init's end of the watcher channel (forwards exit code to whoever requested the spawn).
    watcher_ep: usize,
}

const MAX_DYN_SPAWNS: usize = 8;

/// Init server kernel task.
/// Polls boot channel endpoints for service discovery requests from user processes,
/// and concurrently loads programs from the filesystem.
pub fn init_server() {
    let my_pid = crate::task::current_pid();
    // Heap-allocate fs launch state machines to avoid ~7K stack usage
    let mut fs_launches = alloc::boxed::Box::new_in(
        [const { None::<FsLaunchCtx> }; MAX_FS_LAUNCHES], INIT_ALLOC);
    let mut dyn_spawns: [Option<DynSpawn>; MAX_DYN_SPAWNS] = [const { None }; MAX_DYN_SPAWNS];
    init_fs_launches(&mut *fs_launches, my_pid);

    let mut gpu_shell_launched = false;

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
                handle_request(boot_ep_b, console_type, is_shell, &msg, my_pid,
                               &mut fs_launches);
                handled = true;
            }
        }

        // Clean up dead boot registrations (child process exited, boot_a closed)
        for i in 0..count {
            let (boot_ep_b, _, _) = endpoints[i];
            if !ipc::channel_is_active(boot_ep_b) {
                ipc::channel_close(boot_ep_b);
                let mut config = INIT_CONFIG.lock();
                for slot in config.boot_regs.iter_mut() {
                    if let Some(ref reg) = slot {
                        if reg.boot_ep_b == boot_ep_b {
                            *slot = None;
                            break;
                        }
                    }
                }
            }
        }

        // Poll fs launch endpoints
        for slot in fs_launches.iter_mut() {
            if let Some(ref mut ctx) = slot {
                if poll_fs_launch(ctx, my_pid, &mut dyn_spawns) {
                    handled = true;
                }
                if ctx.state == FsLaunchState::Done {
                    *slot = None;
                }
            }
        }

        // Launch GPU shell once fbcon's GpuConsole is registered
        if !gpu_shell_launched && GPU_PRESENT.load(core::sync::atomic::Ordering::Relaxed) {
            let has_gpu_console = {
                let config = INIT_CONFIG.lock();
                config.services.iter().any(|s| matches!(s, Some(ref e) if e.console_type == ConsoleType::GpuConsole))
            };
            if has_gpu_console {
                start_gpu_shell(&mut fs_launches, my_pid);
                gpu_shell_launched = true;
                handled = true;
            }
        }

        // Poll exit notifications from dynamic spawns
        for slot in dyn_spawns.iter_mut() {
            if let Some(ref ds) = slot {
                let (msg, send_wake) = ipc::channel_recv(ds.notify_ep);
                if send_wake != 0 { crate::task::wake_process(send_wake); }
                if let Some(msg) = msg {
                    handled = true;
                    // Forward exit code to watcher
                    let notif: rvos_proto::process::ExitNotification =
                        rvos_wire::from_bytes(&msg.data[..msg.len])
                            .unwrap_or(rvos_proto::process::ExitNotification { exit_code: -1 });
                    let mut fwd = Message::new();
                    fwd.len = rvos_wire::to_bytes(&notif, &mut fwd.data).unwrap_or(0);
                    fwd.sender_pid = my_pid;
                    send_and_wake(ds.watcher_ep, fwd);
                    ipc::channel_close(ds.notify_ep);
                    ipc::channel_close(ds.watcher_ep);
                    *slot = None;
                }
            }
        }

        if !handled {
            // Register as blocked on ALL boot endpoints, fs launch endpoints, and dyn spawn notify endpoints
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
            for slot in dyn_spawns.iter() {
                if let Some(ref ds) = slot {
                    ipc::channel_set_blocked(ds.notify_ep, my_pid);
                }
            }
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}

fn handle_request(
    boot_ep_b: usize,
    console_type: ConsoleType,
    _is_shell: bool,
    msg: &Message,
    my_pid: usize,
    fs_launches: &mut [Option<FsLaunchCtx>; MAX_FS_LAUNCHES],
) {
    crate::trace::trace_kernel(b"init-handle_req-enter");

    let req: BootRequest = match rvos_wire::from_bytes(&msg.data[..msg.len]) {
        Ok(r) => r,
        Err(_) => {
            send_error(boot_ep_b, "bad request", my_pid);
            crate::trace::trace_kernel(b"init-handle_req-exit");
            return;
        }
    };

    let client_pid = msg.sender_pid as u32;
    match req {
        BootRequest::ConnectService { name } => {
            // Check namespace overrides first
            if let Some(override_ep) = find_ns_override(boot_ep_b, name) {
                send_ok_with_cap(boot_ep_b, override_ep, my_pid);
            } else if name == "stdin" {
                handle_stdio_request(boot_ep_b, console_type, client_pid, my_pid, 1);
            } else if name == "stdout" {
                handle_stdio_request(boot_ep_b, console_type, client_pid, my_pid, 2);
            } else if name == "stdio" {
                // Legacy: redirect old "stdio" to error
                send_error(boot_ep_b, "use stdin/stdout", my_pid);
            } else if let Some(svc) = find_named_service_by_name(name) {
                handle_service_request(boot_ep_b, svc, client_pid, my_pid);
            } else {
                send_error(boot_ep_b, "unknown service", my_pid);
            }
        }
        BootRequest::Spawn { path, args, ns_overrides } => {
            let spawn_cap = if msg.cap_count > 0 { msg.caps[0] } else { NO_CAP };
            handle_spawn_request(boot_ep_b, console_type, path, spawn_cap, args, ns_overrides, &msg, fs_launches, my_pid);
        }
        BootRequest::GetArgs {} => {
            handle_get_args(boot_ep_b, my_pid);
        }
    }

    crate::trace::trace_kernel(b"init-handle_req-exit");
}

/// Find a named service by exact name match.
fn find_named_service_by_name(name: &str) -> Option<&'static NamedService> {
    let count = NAMED_SERVICE_COUNT.load(Ordering::Relaxed);
    let name_bytes = name.as_bytes();
    for i in 0..count {
        let svc = &NAMED_SERVICES[i];
        let nlen = svc.name_len.load(Ordering::Relaxed);
        if nlen > 0 && nlen == name_bytes.len() {
            // SAFETY: name was written during boot before init_server started.
            let svc_name = unsafe { &(&*svc.name.get())[..nlen] };
            if svc_name == name_bytes {
                return Some(svc);
            }
        }
    }
    None
}

/// Find a named service whose name matches the request prefix (used by fs launch).
fn find_named_service(request: &[u8]) -> Option<&'static NamedService> {
    let count = NAMED_SERVICE_COUNT.load(Ordering::Relaxed);
    for i in 0..count {
        let svc = &NAMED_SERVICES[i];
        let nlen = svc.name_len.load(Ordering::Relaxed);
        if nlen > 0 {
            // SAFETY: name was written during boot before init_server started.
            let name_slice = unsafe { &(&*svc.name.get())[..nlen] };
            if starts_with(request, name_slice) {
                return Some(svc);
            }
        }
    }
    None
}

/// Find a namespace override for the given service name in the boot registration.
fn find_ns_override(boot_ep_b: usize, name: &str) -> Option<usize> {
    let config = INIT_CONFIG.lock();
    for slot in config.boot_regs.iter() {
        if let Some(ref reg) = slot {
            if reg.boot_ep_b == boot_ep_b {
                let name_bytes = name.as_bytes();
                for ovr in reg.overrides.iter() {
                    if let Some(ref o) = ovr {
                        if o.name_len == name_bytes.len() && &o.name[..o.name_len] == name_bytes {
                            return Some(o.endpoint);
                        }
                    }
                }
                return None;
            }
        }
    }
    None
}

/// Parse namespace overrides from the packed blob.
/// Format: [count: u8] then count * [name_len: u8, name_bytes..., cap_index: u8]
/// Each cap_index references orig_msg.caps[cap_index] (already encoded by kernel).
fn parse_ns_overrides(blob: &[u8], orig_msg: &Message) -> [Option<NsOverride>; MAX_NS_OVERRIDES] {
    let mut result: [Option<NsOverride>; MAX_NS_OVERRIDES] = [const { None }; MAX_NS_OVERRIDES];
    if blob.is_empty() {
        return result;
    }

    let count = blob[0] as usize;
    let mut pos = 1usize;
    let mut out_idx = 0;

    for _ in 0..count {
        if out_idx >= MAX_NS_OVERRIDES || pos >= blob.len() {
            break;
        }
        let name_len = blob[pos] as usize;
        pos += 1;
        if pos + name_len >= blob.len() {
            break;
        }
        let name_bytes = &blob[pos..pos + name_len];
        pos += name_len;
        let cap_index = blob[pos] as usize;
        pos += 1;

        // Decode the capability from the message's cap array
        if cap_index < orig_msg.cap_count {
            let encoded = orig_msg.caps[cap_index];
            if let Some(ep) = ipc::decode_cap_channel(encoded) {
                let mut name = [0u8; SERVICE_NAME_LEN];
                let nlen = name_len.min(SERVICE_NAME_LEN);
                name[..nlen].copy_from_slice(&name_bytes[..nlen]);
                result[out_idx] = Some(NsOverride {
                    name,
                    name_len: nlen,
                    endpoint: ep,
                });
                out_idx += 1;
            }
        }
    }

    result
}

/// Generic handler for any named service (sysinfo, math, fs, etc.).
/// Creates a channel pair, sends the server endpoint to the service's control channel
/// with a NewConnection message, and responds to the client with the client endpoint.
fn handle_service_request(boot_ep_b: usize, svc: &NamedService, client_pid: u32, my_pid: usize) {
    let (client_ep, server_ep) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            send_error(boot_ep_b, "no channels", my_pid);
            return;
        }
    };

    let ctl_ep = svc.control_ep.load(Ordering::Relaxed);
    if ctl_ep != usize::MAX {
        // Send server endpoint to the service via its control channel with NewConnection
        let mut ctl_msg = Message::new();
        ctl_msg.caps[0] = ipc::encode_cap_channel(server_ep);
    ctl_msg.cap_count = 1;
        ctl_msg.len = rvos_wire::to_bytes(
            &rvos_proto::service_control::NewConnection { client_pid, channel_role: 0 },
            &mut ctl_msg.data,
        ).unwrap_or(0);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(ctl_ep, ctl_msg);

        // Respond to client with Ok + client endpoint
        send_ok_with_cap(boot_ep_b, client_ep, my_pid);
    } else {
        send_error(boot_ep_b, "service not ready", my_pid);
    }
}

fn handle_stdio_request(boot_ep_b: usize, console_type: ConsoleType, client_pid: u32, my_pid: usize, role: u8) {
    // Create a new bidirectional channel for the client <-> console server
    let (client_ep, server_ep) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            send_error(boot_ep_b, "no channels", my_pid);
            return;
        }
    };

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
        // Send NewConnection to console server via its control channel with role
        let mut ctl_msg = Message::new();
        ctl_msg.caps[0] = ipc::encode_cap_channel(server_ep);
    ctl_msg.cap_count = 1;
        ctl_msg.len = rvos_wire::to_bytes(
            &rvos_proto::service_control::NewConnection { client_pid, channel_role: role },
            &mut ctl_msg.data,
        ).unwrap_or(0);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(ctl_ep, ctl_msg);

        // Respond to client with Ok + client endpoint
        send_ok_with_cap(boot_ep_b, client_ep, my_pid);
    } else {
        send_error(boot_ep_b, "no console", my_pid);
    }
}

/// Handle a spawn request: load an ELF from the filesystem and spawn it.
fn handle_spawn_request(
    boot_ep_b: usize,
    console_type: ConsoleType,
    path: &str,
    spawn_cap: usize,
    args: &[u8],
    ns_overrides: &[u8],
    orig_msg: &Message,
    fs_launches: &mut [Option<FsLaunchCtx>; MAX_FS_LAUNCHES],
    my_pid: usize,
) {
    let path_bytes = path.as_bytes();
    if path_bytes.is_empty() || path_bytes.len() > PATH_BUF_LEN {
        send_error(boot_ep_b, "bad path", my_pid);
        return;
    }

    // Find a free fs_launch slot
    let slot_idx = match fs_launches.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None => {
            send_error(boot_ep_b, "busy", my_pid);
            return;
        }
    };

    // Connect to fs service
    let fs_svc = match find_named_service(b"fs") {
        Some(svc) => svc,
        None => {
            send_error(boot_ep_b, "no fs", my_pid);
            return;
        }
    };
    let fs_ctl_ep = fs_svc.control_ep.load(Ordering::Relaxed);
    if fs_ctl_ep == usize::MAX {
        send_error(boot_ep_b, "no fs", my_pid);
        return;
    }

    let (my_ctl_ep, server_ep) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            send_error(boot_ep_b, "no channels", my_pid);
            return;
        }
    };

    // Send the server endpoint to the fs service via its control channel with NewConnection
    let mut ctl_msg = Message::new();
    ctl_msg.caps[0] = ipc::encode_cap_channel(server_ep);
    ctl_msg.cap_count = 1;
    ctl_msg.len = rvos_wire::to_bytes(
        &rvos_proto::service_control::NewConnection { client_pid: my_pid as u32, channel_role: 0 },
        &mut ctl_msg.data,
    ).unwrap_or(0);
    ctl_msg.sender_pid = my_pid;
    send_and_wake(fs_ctl_ep, ctl_msg);

    // Send the initial Stat request
    let mut msg = Message::new();
    let mut pos = 0;
    pos = wire_write_u8(&mut msg.data, pos, 2); // tag: Stat
    pos = wire_write_str(&mut msg.data, pos, path_bytes);
    msg.len = pos;
    msg.sender_pid = my_pid;
    send_and_wake(my_ctl_ep, msg);

    // Derive name from path (everything after last '/')
    let name_start = path_bytes.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    let name_bytes = &path_bytes[name_start..];
    let name_len = name_bytes.len().min(NAME_BUF_LEN);

    let extra_cap = if spawn_cap != NO_CAP {
        match ipc::decode_cap_channel(spawn_cap) {
            Some(ep) => ep,
            None => 0,
        }
    } else {
        0
    };

    let mut args_buf = [0u8; MAX_ARGS_LEN];
    let args_len = args.len().min(MAX_ARGS_LEN);
    args_buf[..args_len].copy_from_slice(&args[..args_len]);

    // Parse namespace overrides from the packed blob
    let parsed_overrides = parse_ns_overrides(ns_overrides, orig_msg);

    let mut ctx = FsLaunchCtx {
        state: FsLaunchState::WaitStat,
        ctl_ep: my_ctl_ep,
        file_ep: 0,
        file_size: 0,
        data: Vec::new_in(INIT_ALLOC),
        path_buf: [0u8; PATH_BUF_LEN],
        path_len: path_bytes.len(),
        name_buf: [0u8; NAME_BUF_LEN],
        name_len,
        console_type,
        service_name: None,
        requester_ep: boot_ep_b,
        extra_cap,
        provides_console: None,
        is_shell: false,
        args: args_buf,
        args_len,
        ns_overrides: parsed_overrides,
    };
    ctx.path_buf[..path_bytes.len()].copy_from_slice(path_bytes);
    ctx.name_buf[..name_len].copy_from_slice(&name_bytes[..name_len]);

    fs_launches[slot_idx] = Some(ctx);
}

/// Handle GetArgs: respond with the stored args for this process.
fn handle_get_args(boot_ep_b: usize, my_pid: usize) {
    let config = INIT_CONFIG.lock();
    for slot in config.boot_regs.iter() {
        if let Some(ref reg) = slot {
            if reg.boot_ep_b == boot_ep_b {
                let mut resp = Message::new();
                resp.len = rvos_wire::to_bytes(
                    &BootResponse::Args { args: &reg.args[..reg.args_len] },
                    &mut resp.data,
                ).unwrap_or(0);
                resp.sender_pid = my_pid;
                drop(config);
                send_and_wake(boot_ep_b, resp);
                return;
            }
        }
    }
    // Not found — send empty args
    drop(config);
    let mut resp = Message::new();
    resp.len = rvos_wire::to_bytes(
        &BootResponse::Args { args: &[] },
        &mut resp.data,
    ).unwrap_or(0);
    resp.sender_pid = my_pid;
    send_and_wake(boot_ep_b, resp);
}

/// Send an Ok response with a capability on the boot channel.
fn send_ok_with_cap(endpoint: usize, cap_ep: usize, my_pid: usize) {
    let mut resp = Message::new();
    resp.len = rvos_wire::to_bytes(&BootResponse::Ok {}, &mut resp.data).unwrap_or(0);
    resp.caps[0] = ipc::encode_cap_channel(cap_ep);
    resp.cap_count = 1;
    resp.sender_pid = my_pid;
    send_and_wake(endpoint, resp);
}

/// Send an Error response on the boot channel.
fn send_error(endpoint: usize, error_msg: &str, my_pid: usize) {
    let mut resp = Message::new();
    resp.len = rvos_wire::to_bytes(&BootResponse::Error { message: error_msg }, &mut resp.data).unwrap_or(0);
    resp.sender_pid = my_pid;
    send_and_wake(endpoint, resp);
}

/// Send a message, blocking if the queue is full. Uses the kernel-side
/// blocking send to prevent silent drops on critical control messages.
fn send_and_wake(endpoint: usize, msg: Message) {
    let my_pid = crate::task::current_pid();
    let _ = ipc::channel_send_blocking(endpoint, &msg, my_pid);
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
/// (path, name, console_type, service_name, requires_gpu, provides_console)
const FS_PROGRAMS: &[(&[u8], &str, ConsoleType, Option<&str>, bool, Option<ConsoleType>)] = &[
    (b"/bin/window-server", "window-srv", ConsoleType::Serial, Some("window"), true, None),
    (b"/bin/fbcon", "fbcon", ConsoleType::Serial, None, true, Some(ConsoleType::GpuConsole)),
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
    for &(path, name, console_type, service_name, requires_gpu, provides_console) in FS_PROGRAMS.iter() {
        if slot_idx >= MAX_FS_LAUNCHES { break; }
        if requires_gpu && !gpu { continue; }

        let (my_ctl_ep, server_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for fs launch of {}", name);
                continue;
            }
        };

        // Send the server endpoint to the fs service via its control channel with NewConnection
        let mut ctl_msg = Message::new();
        ctl_msg.caps[0] = ipc::encode_cap_channel(server_ep);
    ctl_msg.cap_count = 1;
        ctl_msg.len = rvos_wire::to_bytes(
            &rvos_proto::service_control::NewConnection { client_pid: my_pid as u32, channel_role: 0 },
            &mut ctl_msg.data,
        ).unwrap_or(0);
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

        let mut path_buf = [0u8; PATH_BUF_LEN];
        let plen = path.len().min(PATH_BUF_LEN);
        path_buf[..plen].copy_from_slice(&path[..plen]);

        let mut name_buf = [0u8; NAME_BUF_LEN];
        let nlen = name.len().min(NAME_BUF_LEN);
        name_buf[..nlen].copy_from_slice(&name.as_bytes()[..nlen]);

        launches[slot_idx] = Some(FsLaunchCtx {
            state: FsLaunchState::WaitStat,
            ctl_ep: my_ctl_ep,
            file_ep: 0,
            file_size: 0,
            data: Vec::new_in(INIT_ALLOC),
            path_buf,
            path_len: plen,
            name_buf,
            name_len: nlen,
            console_type,
            service_name,
            requester_ep: 0, // boot-time launch, no requester
            extra_cap: 0,
            provides_console,
            is_shell: false,
            args: [0u8; MAX_ARGS_LEN],
            args_len: 0,
            ns_overrides: [const { None }; MAX_NS_OVERRIDES],
        });
        slot_idx += 1;
    }
}

/// Poll a single fs launch state machine. Returns true if progress was made.
fn poll_fs_launch(
    ctx: &mut FsLaunchCtx,
    my_pid: usize,
    dyn_spawns: &mut [Option<DynSpawn>; MAX_DYN_SPAWNS],
) -> bool {
    match ctx.state {
        FsLaunchState::WaitStat => {
            let (resp, send_wake) = ipc::channel_recv(ctx.ctl_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(resp) = resp {
                let tag = wire_read_u8(&resp.data, 0);
                if tag != 0 {
                    crate::println!("[init] fs: stat {} failed", ctx.name());
                    if ctx.requester_ep != 0 {
                        send_error(ctx.requester_ep, "not found", my_pid);
                    }
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
                pos = wire_write_str(&mut msg.data, pos, ctx.path());
                msg.len = pos;
                msg.sender_pid = my_pid;
                send_and_wake(ctx.ctl_ep, msg);
                ctx.state = FsLaunchState::WaitOpen;
                return true;
            } else if !ipc::channel_is_active(ctx.ctl_ep) {
                crate::println!("[init] fs: connection closed for {}", ctx.name());
                if ctx.requester_ep != 0 {
                    send_error(ctx.requester_ep, "fs error", my_pid);
                }
                ipc::channel_close(ctx.ctl_ep);
                ctx.state = FsLaunchState::Done;
                return true;
            }
        }
        FsLaunchState::WaitOpen => {
            let (resp, send_wake) = ipc::channel_recv(ctx.ctl_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(resp) = resp {
                let tag = wire_read_u8(&resp.data, 0);
                if tag != 0 || resp.cap_count == 0 || resp.caps[0] == NO_CAP {
                    crate::println!("[init] fs: open {} failed", ctx.name());
                    if ctx.requester_ep != 0 {
                        send_error(ctx.requester_ep, "open failed", my_pid);
                    }
                    ipc::channel_close(ctx.ctl_ep);
                    ctx.state = FsLaunchState::Done;
                    return true;
                }
                // Decode the file channel endpoint from the cap
                match ipc::decode_cap_channel(resp.caps[0]) {
                    Some(ep) => ctx.file_ep = ep,
                    None => {
                        crate::println!("[init] fs: open {} bad cap", ctx.name());
                        if ctx.requester_ep != 0 {
                            send_error(ctx.requester_ep, "bad cap", my_pid);
                        }
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
            } else if !ipc::channel_is_active(ctx.ctl_ep) {
                crate::println!("[init] fs: connection closed for {}", ctx.name());
                if ctx.requester_ep != 0 {
                    send_error(ctx.requester_ep, "fs error", my_pid);
                }
                ipc::channel_close(ctx.ctl_ep);
                ctx.state = FsLaunchState::Done;
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
                            finish_fs_launch(ctx, my_pid, dyn_spawns);
                            return true;
                        }
                        let tag = wire_read_u8(&resp.data, 0);
                        if tag == 2 {
                            // Error response
                            crate::println!("[init] fs: read {} error", ctx.name());
                            if ctx.requester_ep != 0 {
                                send_error(ctx.requester_ep, "read error", my_pid);
                            }
                            ipc::channel_close(ctx.file_ep);
                            ipc::channel_close(ctx.ctl_ep);
                            ctx.state = FsLaunchState::Done;
                            return true;
                        }
                        // Data chunk: u8(0) + u16(len) + bytes
                        let chunk_len = wire_read_u16(&resp.data, 1) as usize;
                        if chunk_len == 0 {
                            // Sentinel — all data received
                            finish_fs_launch(ctx, my_pid, dyn_spawns);
                            return true;
                        }
                        ctx.data.extend_from_slice(&resp.data[3..3 + chunk_len]);
                    }
                    None => {
                        // Check if the file channel was closed
                        if !ipc::channel_is_active(ctx.file_ep) {
                            crate::println!("[init] fs: file channel closed for {}", ctx.name());
                            if ctx.requester_ep != 0 {
                                send_error(ctx.requester_ep, "read error", my_pid);
                            }
                            ipc::channel_close(ctx.file_ep);
                            ipc::channel_close(ctx.ctl_ep);
                            ctx.state = FsLaunchState::Done;
                            return true;
                        }
                        break;
                    }
                }
            }
            return progress;
        }
        FsLaunchState::Done => {}
    }
    false
}

/// Complete an fs launch: close channels, spawn the process.
fn finish_fs_launch(
    ctx: &mut FsLaunchCtx,
    my_pid: usize,
    dyn_spawns: &mut [Option<DynSpawn>; MAX_DYN_SPAWNS],
) {
    ipc::channel_close(ctx.file_ep);
    ipc::channel_close(ctx.ctl_ep);

    if ctx.data.is_empty() {
        crate::println!("[init] fs: {} empty, skipping", ctx.name());
        if ctx.requester_ep != 0 {
            send_error(ctx.requester_ep, "empty", my_pid);
        }
        ctx.state = FsLaunchState::Done;
        return;
    }

    crate::println!("[init] Loaded {} from fs ({} bytes)", ctx.name(), ctx.data.len());

    // Create boot channel
    let (boot_a, boot_b) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            crate::println!("[init] no channels for boot of {}", ctx.name());
            if ctx.requester_ep != 0 {
                send_error(ctx.requester_ep, "no channels", my_pid);
            }
            ctx.state = FsLaunchState::Done;
            return;
        }
    };
    // Take ns_overrides from ctx (replace with empty array)
    let overrides = core::mem::replace(&mut ctx.ns_overrides, [const { None }; MAX_NS_OVERRIDES]);
    register_boot_with_overrides(boot_b, ctx.console_type, ctx.is_shell, &ctx.args[..ctx.args_len], overrides);

    let pid = if let Some(svc_name) = ctx.service_name {
        // This program is a named service: give it a control channel as handle 1
        let (init_svc_ep, svc_ctl_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for service {}", svc_name);
                ctx.state = FsLaunchState::Done;
                return;
            }
        };
        register_service(svc_name, init_svc_ep);
        crate::task::spawn_user_elf_with_handles(&ctx.data, ctx.name(), boot_a, svc_ctl_ep)
    } else if let Some(console_type) = ctx.provides_console {
        // This program provides a console: give it a control channel as handle 1
        let (init_ep, ctl_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for console {}", ctx.name());
                ctx.state = FsLaunchState::Done;
                return;
            }
        };
        register_console(console_type, init_ep);
        crate::task::spawn_user_elf_with_handles(&ctx.data, ctx.name(), boot_a, ctl_ep)
    } else if ctx.extra_cap != 0 {
        crate::task::spawn_user_elf_with_handles(&ctx.data, ctx.name(), boot_a, ctx.extra_cap)
    } else {
        crate::task::spawn_user_elf_with_boot_channel(&ctx.data, ctx.name(), boot_a)
    };

    // If this is a dynamic spawn, set up exit notification and respond to requester
    if ctx.requester_ep != 0 {
        // Kernel notification channel: kernel sends exit code here
        let (init_notify_ep, kernel_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for exit notify");
                send_error(ctx.requester_ep, "no channels", my_pid);
                ctx.state = FsLaunchState::Done;
                return;
            }
        };
        crate::task::set_exit_notify_ep(pid, kernel_ep);

        // Watcher channel: init forwards exit code to the requester
        let (client_handle_ep, init_watcher_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for watcher");
                ipc::channel_close(init_notify_ep);
                ipc::channel_close(kernel_ep);
                send_error(ctx.requester_ep, "no channels", my_pid);
                ctx.state = FsLaunchState::Done;
                return;
            }
        };

        // Register in dyn_spawns table
        let mut registered = false;
        for slot in dyn_spawns.iter_mut() {
            if slot.is_none() {
                *slot = Some(DynSpawn {
                    notify_ep: init_notify_ep,
                    watcher_ep: init_watcher_ep,
                });
                registered = true;
                break;
            }
        }
        if !registered {
            crate::println!("[init] dyn_spawns full, cannot track process exit");
            ipc::channel_close(init_notify_ep);
            ipc::channel_close(kernel_ep);
            ipc::channel_close(client_handle_ep);
            ipc::channel_close(init_watcher_ep);
            send_error(ctx.requester_ep, "busy", my_pid);
            ctx.state = FsLaunchState::Done;
            return;
        }

        // Send Ok response with process handle capability
        send_ok_with_cap(ctx.requester_ep, client_handle_ep, my_pid);
    }

    ctx.state = FsLaunchState::Done;
}

/// Start loading /bin/shell from the filesystem to run on the GPU console.
/// Called once after fbcon registers its GpuConsole.
fn start_gpu_shell(launches: &mut [Option<FsLaunchCtx>; MAX_FS_LAUNCHES], my_pid: usize) {
    let fs_svc = match find_named_service(b"fs") {
        Some(svc) => svc,
        None => {
            crate::println!("[init] no fs service for gpu shell");
            return;
        }
    };
    let fs_ctl_ep = fs_svc.control_ep.load(Ordering::Relaxed);
    if fs_ctl_ep == usize::MAX {
        crate::println!("[init] fs not ready for gpu shell");
        return;
    }

    let slot_idx = match launches.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None => {
            crate::println!("[init] no launch slot for gpu shell");
            return;
        }
    };

    let (my_ctl_ep, server_ep) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            crate::println!("[init] no channels for gpu shell");
            return;
        }
    };

    let mut ctl_msg = Message::new();
    ctl_msg.caps[0] = ipc::encode_cap_channel(server_ep);
    ctl_msg.cap_count = 1;
    ctl_msg.len = rvos_wire::to_bytes(
        &rvos_proto::service_control::NewConnection { client_pid: my_pid as u32, channel_role: 0 },
        &mut ctl_msg.data,
    ).unwrap_or(0);
    ctl_msg.sender_pid = my_pid;
    send_and_wake(fs_ctl_ep, ctl_msg);

    let path = b"/bin/shell";
    let mut msg = Message::new();
    let mut pos = 0;
    pos = wire_write_u8(&mut msg.data, pos, 2); // tag: Stat
    pos = wire_write_str(&mut msg.data, pos, path);
    msg.len = pos;
    msg.sender_pid = my_pid;
    send_and_wake(my_ctl_ep, msg);

    let mut path_buf = [0u8; PATH_BUF_LEN];
    path_buf[..path.len()].copy_from_slice(path);

    let mut name_buf = [0u8; NAME_BUF_LEN];
    let name = b"shell-gpu";
    name_buf[..name.len()].copy_from_slice(name);

    launches[slot_idx] = Some(FsLaunchCtx {
        state: FsLaunchState::WaitStat,
        ctl_ep: my_ctl_ep,
        file_ep: 0,
        file_size: 0,
        data: Vec::new_in(INIT_ALLOC),
        path_buf,
        path_len: path.len(),
        name_buf,
        name_len: name.len(),
        console_type: ConsoleType::GpuConsole,
        service_name: None,
        requester_ep: 0,
        extra_cap: 0,
        provides_console: None,
        is_shell: true,
        args: [0u8; MAX_ARGS_LEN],
        args_len: 0,
        ns_overrides: [const { None }; MAX_NS_OVERRIDES],
    });

    crate::println!("[init] Starting GPU shell (loading /bin/shell from fs)");
}

// --- Wire protocol helpers (manual byte packing for fs protocol — NOT boot channel) ---

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
