use alloc::vec::Vec;
use crate::ipc::{self, Cap, Message};
use crate::sync::SpinLock;
use crate::mm::heap::{InitAlloc, INIT_ALLOC};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_proto::boot::{BootRequest, BootResponse};
use rvos_proto::fs::{FsRequest, FsResponse, FileRequest, FileResponse, FileOffset, OpenFlags};

/// Console type for routing stdio requests
#[derive(Clone, Copy, PartialEq)]
pub enum ConsoleType {
    Serial,
    Framebuffer,
}

const MAX_ARGS_LEN: usize = 512;
const MAX_NS_OVERRIDES: usize = 16;

/// A single namespace override: maps a service name to a pre-established endpoint,
/// or marks it as explicitly removed (blocks inheritance from parent).
/// `endpoint == None` means removal (blocks inheritance); `Some(ep)` means redirect.
#[derive(Clone)]
struct NsOverride {
    name: [u8; SERVICE_NAME_LEN],
    name_len: usize,
    endpoint: Option<ipc::OwnedEndpoint>, // None = removed, Some = redirect
}

/// A boot channel registration: the init server's end of a user process's boot channel.
struct BootRegistration {
    boot_ep_b: ipc::OwnedEndpoint, // init server's endpoint of the boot channel
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
const MAX_NAMED_SERVICES: usize = 16;
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
pub fn register_boot(boot_ep_b: ipc::OwnedEndpoint, console_type: ConsoleType, is_shell: bool) {
    register_boot_with_args(boot_ep_b, console_type, is_shell, &[]);
}

/// Register a boot channel with command-line arguments.
pub fn register_boot_with_args(boot_ep_b: ipc::OwnedEndpoint, console_type: ConsoleType, is_shell: bool, args_blob: &[u8]) {
    register_boot_with_overrides(boot_ep_b, console_type, is_shell, args_blob, [const { None }; MAX_NS_OVERRIDES]);
}

/// Register a boot channel with args and namespace overrides.
fn register_boot_with_overrides(
    boot_ep_b: ipc::OwnedEndpoint,
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
    crate::println!("[init] WARNING: boot registration table full, skipping");
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
    crate::println!("[init] WARNING: service registration table full, skipping");
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
    /// If true, the spawned process will be suspended before its first instruction.
    suspended: bool,
}

impl FsLaunchCtx {
    fn path(&self) -> &[u8] {
        &self.path_buf[..self.path_len]
    }

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name_buf[..self.name_len]).unwrap_or("???")
    }
}

impl Drop for FsLaunchCtx {
    fn drop(&mut self) {
        // Close any raw endpoint references this context still holds.
        // Fields are zeroed after explicit close to prevent double-close.
        if self.ctl_ep != 0 {
            drop(unsafe { ipc::OwnedEndpoint::from_raw(self.ctl_ep) });
        }
        if self.file_ep != 0 {
            drop(unsafe { ipc::OwnedEndpoint::from_raw(self.file_ep) });
        }
        if self.extra_cap != 0 {
            drop(unsafe { ipc::OwnedEndpoint::from_raw(self.extra_cap) });
        }
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

impl Drop for DynSpawn {
    fn drop(&mut self) {
        if self.notify_ep != 0 {
            drop(unsafe { ipc::OwnedEndpoint::from_raw(self.notify_ep) });
        }
        if self.watcher_ep != 0 {
            drop(unsafe { ipc::OwnedEndpoint::from_raw(self.watcher_ep) });
        }
    }
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
    init_fs_launches(&mut fs_launches, my_pid);

    loop {
        // Snapshot boot registrations under the lock
        let mut endpoints = [(0usize, ConsoleType::Serial, false); MAX_BOOT_REGS];
        let mut count = 0;
        {
            let config = INIT_CONFIG.lock();
            for i in 0..MAX_BOOT_REGS {
                if let Some(ref reg) = config.boot_regs[i] {
                    endpoints[count] = (reg.boot_ep_b.raw(), reg.console_type, reg.is_shell);
                    count += 1;
                }
            }
        }

        // Poll all boot endpoints without holding the lock
        let mut handled = false;
        for &(boot_ep_b, console_type, is_shell) in endpoints.iter().take(count) {
            let (msg, send_wake) = ipc::channel_recv(boot_ep_b);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(msg) = msg {
                handle_request(boot_ep_b, console_type, is_shell, &msg, my_pid,
                               &mut fs_launches);
                handled = true;
            }
        }

        // Clean up dead boot registrations (child process exited, boot_a closed).
        // Drop the BootRegistration → drops boot_ep_b + all NsOverride endpoints.
        for &(raw_boot_ep, _, _) in endpoints.iter().take(count) {
            if !ipc::channel_is_active(raw_boot_ep) {
                let mut config = INIT_CONFIG.lock();
                for slot in config.boot_regs.iter_mut() {
                    if let Some(ref reg) = slot {
                        if reg.boot_ep_b.raw() == raw_boot_ep {
                            *slot = None; // Drop handles all cleanup
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
                    *slot = None; // Drop handles notify_ep + watcher_ep cleanup
                }
            }
        }

        if !handled {
            // Register as blocked on ALL boot endpoints, fs launch endpoints, and dyn spawn notify endpoints
            for ep in endpoints.iter().take(count) {
                ipc::channel_set_blocked(ep.0, my_pid);
            }
            for ctx in fs_launches.iter().flatten() {
                let ep = match ctx.state {
                    FsLaunchState::WaitStat | FsLaunchState::WaitOpen => ctx.ctl_ep,
                    FsLaunchState::WaitRead => ctx.file_ep,
                    FsLaunchState::Done => continue,
                };
                ipc::channel_set_blocked(ep, my_pid);
            }
            for ds in dyn_spawns.iter().flatten() {
                ipc::channel_set_blocked(ds.notify_ep, my_pid);
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
                // send_ok_with_cap handles inc_ref for the transfer.
                // No close needed: the BootRegistration still holds its reference.
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
        BootRequest::Spawn { path, args, ns_overrides, suspended } => {
            // Extract extra_cap as raw endpoint from the first cap in the message.
            // clone_from_raw creates a new reference that FsLaunchCtx will own.
            let spawn_cap: usize = if msg.cap_count > 0 {
                match &msg.caps[0] {
                    Cap::Channel(ep) => ipc::OwnedEndpoint::clone_from_raw(ep.raw()).into_raw(),
                    _ => 0,
                }
            } else {
                0
            };
            handle_spawn_request(SpawnContext {
                boot_ep_b,
                console_type,
                path,
                spawn_cap,
                args,
                ns_overrides,
                suspended,
                orig_msg: msg,
                fs_launches,
                my_pid,
            });
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
    for svc in NAMED_SERVICES.iter().take(count) {
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
    for svc in NAMED_SERVICES.iter().take(count) {
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
/// Returns None for removed entries (falls through to global registry).
fn find_ns_override(boot_ep_b: usize, name: &str) -> Option<usize> {
    let config = INIT_CONFIG.lock();
    for reg in config.boot_regs.iter().flatten() {
        if reg.boot_ep_b.raw() == boot_ep_b {
            let name_bytes = name.as_bytes();
            for o in reg.overrides.iter().flatten() {
                if o.name_len == name_bytes.len() && &o.name[..o.name_len] == name_bytes {
                    return o.endpoint.as_ref().map(|ep| ep.raw());
                }
            }
            return None;
        }
    }
    None
}

/// Parse namespace overrides from the packed blob.
/// Format: [count: u8] then count * [name_len: u8, name_bytes..., action: u8, cap_index: u8]
/// action=0: redirect (use caps[cap_index]), action=1: remove (cap_index ignored).
/// Each cap_index references orig_msg.caps[cap_index] (RAII Cap in the message).
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
        if pos + name_len + 2 > blob.len() {
            break;
        }
        let name_bytes = &blob[pos..pos + name_len];
        pos += name_len;
        let action = blob[pos];
        pos += 1;
        let cap_index = blob[pos] as usize;
        pos += 1;

        let mut name = [0u8; SERVICE_NAME_LEN];
        let nlen = name_len.min(SERVICE_NAME_LEN);
        name[..nlen].copy_from_slice(&name_bytes[..nlen]);

        if action == 1 {
            // Removal entry: blocks inheritance of this name
            result[out_idx] = Some(NsOverride {
                name,
                name_len: nlen,
                endpoint: None,
            });
            out_idx += 1;
        } else {
            // Redirect entry: clone the RAII endpoint from the message's cap array.
            // The clone performs inc_ref so the BootRegistration holds its own reference.
            if cap_index < orig_msg.cap_count {
                if let Cap::Channel(ref ep) = orig_msg.caps[cap_index] {
                    result[out_idx] = Some(NsOverride {
                        name,
                        name_len: nlen,
                        endpoint: Some(ep.clone()), // clone = inc_ref
                    });
                    out_idx += 1;
                }
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
        // Send server endpoint to the service via its control channel with NewConnection.
        // clone = inc_ref for the transfer; drop server_ep closes our reference.
        let mut ctl_msg = Message::new();
        ctl_msg.caps[0] = Cap::Channel(server_ep.clone());
        ctl_msg.cap_count = 1;
        ctl_msg.len = rvos_wire::to_bytes(
            &rvos_proto::service_control::NewConnection { client_pid, channel_role: 0 },
            &mut ctl_msg.data,
        ).unwrap_or(0);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(ctl_ep, ctl_msg);
        drop(server_ep); // close our reference (clone in msg has the receiver's)

        // Respond to client with Ok + client endpoint
        send_ok_with_cap(boot_ep_b, client_ep.raw(), my_pid);
        drop(client_ep); // close our reference
    } else {
        send_error(boot_ep_b, "service not ready", my_pid);
    }
}

fn handle_stdio_request(boot_ep_b: usize, _console_type: ConsoleType, client_pid: u32, my_pid: usize, role: u8) {
    // Create a new bidirectional channel for the client <-> console server
    let (client_ep, server_ep) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            send_error(boot_ep_b, "no channels", my_pid);
            return;
        }
    };

    // Always route stdio to the serial console. Programs that need a different
    // console (e.g., fbcon's shell) use namespace overrides instead.
    let control_ep = {
        let config = INIT_CONFIG.lock();
        config.services.iter()
            .filter_map(|s| s.as_ref())
            .find(|s| s.console_type == ConsoleType::Serial)
            .map(|s| s.control_ep)
    };

    if let Some(ctl_ep) = control_ep {
        // Send NewConnection to console server via its control channel with role.
        // clone = inc_ref for the transfer; drop server_ep closes our reference.
        let mut ctl_msg = Message::new();
        ctl_msg.caps[0] = Cap::Channel(server_ep.clone());
        ctl_msg.cap_count = 1;
        ctl_msg.len = rvos_wire::to_bytes(
            &rvos_proto::service_control::NewConnection { client_pid, channel_role: role },
            &mut ctl_msg.data,
        ).unwrap_or(0);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(ctl_ep, ctl_msg);
        drop(server_ep); // close our reference

        // Respond to client with Ok + client endpoint
        send_ok_with_cap(boot_ep_b, client_ep.raw(), my_pid);
        drop(client_ep); // close our reference
    } else {
        send_error(boot_ep_b, "no console", my_pid);
    }
}

/// Copy the parent's namespace overrides from INIT_CONFIG.
fn get_parent_overrides(boot_ep_b: usize) -> [Option<NsOverride>; MAX_NS_OVERRIDES] {
    let config = INIT_CONFIG.lock();
    for reg in config.boot_regs.iter().flatten() {
        if reg.boot_ep_b.raw() == boot_ep_b {
            return reg.overrides.clone();
        }
    }
    [const { None }; MAX_NS_OVERRIDES]
}

/// Merge parent and explicit overrides. Explicit entries take priority.
/// A removal entry in explicit blocks the parent's override with the same name.
fn merge_overrides(
    parent: &[Option<NsOverride>; MAX_NS_OVERRIDES],
    explicit: [Option<NsOverride>; MAX_NS_OVERRIDES],
) -> [Option<NsOverride>; MAX_NS_OVERRIDES] {
    let mut result = explicit;

    // Count how many explicit entries we have
    let mut count = 0;
    for slot in result.iter() {
        if slot.is_some() { count += 1; }
    }

    // Fill remaining slots with parent entries not already present in explicit
    for p_slot in parent.iter() {
        if count >= MAX_NS_OVERRIDES { break; }
        if let Some(ref p) = p_slot {
            // Check if this name is already in the explicit set
            let already = result.iter().any(|slot| {
                if let Some(ref e) = slot {
                    e.name_len == p.name_len && e.name[..e.name_len] == p.name[..p.name_len]
                } else {
                    false
                }
            });
            if !already {
                // Clone the NsOverride — OwnedEndpoint::clone does inc_ref automatically.
                for slot in result.iter_mut() {
                    if slot.is_none() {
                        *slot = Some(p.clone());
                        count += 1;
                        break;
                    }
                }
            }
        }
    }

    result
}

/// Bundles the arguments for `handle_spawn_request` to avoid too many parameters.
struct SpawnContext<'a> {
    boot_ep_b: usize,
    console_type: ConsoleType,
    path: &'a str,
    spawn_cap: usize,
    args: &'a [u8],
    ns_overrides: &'a [u8],
    suspended: bool,
    orig_msg: &'a Message,
    fs_launches: &'a mut [Option<FsLaunchCtx>; MAX_FS_LAUNCHES],
    my_pid: usize,
}

/// Handle a spawn request: load an ELF from the filesystem and spawn it.
fn handle_spawn_request(ctx: SpawnContext<'_>) {
    // Helper to clean up spawn_cap on early return. spawn_cap is a raw owned
    // endpoint (0 = none) that will be transferred to FsLaunchCtx on success.
    // On error, we must close it to avoid leaking the reference.
    let close_spawn_cap = |cap: usize| {
        if cap != 0 {
            drop(unsafe { ipc::OwnedEndpoint::from_raw(cap) });
        }
    };

    let path_bytes = ctx.path.as_bytes();
    if path_bytes.is_empty() || path_bytes.len() > PATH_BUF_LEN {
        close_spawn_cap(ctx.spawn_cap);
        send_error(ctx.boot_ep_b, "bad path", ctx.my_pid);
        return;
    }

    // Find a free fs_launch slot
    let slot_idx = match ctx.fs_launches.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None => {
            close_spawn_cap(ctx.spawn_cap);
            send_error(ctx.boot_ep_b, "busy", ctx.my_pid);
            return;
        }
    };

    // Connect to fs service
    let fs_svc = match find_named_service(b"fs") {
        Some(svc) => svc,
        None => {
            close_spawn_cap(ctx.spawn_cap);
            send_error(ctx.boot_ep_b, "no fs", ctx.my_pid);
            return;
        }
    };
    let fs_ctl_ep = fs_svc.control_ep.load(Ordering::Relaxed);
    if fs_ctl_ep == usize::MAX {
        close_spawn_cap(ctx.spawn_cap);
        send_error(ctx.boot_ep_b, "no fs", ctx.my_pid);
        return;
    }

    let (my_ctl_ep, server_ep) = match ipc::channel_create_pair() {
        Some(pair) => pair,
        None => {
            close_spawn_cap(ctx.spawn_cap);
            send_error(ctx.boot_ep_b, "no channels", ctx.my_pid);
            return;
        }
    };

    // Send the server endpoint to the fs service via its control channel with NewConnection.
    // clone = inc_ref for the transfer; drop server_ep closes our reference.
    let mut ctl_msg = Message::new();
    ctl_msg.caps[0] = Cap::Channel(server_ep.clone());
    ctl_msg.cap_count = 1;
    ctl_msg.len = rvos_wire::to_bytes(
        &rvos_proto::service_control::NewConnection { client_pid: ctx.my_pid as u32, channel_role: 0 },
        &mut ctl_msg.data,
    ).unwrap_or(0);
    ctl_msg.sender_pid = ctx.my_pid;
    send_and_wake(fs_ctl_ep, ctl_msg);
    drop(server_ep); // close our reference

    // Send the initial Stat request
    let mut msg = Message::new();
    let path_str = core::str::from_utf8(path_bytes).unwrap_or("");
    msg.len = rvos_wire::to_bytes(
        &FsRequest::Stat { path: path_str },
        &mut msg.data,
    ).unwrap_or(0);
    msg.sender_pid = ctx.my_pid;
    send_and_wake(my_ctl_ep.raw(), msg);

    // Derive name from path (everything after last '/')
    let name_start = path_bytes.iter().rposition(|&b| b == b'/').map(|i| i + 1).unwrap_or(0);
    let name_bytes = &path_bytes[name_start..];
    let name_len = name_bytes.len().min(NAME_BUF_LEN);

    // spawn_cap is already a raw endpoint ID (0 = none), set up in handle_request.
    let extra_cap = ctx.spawn_cap;

    let mut args_buf = [0u8; MAX_ARGS_LEN];
    let args_len = ctx.args.len().min(MAX_ARGS_LEN);
    args_buf[..args_len].copy_from_slice(&ctx.args[..args_len]);

    // Parse namespace overrides from the packed blob, then merge with parent's overrides
    let explicit_overrides = parse_ns_overrides(ctx.ns_overrides, ctx.orig_msg);
    let parent_overrides = get_parent_overrides(ctx.boot_ep_b);
    let parsed_overrides = merge_overrides(&parent_overrides, explicit_overrides);

    let mut launch_ctx = FsLaunchCtx {
        state: FsLaunchState::WaitStat,
        ctl_ep: my_ctl_ep.into_raw(),
        file_ep: 0,
        file_size: 0,
        data: Vec::new_in(INIT_ALLOC),
        path_buf: [0u8; PATH_BUF_LEN],
        path_len: path_bytes.len(),
        name_buf: [0u8; NAME_BUF_LEN],
        name_len,
        console_type: ctx.console_type,
        service_name: None,
        requester_ep: ctx.boot_ep_b,
        extra_cap,
        provides_console: None,
        is_shell: false,
        args: args_buf,
        args_len,
        ns_overrides: parsed_overrides,
        suspended: ctx.suspended,
    };
    launch_ctx.path_buf[..path_bytes.len()].copy_from_slice(path_bytes);
    launch_ctx.name_buf[..name_len].copy_from_slice(&name_bytes[..name_len]);

    ctx.fs_launches[slot_idx] = Some(launch_ctx);
}

/// Handle GetArgs: respond with the stored args for this process.
fn handle_get_args(boot_ep_b: usize, my_pid: usize) {
    let config = INIT_CONFIG.lock();
    for reg in config.boot_regs.iter().flatten() {
        if reg.boot_ep_b.raw() == boot_ep_b {
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
/// Uses clone_from_raw to create a new RAII reference (inc_ref) for the transfer.
fn send_ok_with_cap(endpoint: usize, cap_ep: usize, my_pid: usize) {
    let mut resp = Message::new();
    resp.len = rvos_wire::to_bytes(&BootResponse::Ok {}, &mut resp.data).unwrap_or(0);
    resp.caps[0] = Cap::Channel(ipc::OwnedEndpoint::clone_from_raw(cap_ep));
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
    let _ = ipc::channel_send_blocking(endpoint, msg, my_pid);
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

/// Descriptor for a program to launch from the filesystem at boot time.
struct FsProgram {
    path: &'static [u8],
    name: &'static str,
    console_type: ConsoleType,
    service_name: Option<&'static str>,
    requires_gpu: bool,
    provides_console: Option<ConsoleType>,
}

/// Programs to launch from the filesystem at boot time.
const FS_PROGRAMS: &[FsProgram] = &[
    FsProgram { path: b"/bin/window-server", name: "window-srv", console_type: ConsoleType::Serial, service_name: Some("window"), requires_gpu: true, provides_console: None },
    FsProgram { path: b"/bin/fbcon", name: "fbcon", console_type: ConsoleType::Serial, service_name: None, requires_gpu: true, provides_console: None },
    FsProgram { path: b"/bin/net-stack", name: "net-stack", console_type: ConsoleType::Serial, service_name: Some("net"), requires_gpu: false, provides_console: None },
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
    for prog in FS_PROGRAMS.iter() {
        if slot_idx >= MAX_FS_LAUNCHES { break; }
        if prog.requires_gpu && !gpu { continue; }
        let path = prog.path;
        let name = prog.name;
        let console_type = prog.console_type;
        let service_name = prog.service_name;
        let provides_console = prog.provides_console;

        let (my_ctl_ep, server_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for fs launch of {}", name);
                continue;
            }
        };

        // Send the server endpoint to the fs service via its control channel with NewConnection.
        // clone = inc_ref for the transfer; drop server_ep closes our reference.
        let mut ctl_msg = Message::new();
        ctl_msg.caps[0] = Cap::Channel(server_ep.clone());
        ctl_msg.cap_count = 1;
        ctl_msg.len = rvos_wire::to_bytes(
            &rvos_proto::service_control::NewConnection { client_pid: my_pid as u32, channel_role: 0 },
            &mut ctl_msg.data,
        ).unwrap_or(0);
        ctl_msg.sender_pid = my_pid;
        send_and_wake(fs_init_ctl_ep, ctl_msg);
        drop(server_ep); // close our reference

        // Send the initial Stat request
        let mut msg = Message::new();
        let path_str = core::str::from_utf8(path).unwrap_or("");
        msg.len = rvos_wire::to_bytes(
            &FsRequest::Stat { path: path_str },
            &mut msg.data,
        ).unwrap_or(0);
        msg.sender_pid = my_pid;
        send_and_wake(my_ctl_ep.raw(), msg);

        let mut path_buf = [0u8; PATH_BUF_LEN];
        let plen = path.len().min(PATH_BUF_LEN);
        path_buf[..plen].copy_from_slice(&path[..plen]);

        let mut name_buf = [0u8; NAME_BUF_LEN];
        let nlen = name.len().min(NAME_BUF_LEN);
        name_buf[..nlen].copy_from_slice(&name.as_bytes()[..nlen]);

        launches[slot_idx] = Some(FsLaunchCtx {
            state: FsLaunchState::WaitStat,
            ctl_ep: my_ctl_ep.into_raw(),
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
            suspended: false,
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
                match rvos_wire::from_bytes::<FsResponse>(&resp.data[..resp.len]) {
                    Ok(FsResponse::Ok { kind: _, size }) => {
                        ctx.file_size = size as usize;
                    }
                    _ => {
                        crate::println!("[init] fs: stat {} failed", ctx.name());
                        if ctx.requester_ep != 0 {
                            send_error(ctx.requester_ep, "not found", my_pid);
                        }
                        ctx.state = FsLaunchState::Done; // Drop handles ctl_ep cleanup
                        return true;
                    }
                }
                ctx.data = Vec::with_capacity_in(ctx.file_size, INIT_ALLOC);

                // Send Open request
                let mut msg = Message::new();
                let path_str = core::str::from_utf8(ctx.path()).unwrap_or("");
                msg.len = rvos_wire::to_bytes(
                    &FsRequest::Open { flags: OpenFlags::OPEN, path: path_str },
                    &mut msg.data,
                ).unwrap_or(0);
                msg.sender_pid = my_pid;
                send_and_wake(ctx.ctl_ep, msg);
                ctx.state = FsLaunchState::WaitOpen;
                return true;
            } else if !ipc::channel_is_active(ctx.ctl_ep) {
                crate::println!("[init] fs: connection closed for {}", ctx.name());
                if ctx.requester_ep != 0 {
                    send_error(ctx.requester_ep, "fs error", my_pid);
                }
                ctx.state = FsLaunchState::Done; // Drop handles ctl_ep cleanup
                return true;
            }
        }
        FsLaunchState::WaitOpen => {
            let (resp, send_wake) = ipc::channel_recv(ctx.ctl_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            if let Some(mut resp) = resp {
                // Extract raw cap values from the RAII Cap array for from_bytes_with_caps.
                let mut raw_caps = [0usize; ipc::MAX_CAPS];
                for (i, raw_cap) in raw_caps.iter_mut().enumerate().take(resp.cap_count) {
                    if let Cap::Channel(ref ep) = resp.caps[i] {
                        *raw_cap = ep.raw();
                    }
                }
                let parsed = rvos_wire::from_bytes_with_caps::<FsResponse>(
                    &resp.data[..resp.len],
                    &raw_caps[..resp.cap_count],
                );
                if !matches!(parsed, Ok(FsResponse::Opened { .. })) {
                    crate::println!("[init] fs: open {} failed", ctx.name());
                    if ctx.requester_ep != 0 {
                        send_error(ctx.requester_ep, "open failed", my_pid);
                    }
                    ctx.state = FsLaunchState::Done; // Drop handles ctl_ep cleanup
                    return true;
                }
                // Extract the file channel endpoint from the received message cap
                if resp.cap_count > 0 {
                    if let Cap::Channel(ep) = resp.caps[0].take() {
                        ctx.file_ep = ep.into_raw();
                    }
                }
                if ctx.file_ep == 0 {
                    crate::println!("[init] fs: open {} bad cap", ctx.name());
                    if ctx.requester_ep != 0 {
                        send_error(ctx.requester_ep, "bad cap", my_pid);
                    }
                    ctx.state = FsLaunchState::Done; // Drop handles ctl_ep cleanup
                    return true;
                }

                // Send Read request for the whole file
                let mut msg = Message::new();
                msg.len = rvos_wire::to_bytes(
                    &FileRequest::Read {
                        offset: FileOffset::Explicit { offset: 0 },
                        len: ctx.file_size as u32,
                    },
                    &mut msg.data,
                ).unwrap_or(0);
                msg.sender_pid = my_pid;
                send_and_wake(ctx.file_ep, msg);
                ctx.state = FsLaunchState::WaitRead;
                return true;
            } else if !ipc::channel_is_active(ctx.ctl_ep) {
                crate::println!("[init] fs: connection closed for {}", ctx.name());
                if ctx.requester_ep != 0 {
                    send_error(ctx.requester_ep, "fs error", my_pid);
                }
                ctx.state = FsLaunchState::Done; // Drop handles ctl_ep cleanup
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
                        match rvos_wire::from_bytes::<FileResponse>(&resp.data[..resp.len]) {
                            Ok(FileResponse::Data { chunk }) => {
                                if chunk.is_empty() {
                                    // Sentinel — all data received
                                    finish_fs_launch(ctx, my_pid, dyn_spawns);
                                    return true;
                                }
                                ctx.data.extend_from_slice(chunk);
                            }
                            Ok(FileResponse::Error { .. }) => {
                                crate::println!("[init] fs: read {} error", ctx.name());
                                if ctx.requester_ep != 0 {
                                    send_error(ctx.requester_ep, "read error", my_pid);
                                }
                                ctx.state = FsLaunchState::Done; // Drop handles cleanup
                                return true;
                            }
                            _ => {
                                // Malformed or unexpected — treat as end of data
                                finish_fs_launch(ctx, my_pid, dyn_spawns);
                                return true;
                            }
                        }
                    }
                    None => {
                        // Check if the file channel was closed
                        if !ipc::channel_is_active(ctx.file_ep) {
                            crate::println!("[init] fs: file channel closed for {}", ctx.name());
                            if ctx.requester_ep != 0 {
                                send_error(ctx.requester_ep, "read error", my_pid);
                            }
                            ctx.state = FsLaunchState::Done; // Drop handles cleanup
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
    // Close fs channels early to free channel slots for spawn channels.
    // Zero the fields so the Drop impl won't double-close.
    let ctl = core::mem::replace(&mut ctx.ctl_ep, 0);
    let file = core::mem::replace(&mut ctx.file_ep, 0);
    if ctl != 0 { drop(unsafe { ipc::OwnedEndpoint::from_raw(ctl) }); }
    if file != 0 { drop(unsafe { ipc::OwnedEndpoint::from_raw(file) }); }

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
        register_service(svc_name, init_svc_ep.into_raw());
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
        register_console(console_type, init_ep.into_raw());
        crate::task::spawn_user_elf_with_handles(&ctx.data, ctx.name(), boot_a, ctl_ep)
    } else if ctx.extra_cap != 0 {
        // SAFETY: clone_from_raw was called when storing extra_cap, so we own this reference.
        let extra_ep = unsafe { ipc::OwnedEndpoint::from_raw(core::mem::replace(&mut ctx.extra_cap, 0)) };
        crate::task::spawn_user_elf_with_handles(&ctx.data, ctx.name(), boot_a, extra_ep)
    } else {
        crate::task::spawn_user_elf_with_boot_channel(&ctx.data, ctx.name(), boot_a)
    };

    let pid = match pid {
        Some(p) => p,
        None => {
            crate::println!("[init] spawn failed for {}", ctx.name());
            if ctx.requester_ep != 0 {
                send_error(ctx.requester_ep, "spawn failed", my_pid);
            }
            ctx.state = FsLaunchState::Done;
            return;
        }
    };

    // If the caller requested suspended spawn, block the process before it runs.
    if ctx.suspended {
        crate::task::suspend_spawned_process(pid);
    }

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
        let kernel_ep_raw = kernel_ep.into_raw();
        crate::task::set_exit_notify_ep(pid, kernel_ep_raw);

        // Watcher channel: init forwards exit code to the requester
        let (client_handle_ep, init_watcher_ep) = match ipc::channel_create_pair() {
            Some(pair) => pair,
            None => {
                crate::println!("[init] no channels for watcher");
                drop(init_notify_ep); // close our end
                // Reclaim kernel_ep from the process and close it
                crate::task::set_exit_notify_ep(pid, 0);
                drop(unsafe { ipc::OwnedEndpoint::from_raw(kernel_ep_raw) });
                send_error(ctx.requester_ep, "no channels", my_pid);
                ctx.state = FsLaunchState::Done;
                return;
            }
        };

        // Convert to raw for storage; cleanup on error via from_raw.
        let init_notify_raw = init_notify_ep.into_raw();
        let init_watcher_raw = init_watcher_ep.into_raw();
        let client_handle_raw = client_handle_ep.raw();

        // Register in dyn_spawns table
        let mut registered = false;
        for slot in dyn_spawns.iter_mut() {
            if slot.is_none() {
                *slot = Some(DynSpawn {
                    notify_ep: init_notify_raw,
                    watcher_ep: init_watcher_raw,
                });
                registered = true;
                break;
            }
        }
        if !registered {
            crate::println!("[init] dyn_spawns full, cannot track process exit");
            drop(unsafe { ipc::OwnedEndpoint::from_raw(init_notify_raw) });
            // Reclaim kernel_ep from process and close it
            crate::task::set_exit_notify_ep(pid, 0);
            drop(unsafe { ipc::OwnedEndpoint::from_raw(kernel_ep_raw) });
            drop(client_handle_ep);
            drop(unsafe { ipc::OwnedEndpoint::from_raw(init_watcher_raw) });
            send_error(ctx.requester_ep, "busy", my_pid);
            ctx.state = FsLaunchState::Done;
            return;
        }

        // Send ProcessStarted on watcher channel so the parent knows the child PID
        let mut started_msg = Message::new();
        let started = rvos_proto::process::ProcessStarted { pid: pid as u32 };
        started_msg.len = rvos_wire::to_bytes(&started, &mut started_msg.data).unwrap_or(0);
        started_msg.sender_pid = my_pid;
        send_and_wake(init_watcher_raw, started_msg);

        // Send Ok response with process handle capability
        send_ok_with_cap(ctx.requester_ep, client_handle_raw, my_pid);
        drop(client_handle_ep); // close our reference
    }

    ctx.state = FsLaunchState::Done;
}


