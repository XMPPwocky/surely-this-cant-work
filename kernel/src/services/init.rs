use crate::ipc::{self, Message};
use crate::sync::SpinLock;
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
pub fn register_boot(boot_ep_b: usize, console_type: ConsoleType) {
    let mut config = INIT_CONFIG.lock();
    for slot in config.boot_regs.iter_mut() {
        if slot.is_none() {
            *slot = Some(BootRegistration { boot_ep_b, console_type });
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

/// Init server kernel task.
/// Polls boot channel endpoints for service discovery requests from user processes.
pub fn init_server() {
    let my_pid = crate::task::current_pid();

    loop {
        // Snapshot boot registrations under the lock
        let mut endpoints = [(0usize, ConsoleType::Serial); MAX_BOOT_REGS];
        let mut count = 0;
        {
            let config = INIT_CONFIG.lock();
            for i in 0..MAX_BOOT_REGS {
                if let Some(ref reg) = config.boot_regs[i] {
                    endpoints[count] = (reg.boot_ep_b, reg.console_type);
                    count += 1;
                }
            }
        }

        // Poll all endpoints without holding the lock
        let mut handled = false;
        for i in 0..count {
            let (boot_ep_b, console_type) = endpoints[i];
            if let Some(msg) = ipc::channel_recv(boot_ep_b) {
                handle_request(boot_ep_b, console_type, &msg, my_pid);
                handled = true;
            }
        }

        if !handled {
            // Register as blocked on ALL boot endpoints so any channel_send wakes us
            for i in 0..count {
                ipc::channel_set_blocked(endpoints[i].0, my_pid);
            }
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}

fn handle_request(boot_ep_b: usize, console_type: ConsoleType, msg: &Message, my_pid: usize) {
    let request = &msg.data[..msg.len];

    if starts_with(request, b"stdio") {
        handle_stdio_request(boot_ep_b, console_type, my_pid);
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

fn handle_stdio_request(boot_ep_b: usize, console_type: ConsoleType, my_pid: usize) {
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
        // Send server endpoint to console server via its control channel
        let mut ctl_msg = Message::new();
        ctl_msg.cap = ipc::encode_cap_channel(server_ep);
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
/// Ignores send errors (channel closed / queue full) since init is best-effort.
fn send_and_wake(endpoint: usize, msg: Message) {
    if let Ok(wake) = ipc::channel_send(endpoint, msg) {
        if wake != 0 { crate::task::wake_process(wake); }
    }
}

fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    &data[..prefix.len()] == prefix
}
