use crate::ipc::{self, Message};
use crate::sync::SpinLock;

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

const MAX_BOOT_REGS: usize = 8;
const MAX_SERVICES: usize = 4;

struct InitConfig {
    boot_regs: [Option<BootRegistration>; MAX_BOOT_REGS],
    services: [Option<ServiceEntry>; MAX_SERVICES],
}

impl InitConfig {
    const fn new() -> Self {
        InitConfig {
            boot_regs: [const { None }; MAX_BOOT_REGS],
            services: [const { None }; MAX_SERVICES],
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
        let mut handled = false;
        let config = INIT_CONFIG.lock();

        for i in 0..MAX_BOOT_REGS {
            if let Some(ref reg) = config.boot_regs[i] {
                let boot_ep_b = reg.boot_ep_b;
                let console_type = reg.console_type;
                drop(config); // release lock before IPC operations

                if let Some(msg) = ipc::channel_recv(boot_ep_b) {
                    handle_request(boot_ep_b, console_type, &msg, my_pid);
                    handled = true;
                }

                // Re-acquire lock for next iteration
                break; // must break and restart loop since we dropped the lock
            }
        }

        if !handled {
            crate::task::schedule();
        }
    }
}

fn handle_request(boot_ep_b: usize, console_type: ConsoleType, msg: &Message, my_pid: usize) {
    let request = &msg.data[..msg.len];

    if starts_with(request, b"stdio") {
        handle_stdio_request(boot_ep_b, console_type, my_pid);
    } else if starts_with(request, b"sysinfo") {
        handle_sysinfo_request(boot_ep_b, my_pid);
    } else {
        // Unknown request - send error response
        let mut resp = Message::new();
        let err = b"unknown";
        resp.data[..err.len()].copy_from_slice(err);
        resp.len = err.len();
        resp.sender_pid = my_pid;
        let wake = ipc::channel_send(boot_ep_b, resp);
        if wake != 0 { crate::task::wake_process(wake); }
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
        ctl_msg.cap = server_ep;
        ctl_msg.sender_pid = my_pid;
        let wake = ipc::channel_send(ctl_ep, ctl_msg);
        if wake != 0 { crate::task::wake_process(wake); }

        // Respond to client with client endpoint as capability
        let mut resp = Message::new();
        resp.cap = client_ep;
        resp.sender_pid = my_pid;
        let ok = b"ok";
        resp.data[..ok.len()].copy_from_slice(ok);
        resp.len = ok.len();
        let wake = ipc::channel_send(boot_ep_b, resp);
        if wake != 0 { crate::task::wake_process(wake); }
    }
}

fn handle_sysinfo_request(boot_ep_b: usize, my_pid: usize) {
    // Create a channel pair for client <-> sysinfo service
    let (client_ep, server_ep) = ipc::channel_create_pair();

    // Find the sysinfo control endpoint
    let _control_ep: Option<usize> = None; // sysinfo uses dedicated static

    // For sysinfo, we use a dedicated static endpoint
    let sysinfo_ctl = SYSINFO_CONTROL_EP.load(core::sync::atomic::Ordering::Relaxed);
    if sysinfo_ctl != usize::MAX {
        // Send server endpoint to sysinfo
        let mut ctl_msg = Message::new();
        ctl_msg.cap = server_ep;
        ctl_msg.sender_pid = my_pid;
        let wake = ipc::channel_send(sysinfo_ctl, ctl_msg);
        if wake != 0 { crate::task::wake_process(wake); }

        // Respond to client with client endpoint
        let mut resp = Message::new();
        resp.cap = client_ep;
        resp.sender_pid = my_pid;
        let ok = b"ok";
        resp.data[..ok.len()].copy_from_slice(ok);
        resp.len = ok.len();
        let wake = ipc::channel_send(boot_ep_b, resp);
        if wake != 0 { crate::task::wake_process(wake); }
    }
}

/// Sysinfo service control endpoint (set by kmain)
static SYSINFO_CONTROL_EP: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(usize::MAX);

pub fn set_sysinfo_control_ep(ep: usize) {
    SYSINFO_CONTROL_EP.store(ep, core::sync::atomic::Ordering::Relaxed);
}

fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    &data[..prefix.len()] == prefix
}
