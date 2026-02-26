extern crate rvos_rt;

use std::io::Write;
use rvos::raw;
use rvos::rvos_wire;
use rvos_proto::debug::*;
use rvos_proto::fs::{FileRequest, FileResponse, FileOffset};

// Register name table
const REG_NAMES: [&str; 33] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
    "pc",
];

fn reg_index(name: &str) -> Option<u8> {
    // Check named registers
    for (i, &n) in REG_NAMES.iter().enumerate() {
        if name.eq_ignore_ascii_case(n) {
            return Some(i as u8);
        }
    }
    // Also accept "fp" as alias for s0
    if name.eq_ignore_ascii_case("fp") {
        return Some(8);
    }
    // Also accept x0-x31
    if let Some(rest) = name.strip_prefix('x') {
        if let Ok(n) = rest.parse::<u8>() {
            if n < 32 {
                return Some(n);
            }
        }
    }
    // Also accept "sepc" for PC
    if name.eq_ignore_ascii_case("sepc") {
        return Some(32);
    }
    None
}

fn parse_hex(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

struct Debugger {
    session_client: Option<DebugSessionClient<rvos::UserTransport>>,
    event_handle: Option<usize>,
}

impl Debugger {
    fn new() -> Self {
        Debugger {
            session_client: None,
            event_handle: None,
        }
    }

    fn is_attached(&self) -> bool {
        self.session_client.is_some()
    }

    fn attach(&mut self, pid: u32) {
        if self.is_attached() {
            println!("Already attached. Detach first.");
            return;
        }

        // Connect to process-debug service
        let svc = match rvos::connect_to_service("process-debug") {
            Ok(ch) => ch,
            Err(_) => {
                println!("Failed to connect to process-debug service");
                return;
            }
        };

        let svc_handle = svc.into_raw_handle();

        // Send DebugAttachRequest
        let req = DebugAttachRequest { pid };
        let mut msg = rvos::Message::new();
        msg.len = rvos_wire::to_bytes(&req, &mut msg.data).unwrap_or(0);
        let ret = raw::sys_chan_send_blocking(svc_handle, &msg);
        if ret != 0 {
            println!("Failed to send attach request");
            raw::syscall1(raw::SYS_CHAN_CLOSE, svc_handle);
            return;
        }

        // Receive response
        let mut resp_msg = rvos::Message::new();
        let ret = raw::sys_chan_recv_blocking(svc_handle, &mut resp_msg);
        if ret != 0 {
            println!("Failed to receive attach response");
            raw::syscall1(raw::SYS_CHAN_CLOSE, svc_handle);
            return;
        }

        // Decode response
        let resp: DebugAttachResponse = match rvos_wire::from_bytes_with_caps(
            &resp_msg.data[..resp_msg.len],
            &resp_msg.caps[..resp_msg.cap_count],
        ) {
            Ok(r) => r,
            Err(_) => {
                println!("Bad response from service");
                raw::syscall1(raw::SYS_CHAN_CLOSE, svc_handle);
                return;
            }
        };

        match resp {
            DebugAttachResponse::Ok { session, events } => {
                let transport = rvos::UserTransport::new(session.raw());
                self.session_client = Some(DebugSessionClient::new(transport));
                self.event_handle = Some(events.raw());
                println!("Attached to PID {}", pid);
            }
            DebugAttachResponse::Error { code } => {
                let msg = match code {
                    DebugError::NotFound {} => "process not found",
                    DebugError::AlreadyAttached {} => "already attached by another debugger",
                    DebugError::NotAUserProcess {} => "not a user process",
                    DebugError::NoResources {} => "no resources",
                };
                println!("Attach failed: {}", msg);
            }
        }

        // Close the control channel (no longer needed)
        raw::syscall1(raw::SYS_CHAN_CLOSE, svc_handle);
    }

    fn detach(&mut self) {
        if let Some(client) = self.session_client.take() {
            let transport = client.into_inner();
            raw::syscall1(raw::SYS_CHAN_CLOSE, transport.handle());
        }
        if let Some(h) = self.event_handle.take() {
            raw::syscall1(raw::SYS_CHAN_CLOSE, h);
        }
        println!("Detached.");
    }

    fn cmd_suspend(&mut self) {
        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.suspend() {
            Ok(SessionResponse::Ok {}) => println!("Suspend requested (waiting for event...)"),
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_resume(&mut self) {
        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.resume() {
            Ok(SessionResponse::Ok {}) => println!("Resumed."),
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_regs(&mut self) {
        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.read_registers() {
            Ok(SessionResponse::Registers { data: reg_data }) => {
                if reg_data.len() < 264 {
                    println!("Incomplete register data");
                    return;
                }
                let pc = u64::from_le_bytes(reg_data[0..8].try_into().unwrap());
                println!("  pc  = {:#018x}", pc);
                println!();
                for (i, name) in REG_NAMES.iter().enumerate().take(32) {
                    let off = 8 + i * 8;
                    let val = u64::from_le_bytes(
                        reg_data[off..off + 8].try_into().unwrap(),
                    );
                    print!("  {:4} = {:#018x}", name, val);
                    if i % 4 == 3 {
                        println!();
                    }
                }
            }
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_setreg(&mut self, name: &str, val_str: &str) {
        let reg = match reg_index(name) {
            Some(r) => r,
            None => {
                println!("Unknown register: {}", name);
                return;
            }
        };
        let value = match parse_hex(val_str) {
            Some(v) => v,
            None => {
                println!("Bad hex value: {}", val_str);
                return;
            }
        };

        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.write_register(reg, value) {
            Ok(SessionResponse::Ok {}) => {
                println!("Set {} = {:#x}", REG_NAMES[reg as usize], value);
            }
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_mem(&mut self, addr_str: &str, len_str: Option<&str>) {
        let addr = match parse_hex(addr_str) {
            Some(a) => a,
            None => {
                println!("Bad hex address: {}", addr_str);
                return;
            }
        };
        let len: u32 = match len_str {
            Some(s) => s.parse().unwrap_or(64),
            None => 64,
        };
        let len = len.min(512);

        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.read_memory(addr, len) {
            Ok(SessionResponse::Memory { data: mem }) => {
                hex_dump(addr, mem);
            }
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_write(&mut self, addr_str: &str, hex_str: &str) {
        let addr = match parse_hex(addr_str) {
            Some(a) => a,
            None => {
                println!("Bad hex address: {}", addr_str);
                return;
            }
        };
        let bytes = match parse_hex_bytes(hex_str) {
            Some(b) => b,
            None => {
                println!("Bad hex data: {}", hex_str);
                return;
            }
        };

        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.write_memory(addr, &bytes) {
            Ok(SessionResponse::Ok {}) => {
                println!("Wrote {} bytes at {:#x}", bytes.len(), addr);
            }
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_breakpoint(&mut self, addr_str: &str) {
        let addr = match parse_hex(addr_str) {
            Some(a) => a,
            None => {
                println!("Bad hex address: {}", addr_str);
                return;
            }
        };

        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.set_breakpoint(addr) {
            Ok(SessionResponse::Ok {}) => println!("Breakpoint set at {:#x}", addr),
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_clear(&mut self, addr_str: &str) {
        let addr = match parse_hex(addr_str) {
            Some(a) => a,
            None => {
                println!("Bad hex address: {}", addr_str);
                return;
            }
        };

        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.clear_breakpoint(addr) {
            Ok(SessionResponse::Ok {}) => println!("Breakpoint cleared at {:#x}", addr),
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_backtrace(&mut self) {
        let client = match self.session_client.as_mut() {
            Some(c) => c,
            None => { println!("Not attached."); return; }
        };
        match client.backtrace() {
            Ok(SessionResponse::Backtrace { frames }) => {
                if frames.is_empty() {
                    println!("  (no frames)");
                    return;
                }
                let count = frames.len() / 16;
                for i in 0..count {
                    let off = i * 16;
                    let ra =
                        u64::from_le_bytes(frames[off..off + 8].try_into().unwrap());
                    let fp = u64::from_le_bytes(
                        frames[off + 8..off + 16].try_into().unwrap(),
                    );
                    println!("  #{}: ra={:#x} fp={:#x}", i, ra, fp);
                }
            }
            Ok(SessionResponse::Error { message }) => println!("Error: {}", message),
            Ok(_) => println!("Unexpected response"),
            Err(e) => println!("RPC error: {:?}", e),
        }
    }

    fn cmd_spawn(&mut self, path: &str) {
        if self.is_attached() {
            println!("Already attached. Detach first.");
            return;
        }

        // Spawn the process in suspended state
        let handle = match rvos::spawn_process_suspended(path) {
            Ok(h) => h,
            Err(_) => {
                println!("Failed to spawn '{}'", path);
                return;
            }
        };

        // Read ProcessStarted to get the PID
        let handle_raw = handle.raw_handle();
        let mut msg = rvos::Message::new();
        if raw::sys_chan_recv_blocking(handle_raw, &mut msg) != 0 {
            println!("Failed to receive ProcessStarted");
            return;
        }
        let started: rvos_proto::process::ProcessStarted =
            match rvos_wire::from_bytes(&msg.data[..msg.len]) {
                Ok(s) => s,
                Err(_) => {
                    println!("Bad ProcessStarted response");
                    return;
                }
            };
        let pid = started.pid;
        println!("Spawned '{}' as PID {} (suspended)", path, pid);

        // Attach to the suspended process
        self.attach(pid);

        // Store the process handle so we get exit notification later.
        // The handle channel stays open; events will be polled naturally.
        // We leak the handle intentionally — it will be closed on dbg exit.
        core::mem::forget(handle);
    }

    fn poll_events(&mut self) {
        let event_h = match self.event_handle {
            Some(h) => h,
            None => return,
        };

        loop {
            let mut msg = rvos::Message::new();
            if raw::sys_chan_recv(event_h, &mut msg) != 0 {
                break;
            }
            if let Ok(event) = rvos_wire::from_bytes::<DebugEvent>(&msg.data[..msg.len]) {
                match event {
                    DebugEvent::BreakpointHit { addr } => {
                        println!("\n[event] Breakpoint hit at {:#x}", addr);
                    }
                    DebugEvent::Suspended {} => {
                        println!("\n[event] Process suspended");
                    }
                    DebugEvent::ProcessExited { exit_code } => {
                        println!("\n[event] Process exited (code={})", exit_code);
                        // Don't auto-detach here, let user do it explicitly
                    }
                }
            }
        }
    }
}

fn hex_dump(base_addr: u64, data: &[u8]) {
    let mut offset = 0;
    while offset < data.len() {
        print!("  {:08x}: ", base_addr + offset as u64);
        let line_len = (data.len() - offset).min(16);
        for i in 0..16 {
            if i < line_len {
                print!("{:02x} ", data[offset + i]);
            } else {
                print!("   ");
            }
            if i == 7 {
                print!(" ");
            }
        }
        print!(" |");
        for i in 0..line_len {
            let b = data[offset + i];
            if (0x20..0x7f).contains(&b) {
                print!("{}", b as char);
            } else {
                print!(".");
            }
        }
        println!("|");
        offset += 16;
    }
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
        i += 2;
    }
    Some(bytes)
}

fn print_help() {
    println!("Commands:");
    println!("  attach <pid>         Attach to a process");
    println!("  spawn <path>         Spawn a process suspended and attach");
    println!("  detach               Detach from current process");
    println!("  suspend / s          Suspend the target process");
    println!("  continue / c         Resume execution");
    println!("  regs                 Display all registers");
    println!("  setreg <name> <val>  Set a register (e.g. setreg a0 0x42)");
    println!("  mem <addr> [len]     Read memory (hex dump)");
    println!("  write <addr> <hex>   Write hex bytes to memory");
    println!("  break <addr>         Set breakpoint at address");
    println!("  clear <addr>         Clear breakpoint at address");
    println!("  bt                   Show backtrace");
    println!("  help                 Show this help");
    println!("  quit / q             Exit debugger");
}

/// Read a line from stdin while also polling for debug events.
/// Uses a Reactor to multiplex stdin and event channels,
/// so events are printed immediately instead of waiting for user input.
fn read_line_with_events(stdin_h: usize, dbg: &mut Debugger) -> Option<String> {
    // Send a FileRequest::Read to stdin
    let mut req_msg = rvos::Message::new();
    req_msg.len = rvos_wire::to_bytes(&FileRequest::Read {
        offset: FileOffset::Stream {},
        len: 1024,
    }, &mut req_msg.data).unwrap_or(0);
    if raw::sys_chan_send_blocking(stdin_h, &req_msg) != 0 {
        return None;
    }

    // Poll both stdin and event channel until stdin has data
    let mut reactor = rvos::Reactor::new();
    reactor.add(stdin_h);
    if let Some(eh) = dbg.event_handle {
        reactor.add(eh);
    }
    loop {
        reactor.poll_and_block();

        // Drain debug events first
        dbg.poll_events();

        // Try to receive stdin response (non-blocking)
        let mut resp_msg = rvos::Message::new();
        if raw::sys_chan_recv(stdin_h, &mut resp_msg) != 0 {
            continue; // No stdin data yet, keep polling
        }

        // Parse the FileResponse::Data
        let data = match rvos_wire::from_bytes::<FileResponse>(&resp_msg.data[..resp_msg.len]) {
            Ok(FileResponse::Data { chunk }) if !chunk.is_empty() => chunk.to_vec(),
            _ => return Some(String::new()), // Empty sentinel or error → empty line
        };

        // Drain remaining Data chunks until sentinel (empty Data)
        loop {
            let mut drain_msg = rvos::Message::new();
            if raw::sys_chan_recv_blocking(stdin_h, &mut drain_msg) != 0 {
                break;
            }
            match rvos_wire::from_bytes::<FileResponse>(&drain_msg.data[..drain_msg.len]) {
                Ok(FileResponse::Data { chunk }) if !chunk.is_empty() => continue,
                _ => break,
            }
        }

        return Some(String::from_utf8_lossy(&data).into_owned());
    }
}

fn main() {
    println!("rvOS process debugger");
    println!("Type 'help' for available commands.");
    println!();

    let mut dbg = Debugger::new();
    let stdin_h = std::os::rvos::stdin_handle();

    loop {
        // Print prompt
        if dbg.is_attached() {
            print!("dbg> ");
        } else {
            print!("dbg) ");
        }
        std::io::stdout().flush().ok();

        // Read a line — when attached, poll both stdin and event channels
        let line = if dbg.is_attached() && stdin_h != 0 {
            match read_line_with_events(stdin_h, &mut dbg) {
                Some(l) => l,
                None => break,
            }
        } else {
            let mut line = String::new();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => break,
                _ => {}
            }
            line
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let cmd = parts[0];

        match cmd {
            "help" | "h" | "?" => print_help(),
            "quit" | "q" => {
                if dbg.is_attached() {
                    dbg.detach();
                }
                break;
            }
            "attach" => {
                if parts.len() < 2 {
                    println!("Usage: attach <pid>");
                    continue;
                }
                match parts[1].parse::<u32>() {
                    Ok(pid) => dbg.attach(pid),
                    Err(_) => println!("Bad PID: {}", parts[1]),
                }
            }
            "spawn" => {
                if parts.len() < 2 {
                    println!("Usage: spawn <path>");
                    continue;
                }
                dbg.cmd_spawn(parts[1]);
            }
            "detach" => dbg.detach(),
            "suspend" | "s" => dbg.cmd_suspend(),
            "continue" | "c" => dbg.cmd_resume(),
            "regs" => dbg.cmd_regs(),
            "setreg" => {
                if parts.len() < 3 {
                    println!("Usage: setreg <name> <value>");
                    continue;
                }
                dbg.cmd_setreg(parts[1], parts[2]);
            }
            "mem" => {
                if parts.len() < 2 {
                    println!("Usage: mem <addr> [len]");
                    continue;
                }
                dbg.cmd_mem(parts[1], parts.get(2).copied());
            }
            "write" => {
                if parts.len() < 3 {
                    println!("Usage: write <addr> <hex>");
                    continue;
                }
                dbg.cmd_write(parts[1], parts[2]);
            }
            "break" | "b" => {
                if parts.len() < 2 {
                    println!("Usage: break <addr>");
                    continue;
                }
                dbg.cmd_breakpoint(parts[1]);
            }
            "clear" => {
                if parts.len() < 2 {
                    println!("Usage: clear <addr>");
                    continue;
                }
                dbg.cmd_clear(parts[1]);
            }
            "bt" => dbg.cmd_backtrace(),
            _ => println!("Unknown command: {}. Type 'help' for commands.", cmd),
        }
    }
}
