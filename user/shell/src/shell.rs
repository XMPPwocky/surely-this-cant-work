use std::io::{self, BufRead, Write};

use rvos::raw;
use rvos::Message;
use rvos::rvos_wire::{Deserialize, Reader, Serialize, WireError, Writer};

// --- Math protocol types ---

enum MathOp {
    Add(u32, u32),
    Mul(u32, u32),
    Sub(u32, u32),
}

struct MathResponse {
    answer: u32,
}

impl Serialize for MathOp {
    fn serialize(&self, w: &mut Writer) -> Result<(), WireError> {
        match self {
            MathOp::Add(a, b) => { w.write_u8(0)?; w.write_u32(*a)?; w.write_u32(*b) }
            MathOp::Mul(a, b) => { w.write_u8(1)?; w.write_u32(*a)?; w.write_u32(*b) }
            MathOp::Sub(a, b) => { w.write_u8(2)?; w.write_u32(*a)?; w.write_u32(*b) }
        }
    }
}

impl<'a> Deserialize<'a> for MathResponse {
    fn deserialize(r: &mut Reader<'a>) -> Result<Self, WireError> {
        Ok(MathResponse { answer: r.read_u32()? })
    }
}

/// Request a service from the init server via boot channel (handle 0).
/// Uses the boot channel protocol (rvos-wire tagged format).
fn request_service(name: &[u8]) -> usize {
    let msg = Message::build(rvos::NO_CAP, |w| {
        let _ = w.write_u8(0); // tag: ConnectService
        let _ = w.write_bytes(name);
    });
    raw::sys_chan_send(0, &msg);
    let mut reply = Message::new();
    raw::sys_chan_recv_blocking(0, &mut reply);
    // Parse response: u8(tag). Tag 0 = Ok, 1 = Error.
    let mut r = reply.reader();
    let tag = r.read_u8().unwrap_or(1);
    if tag != 0 {
        return usize::MAX; // error
    }
    reply.cap
}

fn cmd_echo(line: &str) {
    if line.len() > 5 {
        println!("{}", &line[5..]);
    } else {
        println!();
    }
}

fn cmd_help() {
    println!("Available commands:");
    println!("  echo <text>           - Print text");
    println!("  math <op> <a> <b>     - Compute math (add/mul/sub)");
    println!("  ps                    - Show process list");
    println!("  mem                   - Show kernel memory stats");
    println!("  trace                 - Show trace ring buffer");
    println!("  trace clear           - Clear trace ring buffer");
    println!("  ls [path]             - List directory");
    println!("  cat <path>            - Read file");
    println!("  write <path> <text>   - Write to file");
    println!("  stat <path>           - Show file metadata");
    println!("  run <path>            - Run a program and wait for it to exit");
    println!("  help                  - Show this help");
    println!("  shutdown              - Shut down the system");
}

fn cmd_cat(args: &str) {
    let path = args.trim();
    if path.is_empty() {
        println!("Usage: cat <path>");
        return;
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => print!("{}", contents),
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_write(args: &str) {
    let args = args.trim();
    let (path, content) = match args.split_once(' ') {
        Some((p, c)) => (p, c),
        None => {
            println!("Usage: write <path> <content>");
            return;
        }
    };
    // Strip surrounding quotes if present
    let content = if content.starts_with('"') && content.ends_with('"') && content.len() >= 2 {
        &content[1..content.len() - 1]
    } else {
        content
    };
    match std::fs::write(path, content) {
        Ok(()) => println!("Wrote {} bytes to {}", content.len(), path),
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_ls(args: &str) {
    let path = if args.is_empty() { "/" } else { args.trim() };
    match std::fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => {
                        let kind = if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                            "dir "
                        } else {
                            "file"
                        };
                        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                        println!("  {} {:>5}  {}", kind, size, e.file_name().to_string_lossy());
                    }
                    Err(e) => println!("  Error: {}", e),
                }
            }
        }
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_stat(args: &str) {
    let path = args.trim();
    if path.is_empty() {
        println!("Usage: stat <path>");
        return;
    }
    match std::fs::metadata(path) {
        Ok(meta) => {
            let kind = if meta.is_dir() { "directory" } else { "file" };
            println!("  Type: {}", kind);
            println!("  Size: {} bytes", meta.len());
        }
        Err(e) => println!("Error: {}", e),
    }
}

fn cmd_trace(args: &str) {
    let sysinfo_handle = request_service(b"sysinfo");
    if sysinfo_handle == usize::MAX {
        println!("Error: could not connect to sysinfo");
        return;
    }

    let cmd_str = if args.trim() == "clear" { b"TRACECLR" as &[u8] } else { b"TRACE" as &[u8] };
    let mut msg = Message::new();
    msg.data[..cmd_str.len()].copy_from_slice(cmd_str);
    msg.len = cmd_str.len();
    raw::sys_chan_send(sysinfo_handle, &msg);

    loop {
        let mut resp = Message::new();
        raw::sys_chan_recv_blocking(sysinfo_handle, &mut resp);
        if resp.len == 0 {
            break;
        }
        io::stdout().write_all(&resp.data[..resp.len]).ok();
    }
    io::stdout().flush().ok();

    raw::sys_chan_close(sysinfo_handle);
}

fn cmd_ps() {
    let sysinfo_handle = request_service(b"sysinfo");
    if sysinfo_handle == usize::MAX {
        println!("Error: could not connect to sysinfo");
        return;
    }

    let mut msg = Message::new();
    msg.data[0] = b'P';
    msg.data[1] = b'S';
    msg.len = 2;
    raw::sys_chan_send(sysinfo_handle, &msg);

    loop {
        let mut resp = Message::new();
        raw::sys_chan_recv_blocking(sysinfo_handle, &mut resp);
        if resp.len == 0 {
            break;
        }
        io::stdout().write_all(&resp.data[..resp.len]).ok();
    }
    io::stdout().flush().ok();

    raw::sys_chan_close(sysinfo_handle);
}

fn cmd_mem() {
    let sysinfo_handle = request_service(b"sysinfo");
    if sysinfo_handle == usize::MAX {
        println!("Error: could not connect to sysinfo");
        return;
    }

    let mut msg = Message::new();
    let cmd = b"MEMSTAT";
    msg.data[..cmd.len()].copy_from_slice(cmd);
    msg.len = cmd.len();
    raw::sys_chan_send(sysinfo_handle, &msg);

    loop {
        let mut resp = Message::new();
        raw::sys_chan_recv_blocking(sysinfo_handle, &mut resp);
        if resp.len == 0 {
            break;
        }
        io::stdout().write_all(&resp.data[..resp.len]).ok();
    }
    io::stdout().flush().ok();

    raw::sys_chan_close(sysinfo_handle);
}

fn cmd_math(args: &str) {
    let parts: Vec<&str> = args.splitn(3, ' ').collect();
    if parts.len() < 3 {
        println!("Usage: math <add|mul|sub> <a> <b>");
        return;
    }

    let a: u32 = match parts[1].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Invalid number");
            return;
        }
    };
    let b: u32 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => {
            println!("Invalid number");
            return;
        }
    };

    let op = match parts[0] {
        "add" => MathOp::Add(a, b),
        "mul" => MathOp::Mul(a, b),
        "sub" => MathOp::Sub(a, b),
        _ => {
            println!("Unknown op. Use add, mul, or sub.");
            return;
        }
    };

    let math_handle = request_service(b"math");
    if math_handle == usize::MAX {
        println!("Error: could not connect to math");
        return;
    }

    let mut msg = Message::new();
    let mut writer = Writer::new(&mut msg.data);
    if op.serialize(&mut writer).is_err() {
        println!("Serialize error");
        raw::sys_chan_close(math_handle);
        return;
    }
    msg.len = writer.position();
    raw::sys_chan_send(math_handle, &msg);

    let mut resp = Message::new();
    raw::sys_chan_recv_blocking(math_handle, &mut resp);

    let mut reader = Reader::new(&resp.data[..resp.len]);
    match MathResponse::deserialize(&mut reader) {
        Ok(r) => println!("{}", r.answer),
        Err(_) => println!("Bad response from math service"),
    }

    raw::sys_chan_close(math_handle);
}

fn cmd_run(args: &str) {
    let path = args.trim();
    if path.is_empty() {
        println!("Usage: run <path>");
        return;
    }

    // Send Spawn request on boot channel (handle 0)
    let msg = Message::build(rvos::NO_CAP, |w| {
        let _ = w.write_u8(1); // tag: Spawn
        let _ = w.write_str(path);
    });
    raw::sys_chan_send(0, &msg);

    // Wait for response
    let mut reply = Message::new();
    raw::sys_chan_recv_blocking(0, &mut reply);

    let mut r = reply.reader();
    let tag = r.read_u8().unwrap_or(1);
    if tag != 0 {
        // Error response
        let err_msg = r.read_str().unwrap_or("unknown error");
        println!("Spawn failed: {}", err_msg);
        return;
    }

    if reply.cap == rvos::NO_CAP {
        println!("Spawn failed: no process handle returned");
        return;
    }

    let proc_handle = reply.cap;

    // Wait for the child process to exit
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);

    // Parse exit notification: i32(exit_code)
    let mut r = Reader::new(&exit_msg.data[..exit_msg.len]);
    let exit_code = r.read_i32().unwrap_or(-1);
    println!("Process exited with code {}", exit_code);

    raw::sys_chan_close(proc_handle);
}

pub fn run() {
    println!("\nrvOS shell v0.1");
    println!("Type 'help' for available commands.\n");

    let stdin = io::stdin();
    let mut line = String::new();

    loop {
        print!("rvos> ");
        io::stdout().flush().ok();

        line.clear();
        if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
            continue;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let cmd = line.split_whitespace().next().unwrap_or("");

        match cmd {
            "echo" => cmd_echo(line),
            "math" => {
                if let Some(args) = line.strip_prefix("math ") {
                    cmd_math(args);
                } else {
                    println!("Usage: math <add|mul|sub> <a> <b>");
                }
            }
            "ps" => cmd_ps(),
            "mem" => cmd_mem(),
            "trace" => {
                let args = line.splitn(2, ' ').nth(1).unwrap_or("");
                cmd_trace(args);
            }
            "cat" | "read" => {
                let args = line.splitn(2, ' ').nth(1).unwrap_or("");
                cmd_cat(args);
            }
            "write" => {
                let args = line.splitn(2, ' ').nth(1).unwrap_or("");
                cmd_write(args);
            }
            "ls" => {
                let args = line.splitn(2, ' ').nth(1).unwrap_or("");
                cmd_ls(args);
            }
            "stat" => {
                let args = line.splitn(2, ' ').nth(1).unwrap_or("");
                cmd_stat(args);
            }
            "run" => {
                let args = line.splitn(2, ' ').nth(1).unwrap_or("");
                cmd_run(args);
            }
            "help" => cmd_help(),
            "shutdown" => {
                println!("Shutting down...");
                raw::sys_shutdown();
            }
            _ => {
                println!("Unknown command: {cmd}");
                println!("Type 'help' for available commands.");
            }
        }
    }
}
