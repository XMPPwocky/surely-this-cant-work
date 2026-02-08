use std::io::{self, Read, Write};

use rvos::raw;
use rvos::Message;
use rvos::UserTransport;
use rvos::rvos_wire;
use rvos::rvos_proto;
use rvos_proto::boot::{BootRequest, BootResponse};
use rvos_proto::math::MathClient;
use rvos_proto::sysinfo::SysinfoCommand;

/// Request a service from the init server via boot channel (handle 0).
fn request_service(name: &str) -> usize {
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&BootRequest::ConnectService { name }, &mut msg.data)
        .unwrap_or(0);
    raw::sys_chan_send(0, &msg);
    let mut reply = Message::new();
    raw::sys_chan_recv_blocking(0, &mut reply);
    match rvos_wire::from_bytes::<BootResponse>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => reply.cap,
        _ => usize::MAX,
    }
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
    println!("  clear                 - Clear screen");
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

fn send_sysinfo_cmd(cmd: &SysinfoCommand) {
    let sysinfo_handle = request_service("sysinfo");
    if sysinfo_handle == usize::MAX {
        println!("Error: could not connect to sysinfo");
        return;
    }

    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(cmd, &mut msg.data).unwrap_or(0);
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

fn cmd_trace(args: &str) {
    let cmd = if args.trim() == "clear" {
        SysinfoCommand::TraceClear {}
    } else {
        SysinfoCommand::Trace {}
    };
    send_sysinfo_cmd(&cmd);
}

fn cmd_ps() {
    send_sysinfo_cmd(&SysinfoCommand::Ps {});
}

fn cmd_mem() {
    send_sysinfo_cmd(&SysinfoCommand::Memstat {});
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

    let math_handle = request_service("math");
    if math_handle == usize::MAX {
        println!("Error: could not connect to math");
        return;
    }

    let mut client = MathClient::new(UserTransport::new(math_handle));
    let result = match parts[0] {
        "add" => client.add(a, b),
        "mul" => client.mul(a, b),
        "sub" => client.sub(a, b),
        _ => {
            println!("Unknown op. Use add, mul, or sub.");
            raw::sys_chan_close(math_handle);
            return;
        }
    };

    match result {
        Ok(resp) => println!("{}", resp.answer),
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
    let mut msg = Message::new();
    msg.len = rvos_wire::to_bytes(&BootRequest::Spawn { path }, &mut msg.data)
        .unwrap_or(0);
    raw::sys_chan_send(0, &msg);

    // Wait for response
    let mut reply = Message::new();
    raw::sys_chan_recv_blocking(0, &mut reply);

    match rvos_wire::from_bytes::<BootResponse>(&reply.data[..reply.len]) {
        Ok(BootResponse::Ok {}) => {}
        Ok(BootResponse::Error { message }) => {
            println!("Spawn failed: {}", message);
            return;
        }
        _ => {
            println!("Spawn failed: bad response");
            return;
        }
    }

    if reply.cap == rvos::NO_CAP {
        println!("Spawn failed: no process handle returned");
        return;
    }

    let proc_handle = reply.cap;

    // Wait for the child process to exit
    let mut exit_msg = Message::new();
    raw::sys_chan_recv_blocking(proc_handle, &mut exit_msg);

    // Parse exit notification
    let exit_code = match rvos_wire::from_bytes::<rvos_proto::process::ExitNotification>(
        &exit_msg.data[..exit_msg.len],
    ) {
        Ok(notif) => notif.exit_code,
        Err(_) => -1,
    };
    println!("Process exited with code {}", exit_code);

    raw::sys_chan_close(proc_handle);
}

// --- Tab completion ---

const COMMANDS: &[&str] = &[
    "cat", "clear", "echo", "help", "ls", "math", "mem",
    "ps", "read", "run", "shutdown", "stat", "trace", "write",
];

enum Completion {
    Single(String, usize),
    Multiple(Vec<String>),
    None,
}

fn try_complete(line: &str) -> Completion {
    let words: Vec<&str> = line.split_whitespace().collect();
    let trailing_space = line.ends_with(' ');

    // Completing first word (command name)
    if words.is_empty() || (words.len() == 1 && !trailing_space) {
        let prefix = words.first().copied().unwrap_or("");
        let matches: Vec<&str> = COMMANDS.iter()
            .copied()
            .filter(|c| c.starts_with(prefix))
            .collect();
        let replace_from = line.len() - prefix.len();
        return match matches.len() {
            0 => Completion::None,
            1 => Completion::Single(matches[0].to_string(), replace_from),
            _ => Completion::Multiple(matches.iter().map(|s| s.to_string()).collect()),
        };
    }

    // Completing argument: file paths for commands that take paths
    let cmd = words[0];
    if matches!(cmd, "run" | "cat" | "read" | "stat" | "ls" | "write") {
        let prefix = if trailing_space { "" } else { words.last().copied().unwrap_or("") };
        let default_dir = if cmd == "run" { "/bin" } else { "/" };

        let (dir, fname_prefix) = if prefix.is_empty() {
            (default_dir, "")
        } else if prefix.starts_with('/') {
            match prefix.rfind('/') {
                Some(0) => ("/", &prefix[1..]),
                Some(pos) => (&prefix[..pos], &prefix[pos + 1..]),
                None => (default_dir, prefix),
            }
        } else {
            (default_dir, prefix)
        };

        let mut matches = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(fname_prefix) {
                    if dir == "/" {
                        matches.push(format!("/{}", name));
                    } else {
                        matches.push(format!("{}/{}", dir, name));
                    }
                }
            }
        }
        matches.sort();

        let replace_from = line.len() - prefix.len();
        return match matches.len() {
            0 => Completion::None,
            1 => Completion::Single(matches.into_iter().next().unwrap(), replace_from),
            _ => Completion::Multiple(matches),
        };
    }

    Completion::None
}

fn handle_tab(buf: &mut String) {
    match try_complete(buf) {
        Completion::Single(text, replace_from) => {
            let old_len = buf.len() - replace_from;
            for _ in 0..old_len {
                print!("\x08 \x08");
            }
            buf.truncate(replace_from);
            buf.push_str(&text);
            buf.push(' ');
            print!("{} ", text);
            io::stdout().flush().ok();
        }
        Completion::Multiple(matches) => {
            print!("\r\n");
            for m in &matches {
                print!("{}  ", m);
            }
            print!("\r\nrvos> {}", buf);
            io::stdout().flush().ok();
        }
        Completion::None => {}
    }
}

// --- Console raw mode control ---

fn set_raw_mode(enable: bool) {
    io::stdout().flush().ok();
    io::stdout().write_all(&[0, if enable { 1 } else { 0 }]).ok();
    io::stdout().flush().ok();
}

// --- Main shell loop ---

pub fn run() {
    println!("\nrvOS shell v0.1");
    println!("Type 'help' for available commands.\n");

    set_raw_mode(true);

    let mut buf = String::new();
    let mut byte = [0u8; 1];

    loop {
        print!("rvos> ");
        io::stdout().flush().ok();
        buf.clear();

        loop {
            if io::stdin().lock().read(&mut byte).unwrap_or(0) == 0 {
                continue;
            }
            match byte[0] {
                b'\r' | b'\n' => {
                    print!("\r\n");
                    io::stdout().flush().ok();
                    break;
                }
                0x7F | 0x08 => {
                    if !buf.is_empty() {
                        buf.pop();
                        print!("\x08 \x08");
                        io::stdout().flush().ok();
                    }
                }
                0x09 => handle_tab(&mut buf),
                0x03 => {
                    print!("^C\r\n");
                    io::stdout().flush().ok();
                    buf.clear();
                    break;
                }
                ch if ch >= 0x20 && ch < 0x7F => {
                    buf.push(ch as char);
                    io::stdout().write_all(&[ch]).ok();
                    io::stdout().flush().ok();
                }
                _ => {}
            }
        }

        let line = buf.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let cmd = line.split_whitespace().next().unwrap_or("");
        match cmd {
            "echo" => cmd_echo(&line),
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
            "clear" => {
                print!("\x1b[2J\x1b[H");
                io::stdout().flush().ok();
            }
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
