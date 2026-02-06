use std::io::{self, BufRead, Write};

use crate::syscall::{self, Message};
use rvos_wire::{Deserialize, Reader, Serialize, WireError, Writer};

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
fn request_service(name: &[u8]) -> usize {
    let mut msg = Message::new();
    msg.data[..name.len()].copy_from_slice(name);
    msg.len = name.len();
    syscall::sys_chan_send(0, &msg);
    syscall::sys_chan_recv_blocking(0, &mut msg);
    msg.cap
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
    println!("  echo <text>  - Print text");
    println!("  math <op> <a> <b> - Compute math (add/mul/sub)");
    println!("  ps           - Show process list");
    println!("  help         - Show this help");
    println!("  shutdown     - Shut down the system");
}

fn cmd_ps() {
    let sysinfo_handle = request_service(b"sysinfo");

    let mut msg = Message::new();
    msg.data[0] = b'P';
    msg.data[1] = b'S';
    msg.len = 2;
    syscall::sys_chan_send(sysinfo_handle, &msg);

    loop {
        let mut resp = Message::new();
        syscall::sys_chan_recv_blocking(sysinfo_handle, &mut resp);
        if resp.len == 0 {
            break;
        }
        io::stdout().write_all(&resp.data[..resp.len]).ok();
    }
    io::stdout().flush().ok();

    syscall::sys_chan_close(sysinfo_handle);
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

    let mut msg = Message::new();
    let mut writer = Writer::new(&mut msg.data);
    if op.serialize(&mut writer).is_err() {
        println!("Serialize error");
        syscall::sys_chan_close(math_handle);
        return;
    }
    msg.len = writer.position();
    syscall::sys_chan_send(math_handle, &msg);

    let mut resp = Message::new();
    syscall::sys_chan_recv_blocking(math_handle, &mut resp);

    let mut reader = Reader::new(&resp.data[..resp.len]);
    match MathResponse::deserialize(&mut reader) {
        Ok(r) => println!("{}", r.answer),
        Err(_) => println!("Bad response from math service"),
    }

    syscall::sys_chan_close(math_handle);
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
            "help" => cmd_help(),
            "shutdown" => {
                println!("Shutting down...");
                std::process::exit(0);
            }
            _ => {
                println!("Unknown command: {cmd}");
                println!("Type 'help' for available commands.");
            }
        }
    }
}
