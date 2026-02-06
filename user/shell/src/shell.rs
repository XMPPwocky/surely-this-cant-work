use crate::syscall::{self, Message, NO_CAP};
use rvos_wire::{Serialize, Deserialize, Writer, Reader, WireError};

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
/// Returns the new handle for that service.
fn request_service(boot_handle: usize, name: &[u8]) -> usize {
    let mut msg = Message::new();
    msg.data[..name.len()].copy_from_slice(name);
    msg.len = name.len();
    syscall::sys_chan_send(boot_handle, &msg);
    syscall::sys_chan_recv_blocking(boot_handle, &mut msg);
    msg.cap // the new handle for the service
}

/// Write a string to the console via a channel handle.
fn print_str(handle: usize, s: &str) {
    let bytes = s.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let chunk_len = (bytes.len() - offset).min(64);
        let mut msg = Message::new();
        msg.data[..chunk_len].copy_from_slice(&bytes[offset..offset + chunk_len]);
        msg.len = chunk_len;
        syscall::sys_chan_send(handle, &msg);
        offset += chunk_len;
    }
}

/// Write raw bytes to the console via a channel handle.
fn print_bytes(handle: usize, data: &[u8]) {
    let mut offset = 0;
    while offset < data.len() {
        let chunk_len = (data.len() - offset).min(64);
        let mut msg = Message::new();
        msg.data[..chunk_len].copy_from_slice(&data[offset..offset + chunk_len]);
        msg.len = chunk_len;
        syscall::sys_chan_send(handle, &msg);
        offset += chunk_len;
    }
}

/// Read a line from the console (blocking).
/// Returns the number of bytes read (excluding trailing newline).
fn read_line(handle: usize, buf: &mut [u8]) -> usize {
    let mut msg = Message::new();
    syscall::sys_chan_recv_blocking(handle, &mut msg);
    let len = msg.len.min(buf.len());
    buf[..len].copy_from_slice(&msg.data[..len]);
    // Strip trailing newline
    if len > 0 && buf[len - 1] == b'\n' {
        len - 1
    } else {
        len
    }
}

/// Find the first space in a byte slice. Returns the index or len if not found.
fn find_space(buf: &[u8]) -> usize {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b' ' {
            return i;
        }
        i += 1;
    }
    buf.len()
}

/// Check if a byte slice starts with a given prefix.
fn starts_with(buf: &[u8], prefix: &[u8]) -> bool {
    if buf.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if buf[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Check if two byte slices are equal.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    starts_with(a, b)
}

fn cmd_echo(stdio: usize, line: &[u8]) {
    // Skip "echo" and the space after it
    if line.len() > 5 {
        print_bytes(stdio, &line[5..]);
    }
    print_str(stdio, "\n");
}

fn cmd_help(stdio: usize) {
    print_str(stdio, "Available commands:\n");
    print_str(stdio, "  echo <text>  - Print text\n");
    print_str(stdio, "  math <op> <a> <b> - Compute math (add/mul/sub)\n");
    print_str(stdio, "  ps           - Show process list\n");
    print_str(stdio, "  help         - Show this help\n");
    print_str(stdio, "  shutdown     - Shut down the system\n");
}

fn cmd_ps(stdio: usize, boot_handle: usize) {
    // Request sysinfo service from init server
    let sysinfo_handle = request_service(boot_handle, b"sysinfo");

    // Send PS command
    let mut msg = Message::new();
    msg.data[0] = b'P';
    msg.data[1] = b'S';
    msg.len = 2;
    syscall::sys_chan_send(sysinfo_handle, &msg);

    // Receive multi-part response (blocking)
    loop {
        let mut resp = Message::new();
        syscall::sys_chan_recv_blocking(sysinfo_handle, &mut resp);
        if resp.len == 0 {
            break; // Sentinel: end of response
        }
        print_bytes(stdio, &resp.data[..resp.len]);
    }

    syscall::sys_chan_close(sysinfo_handle);
}

/// Parse a decimal u32 from a byte slice. Returns None on invalid input.
fn parse_u32(buf: &[u8]) -> Option<u32> {
    if buf.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    let mut i = 0;
    while i < buf.len() {
        let c = buf[i];
        if c < b'0' || c > b'9' {
            return None;
        }
        let digit = (c - b'0') as u32;
        result = match result.checked_mul(10) {
            Some(v) => match v.checked_add(digit) {
                Some(v) => v,
                None => return None,
            },
            None => return None,
        };
        i += 1;
    }
    Some(result)
}

/// Convert a u32 to a decimal string in the provided buffer. Returns the slice.
fn u32_to_str(val: u32, buf: &mut [u8; 10]) -> &[u8] {
    if val == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut v = val;
    let mut i = 10;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[i..]
}

fn cmd_math(stdio: usize, boot_handle: usize, args: &[u8]) {
    // Parse: "add 3 5" -> op="add", a=3, b=5
    let op_end = find_space(args);
    let op_name = &args[..op_end];

    if op_end >= args.len() {
        print_str(stdio, "Usage: math <add|mul|sub> <a> <b>\n");
        return;
    }

    let rest = &args[op_end + 1..];
    let a_end = find_space(rest);
    if a_end >= rest.len() {
        print_str(stdio, "Usage: math <add|mul|sub> <a> <b>\n");
        return;
    }

    let a_str = &rest[..a_end];
    let b_str = &rest[a_end + 1..];

    let a = match parse_u32(a_str) {
        Some(v) => v,
        None => {
            print_str(stdio, "Invalid number\n");
            return;
        }
    };
    let b = match parse_u32(b_str) {
        Some(v) => v,
        None => {
            print_str(stdio, "Invalid number\n");
            return;
        }
    };

    let op = if bytes_eq(op_name, b"add") {
        MathOp::Add(a, b)
    } else if bytes_eq(op_name, b"mul") {
        MathOp::Mul(a, b)
    } else if bytes_eq(op_name, b"sub") {
        MathOp::Sub(a, b)
    } else {
        print_str(stdio, "Unknown op. Use add, mul, or sub.\n");
        return;
    };

    // Request math service from init
    let math_handle = request_service(boot_handle, b"math");

    // Serialize MathOp and send
    let mut msg = Message::new();
    let mut writer = Writer::new(&mut msg.data);
    if op.serialize(&mut writer).is_err() {
        print_str(stdio, "Serialize error\n");
        syscall::sys_chan_close(math_handle);
        return;
    }
    msg.len = writer.position();
    syscall::sys_chan_send(math_handle, &msg);

    // Receive response
    let mut resp = Message::new();
    syscall::sys_chan_recv_blocking(math_handle, &mut resp);

    // Deserialize MathResponse
    let mut reader = Reader::new(&resp.data[..resp.len]);
    match MathResponse::deserialize(&mut reader) {
        Ok(r) => {
            let mut num_buf = [0u8; 10];
            let s = u32_to_str(r.answer, &mut num_buf);
            print_bytes(stdio, s);
            print_str(stdio, "\n");
        }
        Err(_) => {
            print_str(stdio, "Bad response from math service\n");
        }
    }

    syscall::sys_chan_close(math_handle);
}

#[no_mangle]
pub extern "C" fn shell_main() {
    // Request stdio from init server via boot channel (handle 0)
    let stdio = request_service(0, b"stdio");

    print_str(stdio, "\nrvOS shell v0.1\n");
    print_str(stdio, "Type 'help' for available commands.\n\n");

    let mut line_buf = [0u8; 256];

    loop {
        print_str(stdio, "rvos> ");
        let len = read_line(stdio, &mut line_buf);

        if len == 0 {
            continue;
        }

        let line = &line_buf[..len];

        // Find where the command word ends
        let cmd_end = find_space(line);
        let cmd = &line[..cmd_end];

        if bytes_eq(cmd, b"echo") {
            cmd_echo(stdio, line);
        } else if bytes_eq(cmd, b"math") {
            if cmd_end < line.len() {
                cmd_math(stdio, 0, &line[cmd_end + 1..]);
            } else {
                print_str(stdio, "Usage: math <add|mul|sub> <a> <b>\n");
            }
        } else if bytes_eq(cmd, b"ps") {
            cmd_ps(stdio, 0);
        } else if bytes_eq(cmd, b"help") {
            cmd_help(stdio);
        } else if bytes_eq(cmd, b"shutdown") {
            print_str(stdio, "Shutting down...\n");
            syscall::sys_exit(0);
        } else {
            print_str(stdio, "Unknown command: ");
            print_bytes(stdio, cmd);
            print_str(stdio, "\nType 'help' for available commands.\n");
        }
    }
}
