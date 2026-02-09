use crate::ipc::{self, Message, MAX_MSG_SIZE};
use crate::drivers::tty;
use core::sync::atomic::{AtomicUsize, Ordering};
use rvos_wire::{Reader, Writer};

/// Control endpoint for serial console server (set by kmain before spawn)
static SERIAL_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_serial_control_ep(ep: usize) {
    SERIAL_CONTROL_EP.store(ep, Ordering::Relaxed);
}

const LINE_BUF_SIZE: usize = 256;

/// Line discipline state for a console
struct LineDiscipline {
    line_buf: [u8; LINE_BUF_SIZE],
    line_len: usize,
}

impl LineDiscipline {
    const fn new() -> Self {
        LineDiscipline {
            line_buf: [0; LINE_BUF_SIZE],
            line_len: 0,
        }
    }

    /// Process a character. Returns Some(slice_len) when a complete line is ready.
    fn push_char(&mut self, ch: u8) -> Option<usize> {
        match ch {
            0x7F | 0x08 => {
                // Backspace
                if self.line_len > 0 {
                    self.line_len -= 1;
                }
                None
            }
            b'\r' | b'\n' => {
                // Enter: line is complete
                if self.line_len < LINE_BUF_SIZE {
                    self.line_buf[self.line_len] = b'\n';
                    self.line_len += 1;
                }
                let result_len = self.line_len;
                self.line_len = 0;
                Some(result_len)
            }
            ch if ch >= 0x20 && ch < 0x7F => {
                if self.line_len < LINE_BUF_SIZE - 1 {
                    self.line_buf[self.line_len] = ch;
                    self.line_len += 1;
                }
                None
            }
            _ => None,
        }
    }

    fn line_data(&self, len: usize) -> &[u8] {
        &self.line_buf[..len]
    }
}

/// Echo a character to UART.
fn echo_serial(ch: u8) {
    match ch {
        0x7F | 0x08 => {
            tty::raw_uart_putchar(0x08);
            tty::raw_uart_putchar(b' ');
            tty::raw_uart_putchar(0x08);
        }
        b'\r' | b'\n' => {
            tty::raw_uart_putchar(b'\r');
            tty::raw_uart_putchar(b'\n');
        }
        ch => {
            tty::raw_uart_putchar(ch);
        }
    }
}

/// Write data to UART output.
fn write_serial(data: &[u8]) {
    for &ch in data {
        tty::raw_uart_putchar(ch);
    }
}

// --- FileOps response helpers ---

/// Max data payload per chunk: MAX_MSG_SIZE - 1 (tag) - 2 (length prefix) = 1021
const MAX_DATA_CHUNK: usize = MAX_MSG_SIZE - 3;

/// Send FileResponse::Data { chunk } on an endpoint.
fn send_file_data(ep: usize, data: &[u8], pid: usize) {
    for chunk in data.chunks(MAX_DATA_CHUNK) {
        let mut msg = Message::new();
        let mut w = Writer::new(&mut msg.data);
        let _ = w.write_u8(0); // tag: Data
        let _ = w.write_bytes(chunk);
        msg.len = w.position();
        msg.sender_pid = pid;
        let _ = ipc::channel_send_blocking(ep, &msg, pid);
    }
}

/// Send FileResponse::Data with empty chunk (EOF sentinel).
fn send_file_sentinel(ep: usize, pid: usize) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(0); // tag: Data
    let _ = w.write_u16(0); // zero-length payload
    msg.len = w.position();
    msg.sender_pid = pid;
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

/// Send FileResponse::WriteOk { written }.
fn send_write_ok(ep: usize, written: u32, pid: usize) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(1); // tag: WriteOk
    let _ = w.write_u32(written);
    msg.len = w.position();
    msg.sender_pid = pid;
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

/// Send FileResponse::IoctlOk { result }.
fn send_ioctl_ok(ep: usize, result: u32, pid: usize) {
    let mut msg = Message::new();
    let mut w = Writer::new(&mut msg.data);
    let _ = w.write_u8(3); // tag: IoctlOk
    let _ = w.write_u32(result);
    msg.len = w.position();
    msg.sender_pid = pid;
    let _ = ipc::channel_send_blocking(ep, &msg, pid);
}

// --- Per-client state ---

const MAX_CONSOLE_CLIENTS: usize = 8;

struct ConsoleClient {
    stdin_ep: usize,          // receives Read/Ioctl requests, sends Data responses
    stdout_ep: usize,         // receives Write requests, sends WriteOk responses
    pid: u32,
    has_pending_read: bool,   // true if client sent Read but no data available yet
    pending_read_len: u32,    // requested read length
    active: bool,
}

impl ConsoleClient {
    const fn empty() -> Self {
        ConsoleClient {
            stdin_ep: usize::MAX,
            stdout_ep: usize::MAX,
            pid: 0,
            has_pending_read: false,
            pending_read_len: 0,
            active: false,
        }
    }

    fn is_complete(&self) -> bool {
        self.stdin_ep != usize::MAX && self.stdout_ep != usize::MAX
    }
}

/// Find or create a client entry for the given PID. Returns index.
fn find_or_create_client(
    clients: &mut [ConsoleClient; MAX_CONSOLE_CLIENTS],
    pid: u32,
) -> Option<usize> {
    // Find existing
    for i in 0..MAX_CONSOLE_CLIENTS {
        if clients[i].active && clients[i].pid == pid {
            return Some(i);
        }
    }
    // Create new
    for i in 0..MAX_CONSOLE_CLIENTS {
        if !clients[i].active {
            clients[i] = ConsoleClient::empty();
            clients[i].active = true;
            clients[i].pid = pid;
            return Some(i);
        }
    }
    crate::println!("[serial-con] WARN: too many console clients, dropping PID {}", pid);
    None
}

/// Clean up dead clients and update stdin stack.
fn cleanup_dead_clients(
    clients: &mut [ConsoleClient; MAX_CONSOLE_CLIENTS],
    stdin_stack: &mut [usize; MAX_CONSOLE_CLIENTS],
    stdin_stack_len: &mut usize,
) {
    for i in 0..MAX_CONSOLE_CLIENTS {
        if !clients[i].active { continue; }

        let stdin_dead = clients[i].stdin_ep != usize::MAX && !ipc::channel_is_active(clients[i].stdin_ep);
        let stdout_dead = clients[i].stdout_ep != usize::MAX && !ipc::channel_is_active(clients[i].stdout_ep);

        if stdin_dead || stdout_dead {
            // Close both endpoints
            if clients[i].stdin_ep != usize::MAX {
                ipc::channel_close(clients[i].stdin_ep);
            }
            if clients[i].stdout_ep != usize::MAX {
                ipc::channel_close(clients[i].stdout_ep);
            }
            clients[i].active = false;

            // Remove from stdin stack
            let mut j = 0;
            while j < *stdin_stack_len {
                if stdin_stack[j] == i {
                    for k in j..*stdin_stack_len - 1 {
                        stdin_stack[k] = stdin_stack[k + 1];
                    }
                    *stdin_stack_len -= 1;
                } else {
                    j += 1;
                }
            }
        }
    }
}

/// Serial console server kernel task.
/// Owns UART I/O. Accepts multiple client endpoints via its control channel.
/// Each client has separate stdin/stdout channels speaking the FileOps protocol.
/// Stdin goes to the most recently connected client (stack model); reverts on disconnect.
pub fn serial_console_server() {
    let control_ep = SERIAL_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register for wake on serial input
    tty::set_serial_wake_pid(my_pid);

    let mut clients: [ConsoleClient; MAX_CONSOLE_CLIENTS] = [const { ConsoleClient::empty() }; MAX_CONSOLE_CLIENTS];
    // Stdin stack: indices into clients[]; most recent is on top
    let mut stdin_stack: [usize; MAX_CONSOLE_CLIENTS] = [usize::MAX; MAX_CONSOLE_CLIENTS];
    let mut stdin_stack_len: usize = 0;

    let mut line_disc = LineDiscipline::new();
    let mut raw_mode = false;

    // Main loop
    loop {
        let mut handled = false;

        // Check control channel for new client registrations
        loop {
            let (msg, send_wake) = ipc::channel_recv(control_ep);
            if send_wake != 0 { crate::task::wake_process(send_wake); }
            match msg {
                Some(msg) => {
                    handled = true;
                    if msg.cap_count > 0 {
                        if let Some(ep) = ipc::decode_cap_channel(msg.caps[0]) {
                            // Parse NewConnection { client_pid, channel_role }
                            let (client_pid, channel_role) = if msg.len >= 5 {
                                let pid = u32::from_le_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                                (pid, msg.data[4])
                            } else if msg.len >= 4 {
                                let pid = u32::from_le_bytes([msg.data[0], msg.data[1], msg.data[2], msg.data[3]]);
                                (pid, 0u8)
                            } else {
                                (0, 0u8)
                            };

                            if let Some(idx) = find_or_create_client(&mut clients, client_pid) {
                                match channel_role {
                                    1 => clients[idx].stdin_ep = ep,  // stdin
                                    2 => clients[idx].stdout_ep = ep, // stdout
                                    _ => {
                                        // Legacy generic: treat as stdout (shouldn't happen)
                                        clients[idx].stdout_ep = ep;
                                    }
                                }

                                // Once both endpoints are set, push onto stdin stack
                                if clients[idx].is_complete() {
                                    // Only push if not already in stack
                                    let already = (0..stdin_stack_len).any(|j| stdin_stack[j] == idx);
                                    if !already && stdin_stack_len < MAX_CONSOLE_CLIENTS {
                                        stdin_stack[stdin_stack_len] = idx;
                                        stdin_stack_len += 1;
                                    }
                                }
                            } else {
                                ipc::channel_close(ep);
                            }
                        }
                    }
                }
                None => break,
            }
        }

        // Current stdin recipient (top of stack)
        let stdin_idx = if stdin_stack_len > 0 { stdin_stack[stdin_stack_len - 1] } else { usize::MAX };

        // Process UART input characters
        loop {
            let ch = tty::SERIAL_INPUT.lock().pop();
            match ch {
                Some(ch) => {
                    handled = true;
                    if raw_mode {
                        // Raw mode: no echo, no line discipline, fulfill pending read directly
                        if stdin_idx != usize::MAX && clients[stdin_idx].has_pending_read {
                            send_file_data(clients[stdin_idx].stdin_ep, &[ch], my_pid);
                            send_file_sentinel(clients[stdin_idx].stdin_ep, my_pid);
                            clients[stdin_idx].has_pending_read = false;
                        }
                    } else {
                        echo_serial(ch);
                        if let Some(len) = line_disc.push_char(ch) {
                            let mut buf = [0u8; LINE_BUF_SIZE];
                            let data = line_disc.line_data(len);
                            buf[..len].copy_from_slice(data);
                            // Fulfill pending read on stdin client
                            if stdin_idx != usize::MAX && clients[stdin_idx].has_pending_read {
                                send_file_data(clients[stdin_idx].stdin_ep, &buf[..len], my_pid);
                                send_file_sentinel(clients[stdin_idx].stdin_ep, my_pid);
                                clients[stdin_idx].has_pending_read = false;
                            }
                        }
                    }
                }
                None => break,
            }
        }

        // Poll stdin channels for Read/Ioctl requests
        for i in 0..MAX_CONSOLE_CLIENTS {
            if !clients[i].active || clients[i].stdin_ep == usize::MAX { continue; }
            loop {
                let (msg, send_wake) = ipc::channel_recv(clients[i].stdin_ep);
                if send_wake != 0 { crate::task::wake_process(send_wake); }
                match msg {
                    Some(msg) => {
                        handled = true;
                        if msg.len == 0 { continue; }
                        let mut r = Reader::new(&msg.data[..msg.len]);
                        let tag = r.read_u8().unwrap_or(0xFF);
                        match tag {
                            0 => {
                                // FileRequest::Read { offset, len }
                                let _offset = r.read_u64().unwrap_or(0);
                                let len = r.read_u32().unwrap_or(1024);
                                clients[i].has_pending_read = true;
                                clients[i].pending_read_len = len;
                            }
                            2 => {
                                // FileRequest::Ioctl { cmd, arg }
                                let cmd = r.read_u32().unwrap_or(0);
                                let _arg = r.read_u32().unwrap_or(0);
                                match cmd {
                                    1 => { // TCRAW
                                        raw_mode = true;
                                        send_ioctl_ok(clients[i].stdin_ep, 0, my_pid);
                                    }
                                    2 => { // TCCOOKED
                                        raw_mode = false;
                                        send_ioctl_ok(clients[i].stdin_ep, 0, my_pid);
                                    }
                                    _ => {
                                        // Unknown ioctl — send error
                                        let mut emsg = Message::new();
                                        let mut w = Writer::new(&mut emsg.data);
                                        let _ = w.write_u8(2); // tag: Error
                                        let _ = w.write_u8(7); // IO error
                                        emsg.len = w.position();
                                        emsg.sender_pid = my_pid;
                                        let _ = ipc::channel_send_blocking(clients[i].stdin_ep, &emsg, my_pid);
                                    }
                                }
                            }
                            _ => {} // ignore unknown tags
                        }
                    }
                    None => break,
                }
            }
        }

        // Poll stdout channels for Write requests
        for i in 0..MAX_CONSOLE_CLIENTS {
            if !clients[i].active || clients[i].stdout_ep == usize::MAX { continue; }
            loop {
                let (msg, send_wake) = ipc::channel_recv(clients[i].stdout_ep);
                if send_wake != 0 { crate::task::wake_process(send_wake); }
                match msg {
                    Some(msg) => {
                        handled = true;
                        if msg.len == 0 { continue; }
                        let mut r = Reader::new(&msg.data[..msg.len]);
                        let tag = r.read_u8().unwrap_or(0xFF);
                        match tag {
                            1 => {
                                // FileRequest::Write { offset, data }
                                let _offset = r.read_u64().unwrap_or(0);
                                let data = r.read_bytes().unwrap_or(&[]);
                                write_serial(data);
                                send_write_ok(clients[i].stdout_ep, data.len() as u32, my_pid);
                            }
                            _ => {} // ignore unknown tags
                        }
                    }
                    None => break,
                }
            }
        }

        // Clean up dead clients
        cleanup_dead_clients(&mut clients, &mut stdin_stack, &mut stdin_stack_len);

        if !handled {
            // Register blocked on control channel + all stdin/stdout endpoints + UART wake
            ipc::channel_set_blocked(control_ep, my_pid);
            for i in 0..MAX_CONSOLE_CLIENTS {
                if !clients[i].active { continue; }
                if clients[i].stdin_ep != usize::MAX {
                    ipc::channel_set_blocked(clients[i].stdin_ep, my_pid);
                }
                if clients[i].stdout_ep != usize::MAX {
                    ipc::channel_set_blocked(clients[i].stdout_ep, my_pid);
                }
            }
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}
