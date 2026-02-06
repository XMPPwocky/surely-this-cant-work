use crate::ipc::{self, Message};
use crate::drivers::tty;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Control endpoint for serial console server (set by kmain before spawn)
static SERIAL_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Control endpoint for FB console server (set by kmain before spawn)
static FB_CONTROL_EP: AtomicUsize = AtomicUsize::new(usize::MAX);

pub fn set_serial_control_ep(ep: usize) {
    SERIAL_CONTROL_EP.store(ep, Ordering::Relaxed);
}

pub fn set_fb_control_ep(ep: usize) {
    FB_CONTROL_EP.store(ep, Ordering::Relaxed);
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
                let len = self.line_len;
                // Add newline to buffer
                if self.line_len < LINE_BUF_SIZE {
                    self.line_buf[self.line_len] = b'\n';
                    self.line_len += 1;
                }
                let result_len = self.line_len;
                self.line_len = 0;
                if len == 0 && result_len == 1 {
                    // Just a newline with no content - still deliver it
                    Some(result_len)
                } else {
                    Some(result_len)
                }
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

/// Echo a character to framebuffer console.
fn echo_fb(ch: u8) {
    let mut fb = crate::console::FB_CONSOLE.lock();
    if !fb.is_active() {
        return;
    }
    match ch {
        0x7F | 0x08 => {
            fb.write_char(0x08);
            fb.write_char(b' ');
            fb.write_char(0x08);
        }
        b'\r' | b'\n' => {
            fb.write_char(b'\r');
            fb.write_char(b'\n');
        }
        ch => {
            fb.write_char(ch);
        }
    }
    drop(fb);
    crate::drivers::virtio::gpu::flush();
}

/// Write data to UART output.
fn write_serial(data: &[u8]) {
    for &ch in data {
        tty::raw_uart_putchar(ch);
    }
}

/// Write data to framebuffer console output.
fn write_fb(data: &[u8]) {
    let mut fb = crate::console::FB_CONSOLE.lock();
    if fb.is_active() {
        for &ch in data {
            fb.write_char(ch);
        }
    }
    drop(fb);
    crate::drivers::virtio::gpu::flush();
}

/// Send a line as a message to the client endpoint.
fn send_line(client_ep: usize, data: &[u8]) {
    let pid = crate::task::current_pid();
    // Send in 64-byte chunks
    let mut offset = 0;
    while offset < data.len() {
        let chunk_len = (data.len() - offset).min(64);
        let mut msg = Message::new();
        msg.data[..chunk_len].copy_from_slice(&data[offset..offset + chunk_len]);
        msg.len = chunk_len;
        msg.sender_pid = pid;
        let wake = ipc::channel_send(client_ep, msg);
        if wake != 0 {
            crate::task::wake_process(wake);
        }
        offset += chunk_len;
    }
}

const MAX_CONSOLE_CLIENTS: usize = 4;

/// Serial console server kernel task.
/// Owns UART I/O. Accepts multiple client endpoints via its control channel.
/// All clients can write output; input goes to client 0 (the primary shell).
pub fn serial_console_server() {
    let control_ep = SERIAL_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register for wake on serial input
    tty::set_serial_wake_pid(my_pid);

    let mut client_eps: [usize; MAX_CONSOLE_CLIENTS] = [usize::MAX; MAX_CONSOLE_CLIENTS];
    let mut client_count: usize = 0;

    // Wait for at least the first client endpoint via control channel
    loop {
        match ipc::channel_recv(control_ep) {
            Some(msg) => {
                if let Some(ep) = ipc::decode_cap_channel(msg.cap) {
                    if client_count < MAX_CONSOLE_CLIENTS {
                        client_eps[client_count] = ep;
                        client_count += 1;
                        break;
                    }
                }
            }
            None => {
                crate::ipc::channel_set_blocked(control_ep, my_pid);
                crate::task::block_process(my_pid);
                crate::task::schedule();
            }
        }
    }

    let mut line_disc = LineDiscipline::new();

    // Main loop
    loop {
        // Check control channel for new client registrations
        while let Some(msg) = ipc::channel_recv(control_ep) {
            if let Some(ep) = ipc::decode_cap_channel(msg.cap) {
                if client_count < MAX_CONSOLE_CLIENTS {
                    client_eps[client_count] = ep;
                    client_count += 1;
                }
            }
        }

        // Check for input characters from UART ring buffer
        let mut got_input = false;
        loop {
            let ch = tty::SERIAL_INPUT.lock().pop();
            match ch {
                Some(ch) => {
                    got_input = true;
                    echo_serial(ch);
                    // Also echo to FB if active
                    echo_fb(ch);
                    if let Some(len) = line_disc.push_char(ch) {
                        // Complete line — send to primary client (client 0)
                        let data_copy = {
                            let src = line_disc.line_data(len);
                            let mut buf = [0u8; LINE_BUF_SIZE];
                            buf[..len].copy_from_slice(src);
                            (buf, len)
                        };
                        if client_count > 0 {
                            send_line(client_eps[0], &data_copy.0[..data_copy.1]);
                        }
                    }
                }
                None => break,
            }
        }

        // Check for write requests from ALL clients
        let mut got_write = false;
        for i in 0..client_count {
            loop {
                match ipc::channel_recv(client_eps[i]) {
                    Some(msg) => {
                        got_write = true;
                        if msg.len > 0 {
                            write_serial(&msg.data[..msg.len]);
                            write_fb(&msg.data[..msg.len]);
                        }
                    }
                    None => break,
                }
            }
        }

        if !got_input && !got_write {
            // Register blocked on control channel + all client endpoints
            ipc::channel_set_blocked(control_ep, my_pid);
            for i in 0..client_count {
                ipc::channel_set_blocked(client_eps[i], my_pid);
            }
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}

/// FB console server kernel task.
/// Owns framebuffer + keyboard. Same multi-client pattern as serial console server.
pub fn fb_console_server() {
    let control_ep = FB_CONTROL_EP.load(Ordering::Relaxed);
    let my_pid = crate::task::current_pid();

    // Register for wake on keyboard input
    tty::set_kbd_wake_pid(my_pid);

    let mut client_eps: [usize; MAX_CONSOLE_CLIENTS] = [usize::MAX; MAX_CONSOLE_CLIENTS];
    let mut client_count: usize = 0;

    // Wait for at least the first client
    loop {
        match ipc::channel_recv(control_ep) {
            Some(msg) => {
                if let Some(ep) = ipc::decode_cap_channel(msg.cap) {
                    if client_count < MAX_CONSOLE_CLIENTS {
                        client_eps[client_count] = ep;
                        client_count += 1;
                        break;
                    }
                }
            }
            None => {
                crate::ipc::channel_set_blocked(control_ep, my_pid);
                crate::task::block_process(my_pid);
                crate::task::schedule();
            }
        }
    }

    let mut line_disc = LineDiscipline::new();

    loop {
        // Check control channel for new clients
        while let Some(msg) = ipc::channel_recv(control_ep) {
            if let Some(ep) = ipc::decode_cap_channel(msg.cap) {
                if client_count < MAX_CONSOLE_CLIENTS {
                    client_eps[client_count] = ep;
                    client_count += 1;
                }
            }
        }

        // Check for keyboard input
        let mut got_input = false;
        loop {
            let ch = tty::KBD_INPUT.lock().pop();
            match ch {
                Some(ch) => {
                    got_input = true;
                    echo_fb(ch);
                    if let Some(len) = line_disc.push_char(ch) {
                        let data_copy = {
                            let src = line_disc.line_data(len);
                            let mut buf = [0u8; LINE_BUF_SIZE];
                            buf[..len].copy_from_slice(src);
                            (buf, len)
                        };
                        if client_count > 0 {
                            send_line(client_eps[0], &data_copy.0[..data_copy.1]);
                        }
                    }
                }
                None => break,
            }
        }

        // Check for write requests from ALL clients
        let mut got_write = false;
        for i in 0..client_count {
            loop {
                match ipc::channel_recv(client_eps[i]) {
                    Some(msg) => {
                        got_write = true;
                        if msg.len > 0 {
                            write_fb(&msg.data[..msg.len]);
                        }
                    }
                    None => break,
                }
            }
        }

        if !got_input && !got_write {
            ipc::channel_set_blocked(control_ep, my_pid);
            for i in 0..client_count {
                ipc::channel_set_blocked(client_eps[i], my_pid);
            }
            crate::task::block_process(my_pid);
            crate::task::schedule();
        }
    }
}
