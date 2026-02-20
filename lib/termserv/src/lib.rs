//! Terminal server library for rvOS.
//!
//! Provides the shared logic for terminal/console servers: line discipline,
//! FileOps protocol dispatch, client management, stdin multiplexing, ioctl
//! handling, and Ctrl+C delivery.
//!
//! Backends implement the [`TermOutput`] trait to provide I/O primitives
//! (write output, echo characters). The library handles everything else.
//!
//! Used by: fbcon (GUI terminal), nc -e (network terminal).

#![no_std]

use rvos::raw;
use rvos::Channel;
use rvos::RecvError;
use rvos_proto::fs::{
    FileRequest, FileRequestMsg, FileResponse, FileResponseMsg,
    FsError, TCCOOKED, TCRAW, TCSETFG,
};

/// Channel type for stdio endpoints (server perspective):
/// sends FileResponse, receives FileRequest.
pub type StdioChannel = Channel<FileResponseMsg, FileRequestMsg>;

/// Maximum number of clients a TermServer can manage.
pub const MAX_TERM_CLIENTS: usize = 8;

const LINE_BUF_SIZE: usize = 256;

/// Max data payload per FileResponse::Data chunk:
/// 1024 (msg data) - 1 (tag) - 2 (length prefix) = 1021
const MAX_DATA_CHUNK: usize = 1021;

// ---------------------------------------------------------------------------
// TermOutput trait
// ---------------------------------------------------------------------------

/// Backend trait — the only thing each terminal implementation provides.
///
/// All methods receive data that should be delivered to the physical output
/// (display, UART, network socket, etc.).
pub trait TermOutput {
    /// Data from a client process (they wrote to stdout via `FileRequest::Write`).
    fn write_output(&mut self, data: &[u8]);

    /// Echo a printable character during cooked-mode line editing.
    fn echo_char(&mut self, ch: u8);

    /// Echo a backspace (typically: BS, space, BS to erase the character).
    fn echo_backspace(&mut self);

    /// Echo a newline (typically: CR, LF) when Enter is pressed.
    fn echo_newline(&mut self);
}

// ---------------------------------------------------------------------------
// LineDiscipline
// ---------------------------------------------------------------------------

struct LineDiscipline {
    buf: [u8; LINE_BUF_SIZE],
    len: usize,
    raw_mode: bool,
}

impl LineDiscipline {
    const fn new() -> Self {
        LineDiscipline {
            buf: [0; LINE_BUF_SIZE],
            len: 0,
            raw_mode: false,
        }
    }

    /// Process a character. Returns `Some(len)` when data is ready to deliver.
    fn push_char(&mut self, ch: u8) -> Option<usize> {
        if self.raw_mode {
            self.buf[0] = ch;
            return Some(1);
        }
        match ch {
            0x7F | 0x08 => {
                if self.len > 0 {
                    self.len -= 1;
                }
                None
            }
            b'\r' | b'\n' => {
                if self.len < LINE_BUF_SIZE {
                    self.buf[self.len] = b'\n';
                    self.len += 1;
                }
                let result = self.len;
                self.len = 0;
                Some(result)
            }
            ch if (0x20..0x7F).contains(&ch) => {
                if self.len < LINE_BUF_SIZE - 1 {
                    self.buf[self.len] = ch;
                    self.len += 1;
                }
                None
            }
            _ => None,
        }
    }

    fn line_data(&self, len: usize) -> &[u8] {
        &self.buf[..len]
    }
}

// ---------------------------------------------------------------------------
// TermClient
// ---------------------------------------------------------------------------

struct TermClient {
    stdin: StdioChannel,
    stdout: StdioChannel,
    has_pending_read: bool,
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn send_data(ch: &StdioChannel, data: &[u8]) {
    for chunk in data.chunks(MAX_DATA_CHUNK) {
        let _ = ch.send(&FileResponse::Data { chunk });
    }
}

fn send_sentinel(ch: &StdioChannel) {
    let _ = ch.send(&FileResponse::Data { chunk: &[] });
}

fn send_write_ok(ch: &StdioChannel, written: u32) {
    let _ = ch.send(&FileResponse::WriteOk { written });
}

fn send_ioctl_ok(ch: &StdioChannel, result: u32) {
    let _ = ch.send(&FileResponse::IoctlOk { result });
}

// ---------------------------------------------------------------------------
// TermServer
// ---------------------------------------------------------------------------

/// A terminal server that manages FileOps clients.
///
/// Handles the server side of the FileOps protocol for stdin and stdout
/// channels: line discipline, ioctl dispatch, Ctrl+C, and response
/// serialization. Backends provide physical I/O via the [`TermOutput`] trait.
pub struct TermServer {
    clients: [Option<TermClient>; MAX_TERM_CLIENTS],
    stdin_stack: [usize; MAX_TERM_CLIENTS],
    stdin_stack_len: usize,
    line_disc: LineDiscipline,
    foreground_pid: u32,
}

impl TermServer {
    /// Create a new terminal server with no clients.
    pub fn new() -> Self {
        TermServer {
            clients: [const { None }; MAX_TERM_CLIENTS],
            stdin_stack: [usize::MAX; MAX_TERM_CLIENTS],
            stdin_stack_len: 0,
            line_disc: LineDiscipline::new(),
            foreground_pid: 0,
        }
    }

    /// Register a new client with separate stdin/stdout raw channel handles.
    ///
    /// The TermServer takes ownership of the handles (they will be closed
    /// when the client is removed or the TermServer is dropped).
    ///
    /// Returns the client slot index, or `None` if all slots are full.
    pub fn add_client(&mut self, stdin_h: usize, stdout_h: usize) -> Option<usize> {
        for i in 0..MAX_TERM_CLIENTS {
            if self.clients[i].is_none() {
                self.clients[i] = Some(TermClient {
                    stdin: Channel::from_raw_handle(stdin_h),
                    stdout: Channel::from_raw_handle(stdout_h),
                    has_pending_read: false,
                });
                return Some(i);
            }
        }
        None
    }

    /// Feed an input byte from the external source (keyboard, network, etc.)
    /// through the line discipline and deliver to the active client.
    ///
    /// In raw mode: delivers the byte immediately, no echo.
    /// In cooked mode: echoes via `output`, buffers until Enter, then delivers.
    /// Ctrl+C (0x03): kills the foreground process if one is set.
    pub fn feed_input(&mut self, ch: u8, output: &mut impl TermOutput) {
        let stdin_idx = self.active_stdin_idx();

        // Ctrl+C: kill foreground process
        if ch == 0x03 && self.foreground_pid != 0 {
            output.write_output(b"^C\r\n");
            raw::sys_kill(self.foreground_pid as usize, -2);
            self.foreground_pid = 0;
            return;
        }

        // Raw mode: deliver immediately, no echo
        if self.line_disc.raw_mode {
            if let Some(len) = self.line_disc.push_char(ch) {
                let mut buf = [0u8; LINE_BUF_SIZE];
                buf[..len].copy_from_slice(self.line_disc.line_data(len));
                self.deliver_to_reader(stdin_idx, &buf[..len]);
            }
            return;
        }

        // Cooked mode: echo first
        match ch {
            0x7F | 0x08 => {
                // Only echo backspace if there's something to delete
                if self.line_disc.len > 0 {
                    output.echo_backspace();
                }
            }
            b'\r' => output.echo_newline(),
            ch if (0x20..0x7F).contains(&ch) => output.echo_char(ch),
            _ => {}
        }

        // Feed to line discipline
        if let Some(len) = self.line_disc.push_char(ch) {
            let mut buf = [0u8; LINE_BUF_SIZE];
            buf[..len].copy_from_slice(self.line_disc.line_data(len));
            self.deliver_to_reader(stdin_idx, &buf[..len]);
        }
    }

    /// Feed raw bytes directly to the pending reader, bypassing the line
    /// discipline. Used for escape sequences (arrow keys, etc.) in raw mode.
    ///
    /// Only delivers if there is an active client with a pending read.
    pub fn feed_raw(&mut self, data: &[u8]) {
        let idx = self.active_stdin_idx();
        self.deliver_to_reader(idx, data);
    }

    /// Poll all stdin channels for `FileRequest::Read` and `FileRequest::Ioctl`
    /// requests. Returns `true` if any work was done.
    pub fn poll_stdin(&mut self) -> bool {
        let mut handled = false;
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_TERM_CLIENTS {
            if self.clients[i].is_none() {
                continue;
            }
            let mut closed = false;
            loop {
                let client = self.clients[i].as_mut().unwrap();
                match client.stdin.try_recv() {
                    Ok(FileRequest::Read { offset: _, len: _ }) => {
                        handled = true;
                        client.has_pending_read = true;
                        // Push onto stdin_stack on first Read (lazy)
                        let already =
                            (0..self.stdin_stack_len).any(|j| self.stdin_stack[j] == i);
                        if !already && self.stdin_stack_len < MAX_TERM_CLIENTS {
                            self.stdin_stack[self.stdin_stack_len] = i;
                            self.stdin_stack_len += 1;
                        }
                    }
                    Ok(FileRequest::Ioctl { cmd, arg }) => {
                        handled = true;
                        match cmd {
                            TCRAW => {
                                self.line_disc.raw_mode = true;
                                send_ioctl_ok(&client.stdin, 0);
                            }
                            TCCOOKED => {
                                self.line_disc.raw_mode = false;
                                send_ioctl_ok(&client.stdin, 0);
                            }
                            TCSETFG => {
                                self.foreground_pid = arg;
                                send_ioctl_ok(&client.stdin, 0);
                            }
                            _ => {
                                let _ = client
                                    .stdin
                                    .send(&FileResponse::Error { code: FsError::Io {} });
                            }
                        }
                    }
                    Ok(_) => {} // ignore unexpected requests on stdin
                    Err(RecvError::Closed) => {
                        closed = true;
                        handled = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if closed {
                self.clients[i] = None;
                self.remove_from_stdin_stack(i);
            }
        }
        handled
    }

    /// Poll all stdout channels for `FileRequest::Write` requests.
    /// Received data is passed to `output.write_output()`.
    /// Returns `true` if any work was done.
    pub fn poll_stdout(&mut self, output: &mut impl TermOutput) -> bool {
        let mut handled = false;
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_TERM_CLIENTS {
            if self.clients[i].is_none() {
                continue;
            }
            let mut closed = false;
            loop {
                // Phase 1: recv and process (data borrows from channel buffer)
                let written: Option<u32> = {
                    let client = self.clients[i].as_mut().unwrap();
                    match client.stdout.try_recv() {
                        Ok(FileRequest::Write { offset: _, data }) => {
                            output.write_output(data);
                            Some(data.len() as u32)
                        }
                        Ok(_) => None,
                        Err(RecvError::Closed) => {
                            closed = true;
                            break;
                        }
                        Err(_) => break,
                    }
                };
                // Phase 2: respond (borrow released)
                if let Some(w) = written {
                    handled = true;
                    send_write_ok(&self.clients[i].as_ref().unwrap().stdout, w);
                }
            }
            if closed {
                handled = true;
                self.clients[i] = None;
                self.remove_from_stdin_stack(i);
            }
        }
        handled
    }

    /// Register all active client channels for poll-based wakeup.
    ///
    /// Call this before `raw::sys_block()` to be woken when any client
    /// sends a message.
    pub fn poll_add_all(&self) {
        for client in self.clients.iter().flatten() {
            client.stdin.poll_add();
            client.stdout.poll_add();
        }
    }

    /// Returns `true` if there are any active (non-closed) clients.
    pub fn has_active_clients(&self) -> bool {
        self.clients.iter().any(|c| c.is_some())
    }

    /// Returns `true` if the line discipline is in raw mode.
    pub fn is_raw_mode(&self) -> bool {
        self.line_disc.raw_mode
    }

    // --- Internal helpers ---

    /// Get the active stdin client index (top of the stdin stack).
    fn active_stdin_idx(&self) -> Option<usize> {
        if self.stdin_stack_len > 0 {
            Some(self.stdin_stack[self.stdin_stack_len - 1])
        } else {
            None
        }
    }

    /// Deliver data to the pending reader at the given client index.
    fn deliver_to_reader(&mut self, idx: Option<usize>, data: &[u8]) {
        if let Some(i) = idx {
            if let Some(ref mut client) = self.clients[i] {
                if client.has_pending_read {
                    send_data(&client.stdin, data);
                    send_sentinel(&client.stdin);
                    client.has_pending_read = false;
                }
            }
        }
    }

    /// Remove a client index from the stdin stack.
    fn remove_from_stdin_stack(&mut self, client_idx: usize) {
        let mut j = 0;
        while j < self.stdin_stack_len {
            if self.stdin_stack[j] == client_idx {
                for k in j..self.stdin_stack_len - 1 {
                    self.stdin_stack[k] = self.stdin_stack[k + 1];
                }
                self.stdin_stack_len -= 1;
            } else {
                j += 1;
            }
        }
    }
}
