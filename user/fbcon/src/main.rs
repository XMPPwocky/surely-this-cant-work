extern crate rvos_rt;

use rvos::raw;
use rvos::{Channel, UserTransport};
use rvos::rvos_wire::Never;
use rvos_proto::fs::{
    FileRequest, FileResponse, FileResponseMsg, FileRequestMsg,
    FsError, TCRAW, TCCOOKED,
};
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowEvent, WindowClient,
};

// --- Font data (shared from rvos-gfx) ---

use rvos_gfx::font::{FONT_8X16, GLYPH_WIDTH, GLYPH_HEIGHT};

const FONT_WIDTH: u32 = GLYPH_WIDTH;
const FONT_HEIGHT: u32 = GLYPH_HEIGHT;

// --- Keymap data (Linux keycodes → ASCII) ---

static KEYMAP: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'1'; map[3] = b'2'; map[4] = b'3'; map[5] = b'4';
    map[6] = b'5'; map[7] = b'6'; map[8] = b'7'; map[9] = b'8';
    map[10] = b'9'; map[11] = b'0'; map[12] = b'-'; map[13] = b'=';
    map[14] = 0x7F; // Backspace → DEL
    map[15] = b'\t';
    map[16] = b'q'; map[17] = b'w'; map[18] = b'e'; map[19] = b'r';
    map[20] = b't'; map[21] = b'y'; map[22] = b'u'; map[23] = b'i';
    map[24] = b'o'; map[25] = b'p'; map[26] = b'['; map[27] = b']';
    map[28] = b'\r'; // Enter
    map[30] = b'a'; map[31] = b's'; map[32] = b'd'; map[33] = b'f';
    map[34] = b'g'; map[35] = b'h'; map[36] = b'j'; map[37] = b'k';
    map[38] = b'l'; map[39] = b';'; map[40] = b'\''; map[41] = b'`';
    map[43] = b'\\';
    map[44] = b'z'; map[45] = b'x'; map[46] = b'c'; map[47] = b'v';
    map[48] = b'b'; map[49] = b'n'; map[50] = b'm'; map[51] = b',';
    map[52] = b'.'; map[53] = b'/';
    map[55] = b'*'; // Keypad *
    map[57] = b' '; // Space
    map
};

static KEYMAP_SHIFT: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'!'; map[3] = b'@'; map[4] = b'#'; map[5] = b'$';
    map[6] = b'%'; map[7] = b'^'; map[8] = b'&'; map[9] = b'*';
    map[10] = b'('; map[11] = b')'; map[12] = b'_'; map[13] = b'+';
    map[14] = 0x7F; // Backspace → DEL
    map[15] = b'\t';
    map[16] = b'Q'; map[17] = b'W'; map[18] = b'E'; map[19] = b'R';
    map[20] = b'T'; map[21] = b'Y'; map[22] = b'U'; map[23] = b'I';
    map[24] = b'O'; map[25] = b'P'; map[26] = b'{'; map[27] = b'}';
    map[28] = b'\r'; // Enter
    map[30] = b'A'; map[31] = b'S'; map[32] = b'D'; map[33] = b'F';
    map[34] = b'G'; map[35] = b'H'; map[36] = b'J'; map[37] = b'K';
    map[38] = b'L'; map[39] = b':'; map[40] = b'"'; map[41] = b'~';
    map[43] = b'|';
    map[44] = b'Z'; map[45] = b'X'; map[46] = b'C'; map[47] = b'V';
    map[48] = b'B'; map[49] = b'N'; map[50] = b'M'; map[51] = b'<';
    map[52] = b'>'; map[53] = b'?';
    map[57] = b' '; // Space
    map
};

// --- FbConsole: text renderer on SHM framebuffer ---

struct FbConsole {
    fb: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
    col: u32,
    row: u32,
    cols: u32,
    rows: u32,
    fg: u32,
    bg: u32,
    dirty: bool,
    // ANSI escape sequence parser state
    esc_state: u8,         // 0=normal, 1=saw ESC, 2=in CSI
    esc_params: [u32; 4],
    esc_nparam: usize,
    esc_cur_param: u32,
    esc_has_digit: bool,
}

impl FbConsole {
    fn new(fb: *mut u32, width: u32, height: u32, stride: u32) -> Self {
        let cols = width / FONT_WIDTH;
        let rows = height / FONT_HEIGHT;
        // Clear the back buffer to opaque black
        let total = (stride * height) as usize;
        for i in 0..total {
            unsafe { *fb.add(i) = 0xFF000000; }
        }
        FbConsole {
            fb, width, height, stride,
            col: 0, row: 0, cols, rows,
            fg: 0xFF00FF00, // green on black (opaque)
            bg: 0xFF000000, // opaque black
            dirty: true,
            esc_state: 0,
            esc_params: [0; 4],
            esc_nparam: 0,
            esc_cur_param: 0,
            esc_has_digit: false,
        }
    }

    fn put_char(&mut self, cx: u32, cy: u32, ch: u8) {
        let glyph_idx = if (ch as usize) < 128 { ch as usize } else { 0 };
        let glyph = &FONT_8X16[glyph_idx];
        let px = cx * FONT_WIDTH;
        let py = cy * FONT_HEIGHT;

        for row in 0..FONT_HEIGHT {
            let bits = glyph[row as usize];
            let y = py + row;
            if y >= self.height { break; }
            for col in 0..FONT_WIDTH {
                let x = px + col;
                if x >= self.width { break; }
                let pixel = if bits & (0x80 >> col) != 0 { self.fg } else { self.bg };
                let offset = (y * self.stride + x) as usize;
                unsafe { *self.fb.add(offset) = pixel; }
            }
        }
    }

    /// Render a character directly (no escape sequence parsing).
    fn emit_char(&mut self, ch: u8) {
        match ch {
            b'\n' => {
                self.col = 0;
                self.row += 1;
                if self.row >= self.rows {
                    self.scroll_up();
                    self.row = self.rows - 1;
                }
            }
            b'\r' => {
                self.col = 0;
            }
            0x08 => {
                if self.col > 0 {
                    self.col -= 1;
                }
            }
            b'\t' => {
                let next = (self.col + 8) & !7;
                while self.col < next && self.col < self.cols {
                    self.put_char(self.col, self.row, b' ');
                    self.col += 1;
                }
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows {
                        self.scroll_up();
                        self.row = self.rows - 1;
                    }
                }
            }
            ch => {
                self.put_char(self.col, self.row, ch);
                self.col += 1;
                if self.col >= self.cols {
                    self.col = 0;
                    self.row += 1;
                    if self.row >= self.rows {
                        self.scroll_up();
                        self.row = self.rows - 1;
                    }
                }
            }
        }
        self.dirty = true;
    }

    /// Process a byte through the ANSI escape sequence parser.
    fn write_char(&mut self, ch: u8) {
        match self.esc_state {
            1 => {
                // Saw ESC
                if ch == b'[' {
                    self.esc_state = 2;
                    self.esc_nparam = 0;
                    self.esc_cur_param = 0;
                    self.esc_has_digit = false;
                } else {
                    self.esc_state = 0;
                    // Unknown escape, ignore
                }
            }
            2 => {
                // In CSI: accumulate params and dispatch
                if ch.is_ascii_digit() {
                    self.esc_cur_param = self.esc_cur_param * 10 + (ch - b'0') as u32;
                    self.esc_has_digit = true;
                } else if ch == b';' {
                    if self.esc_nparam < 4 {
                        self.esc_params[self.esc_nparam] = self.esc_cur_param;
                        self.esc_nparam += 1;
                    }
                    self.esc_cur_param = 0;
                    self.esc_has_digit = false;
                } else {
                    // Final byte: store last param and dispatch
                    if self.esc_has_digit && self.esc_nparam < 4 {
                        self.esc_params[self.esc_nparam] = self.esc_cur_param;
                        self.esc_nparam += 1;
                    }
                    self.esc_state = 0;
                    self.dispatch_csi(ch);
                }
            }
            _ => {
                // Normal: check for ESC
                if ch == 0x1B {
                    self.esc_state = 1;
                } else {
                    self.emit_char(ch);
                }
            }
        }
    }

    fn dispatch_csi(&mut self, ch: u8) {
        let p0 = if self.esc_nparam > 0 { self.esc_params[0] } else { 0 };
        let p1 = if self.esc_nparam > 1 { self.esc_params[1] } else { 0 };

        match ch {
            b'A' => {
                // Cursor up
                let n = if p0 == 0 { 1 } else { p0 };
                self.row = self.row.saturating_sub(n);
                self.dirty = true;
            }
            b'B' => {
                // Cursor down
                let n = if p0 == 0 { 1 } else { p0 };
                self.row = (self.row + n).min(self.rows - 1);
                self.dirty = true;
            }
            b'C' => {
                // Cursor right
                let n = if p0 == 0 { 1 } else { p0 };
                self.col = (self.col + n).min(self.cols - 1);
                self.dirty = true;
            }
            b'D' => {
                // Cursor left
                let n = if p0 == 0 { 1 } else { p0 };
                self.col = self.col.saturating_sub(n);
                self.dirty = true;
            }
            b'H' | b'f' => {
                // Cursor position (1-based: ESC[row;colH)
                let row = if p0 == 0 { 0 } else { p0 - 1 };
                let col = if p1 == 0 { 0 } else { p1 - 1 };
                self.row = row.min(self.rows - 1);
                self.col = col.min(self.cols - 1);
                self.dirty = true;
            }
            b'J' => {
                if p0 == 2 {
                    // Clear entire screen
                    let total = (self.stride * self.height) as usize;
                    for i in 0..total {
                        unsafe { *self.fb.add(i) = self.bg; }
                    }
                    self.dirty = true;
                }
            }
            b'K' => {
                if p0 == 0 {
                    // Erase from cursor to end of line
                    for c in self.col..self.cols {
                        self.put_char(c, self.row, b' ');
                    }
                    self.dirty = true;
                }
            }
            _ => {} // ignore unknown CSI sequences
        }
    }

    fn scroll_up(&mut self) {
        let row_pixels = (self.stride * FONT_HEIGHT) as usize;
        let total_pixels = (self.stride * self.height) as usize;
        let copy_pixels = total_pixels - row_pixels;

        unsafe {
            core::ptr::copy(
                self.fb.add(row_pixels),
                self.fb,
                copy_pixels,
            );
            // Fill last row with bg
            for i in copy_pixels..total_pixels {
                *self.fb.add(i) = self.bg;
            }
        }
    }

    /// XOR the cursor cell to toggle block cursor visibility.
    /// Call before swap to show cursor, after swap+copy to erase from back buffer.
    fn toggle_cursor(&mut self) {
        let px = self.col * FONT_WIDTH;
        let py = self.row * FONT_HEIGHT;
        let xor = self.fg ^ self.bg;
        for row in 0..FONT_HEIGHT {
            let y = py + row;
            if y >= self.height { break; }
            for col in 0..FONT_WIDTH {
                let x = px + col;
                if x >= self.width { break; }
                let offset = (y * self.stride + x) as usize;
                unsafe {
                    let p = self.fb.add(offset);
                    *p ^= xor;
                }
            }
        }
    }

    fn write_str(&mut self, s: &[u8]) {
        for &ch in s {
            self.write_char(ch);
        }
    }
}

// --- Line discipline ---

const LINE_BUF_SIZE: usize = 256;

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

    /// Process a character. Returns Some(line_len) when a line is ready.
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

// --- Console client management (FileOps protocol) ---

const MAX_CONSOLE_CLIENTS: usize = 8;
/// Max data payload per chunk: 1024 - 1 (tag) - 2 (length prefix) = 1021
const MAX_DATA_CHUNK: usize = 1021;

struct FbconClient {
    stdin: Channel<FileResponseMsg, FileRequestMsg>,
    stdout: Channel<FileResponseMsg, FileRequestMsg>,
    has_pending_read: bool,
}

/// FileOps response helpers for user-space (typed channel)
fn fb_send_data(ch: &Channel<FileResponseMsg, FileRequestMsg>, data: &[u8]) {
    for chunk in data.chunks(MAX_DATA_CHUNK) {
        let _ = ch.send(&FileResponse::Data { chunk });
    }
}

fn fb_send_sentinel(ch: &Channel<FileResponseMsg, FileRequestMsg>) {
    let _ = ch.send(&FileResponse::Data { chunk: &[] });
}

fn fb_send_write_ok(ch: &Channel<FileResponseMsg, FileRequestMsg>, written: u32) {
    let _ = ch.send(&FileResponse::WriteOk { written });
}

fn fb_send_ioctl_ok(ch: &Channel<FileResponseMsg, FileRequestMsg>, result: u32) {
    let _ = ch.send(&FileResponse::IoctlOk { result });
}

// --- Main ---

fn main() {
    println!("[fbcon] starting");

    // Parse command-line arguments: fbcon [width height]
    let args: Vec<String> = std::env::args().collect();
    let (req_width, req_height) = if args.len() >= 3 {
        let w: u32 = args[1].parse().unwrap_or(0);
        let h: u32 = args[2].parse().unwrap_or(0);
        (w, h)
    } else {
        (0, 0) // fullscreen
    };

    // 1. Connect to "window" service via boot channel
    let win_ctl = rvos::connect_to_service("window")
        .expect("failed to connect to window service")
        .into_raw_handle();

    // 2. Send CreateWindow request and receive per-window channels
    let mut ch = Channel::<CreateWindowRequest, CreateWindowResponse>::from_raw_handle(win_ctl);
    ch.send(&CreateWindowRequest { width: req_width, height: req_height }).expect("CreateWindow send failed");
    let create_resp = ch.recv_blocking().expect("CreateWindow recv failed");
    let req_chan = create_resp.req_channel.raw();
    let event_chan = create_resp.event_channel.raw();

    // 3. Use WindowClient for typed RPC
    let mut window_client = WindowClient::new(UserTransport::new(req_chan));

    // 4. GetInfo to query dimensions
    let (width, height, stride) = match window_client.get_info(1) {
        Ok(WindowReply::InfoReply { width, height, stride, .. }) => (width, height, stride),
        _ => (1024, 768, 1024),
    };

    // 5. GetFramebuffer → receive SHM handle
    let shm_handle = match window_client.get_framebuffer(2) {
        Ok(WindowReply::FbReply { fb, .. }) => fb.0,
        _ => panic!("[fbcon] GetFramebuffer failed"),
    };

    // 6. Map the SHM (double-buffered: 2 * stride * height * 4)
    let fb_size = (stride as usize) * (height as usize) * 4 * 2;
    let fb_base = match raw::mmap(shm_handle, fb_size) {
        Ok(ptr) => ptr as *mut u32,
        Err(_) => panic!("[fbcon] mmap failed"),
    };
    let pixels_per_buffer = (stride as usize) * (height as usize);

    println!("[fbcon] window ready ({}x{}, stride={}, fb={:#x})", width, height, stride, fb_base as usize);

    // Start drawing in back buffer (buffer 1)
    let mut current_back: u8 = 1;
    let back_offset = pixels_per_buffer;
    let back_fb = unsafe { fb_base.add(back_offset) };

    // Initialize FbConsole on the back buffer
    let mut console = FbConsole::new(back_fb, width, height, stride);
    let mut clients: [Option<FbconClient>; MAX_CONSOLE_CLIENTS] = [const { None }; MAX_CONSOLE_CLIENTS];
    // Stdin stack: indices into clients[]; most recent is on top
    let mut stdin_stack: [usize; MAX_CONSOLE_CLIENTS] = [usize::MAX; MAX_CONSOLE_CLIENTS];
    let mut stdin_stack_len: usize = 0;
    let mut line_disc = LineDiscipline::new();
    let mut shift_pressed = false;
    let mut swap_seq: u32 = 10;

    // Print startup banner
    console.write_str(b"rvOS GUI Console\r\n");
    console.write_str(b"================\r\n\r\n");

    // Do initial present
    do_swap(&mut window_client, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
    // Re-point console to new back buffer
    update_console_fb(&mut console, fb_base, pixels_per_buffer, current_back);
    console.dirty = false;

    // Spawn /bin/shell with stdin/stdout connected to us
    let (stdin_our, stdin_shell) = raw::sys_chan_create();
    let (stdout_our, stdout_shell) = raw::sys_chan_create();

    // Spawn shell with stdin/stdout redirected to our channels
    match rvos::spawn_process_with_overrides(
        "/bin/shell",
        b"shell",
        &[
            rvos::NsOverride::Redirect("stdin", stdin_shell),
            rvos::NsOverride::Redirect("stdout", stdout_shell),
        ],
    ) {
        Ok(_proc_chan) => {
            println!("[fbcon] spawned /bin/shell");
        }
        Err(e) => {
            println!("[fbcon] ERROR: failed to spawn shell: {:?}", e);
        }
    }
    raw::sys_chan_close(stdin_shell);
    raw::sys_chan_close(stdout_shell);

    // Register shell as client 0
    clients[0] = Some(FbconClient {
        stdin: Channel::<FileResponseMsg, FileRequestMsg>::from_raw_handle(stdin_our),
        stdout: Channel::<FileResponseMsg, FileRequestMsg>::from_raw_handle(stdout_our),
        has_pending_read: false,
    });

    // Typed event channel
    let mut events = Channel::<Never, WindowEvent>::from_raw_handle(event_chan);

    // Main event loop
    loop {
        let mut handled = false;

        let stdin_idx = if stdin_stack_len > 0 { stdin_stack[stdin_stack_len - 1] } else { usize::MAX };

        // Check for keyboard events on event channel (typed)
        while let Some(event) = events.try_next_message() {
            handled = true;
            match event {
                WindowEvent::KeyDown { code } => {
                    let code = code as usize;
                    if code == 42 || code == 54 {
                        shift_pressed = true;
                    } else if let Some(seq) = escape_seq_for_keycode(code) {
                        // Special key: send full escape sequence in raw mode
                        if line_disc.raw_mode
                            && stdin_idx != usize::MAX {
                                if let Some(ref client) = clients[stdin_idx] {
                                    if client.has_pending_read {
                                        fb_send_data(&client.stdin, seq);
                                        fb_send_sentinel(&client.stdin);
                                    }
                                }
                                if let Some(ref mut client) = clients[stdin_idx] {
                                    client.has_pending_read = false;
                                }
                            }
                    } else if code < 128 {
                        let ascii = if shift_pressed {
                            KEYMAP_SHIFT[code]
                        } else {
                            KEYMAP[code]
                        };
                        if ascii != 0 {
                            handle_key_input(ascii, &mut console, &mut line_disc, &mut clients, stdin_idx);
                        }
                    }
                }
                WindowEvent::KeyUp { code } => {
                    let code = code as usize;
                    if code == 42 || code == 54 {
                        shift_pressed = false;
                    }
                }
                WindowEvent::CloseRequested {} => {
                    // Close window and exit
                    let _ = window_client.close_window();
                    return;
                }
                _ => {
                    // Ignore mouse events and other window events
                }
            }
        }

        // Poll stdin channels for Read/Ioctl requests (typed).
        // Also detect closed channels for dead client cleanup.
        #[allow(clippy::needless_range_loop)] // index needed for clients[i] = None
        for i in 0..MAX_CONSOLE_CLIENTS {
            if clients[i].is_none() { continue; }
            let mut closed = false;
            loop {
                let client = clients[i].as_mut().unwrap();
                match client.stdin.try_recv() {
                    Ok(FileRequest::Read { offset: _, len: _ }) => {
                        handled = true;
                        client.has_pending_read = true;
                        // Push onto stdin_stack on first Read (lazy)
                        let already = (0..stdin_stack_len).any(|j| stdin_stack[j] == i);
                        if !already && stdin_stack_len < MAX_CONSOLE_CLIENTS {
                            stdin_stack[stdin_stack_len] = i;
                            stdin_stack_len += 1;
                        }
                    }
                    Ok(FileRequest::Ioctl { cmd, arg: _ }) => {
                        handled = true;
                        match cmd {
                            TCRAW => { line_disc.raw_mode = true; fb_send_ioctl_ok(&client.stdin, 0); }
                            TCCOOKED => { line_disc.raw_mode = false; fb_send_ioctl_ok(&client.stdin, 0); }
                            _ => {
                                let _ = client.stdin.send(&FileResponse::Error { code: FsError::Io {} });
                            }
                        }
                    }
                    Ok(_) => {} // ignore unexpected requests on stdin
                    Err(rvos::RecvError::Closed) => { closed = true; handled = true; break; }
                    Err(_) => break,
                }
            }
            if closed {
                clients[i] = None; // channels auto-close on drop
                remove_from_stdin_stack(&mut stdin_stack, &mut stdin_stack_len, i);
            }
        }

        // Poll stdout channels for Write requests (typed).
        // Use two-phase pattern: recv+process in inner block, respond after.
        #[allow(clippy::needless_range_loop)] // index needed for clients[i] = None
        for i in 0..MAX_CONSOLE_CLIENTS {
            if clients[i].is_none() { continue; }
            let mut closed = false;
            loop {
                // Phase 1: recv and process (data borrows from channel buffer)
                let written: Option<u32> = {
                    let client = clients[i].as_mut().unwrap();
                    match client.stdout.try_recv() {
                        Ok(FileRequest::Write { offset: _, data }) => {
                            console.write_str(data);
                            Some(data.len() as u32)
                        }
                        Ok(_) => None,
                        Err(rvos::RecvError::Closed) => { closed = true; break; }
                        Err(_) => break,
                    }
                };
                // Phase 2: respond (borrow released)
                if let Some(w) = written {
                    handled = true;
                    fb_send_write_ok(&clients[i].as_ref().unwrap().stdout, w);
                }
            }
            if closed {
                handled = true;
                clients[i] = None;
                remove_from_stdin_stack(&mut stdin_stack, &mut stdin_stack_len, i);
            }
        }

        // If console is dirty, present the frame
        if console.dirty {
            console.toggle_cursor(); // draw cursor on back buffer
            do_swap(&mut window_client, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
            update_console_fb(&mut console, fb_base, pixels_per_buffer, current_back);
            console.toggle_cursor(); // erase cursor from new back buffer
            console.dirty = false;
            handled = true;
        }

        if !handled {
            // Register interest on all channels then block
            raw::sys_chan_poll_add(req_chan);
            events.poll_add();
            for client in clients.iter().flatten() {
                client.stdin.poll_add();
                client.stdout.poll_add();
            }
            raw::sys_block();
        }
    }
}

/// Remove a client index from the stdin stack.
fn remove_from_stdin_stack(
    stdin_stack: &mut [usize; MAX_CONSOLE_CLIENTS],
    stdin_stack_len: &mut usize,
    client_idx: usize,
) {
    let mut j = 0;
    while j < *stdin_stack_len {
        if stdin_stack[j] == client_idx {
            for k in j..*stdin_stack_len - 1 { stdin_stack[k] = stdin_stack[k + 1]; }
            *stdin_stack_len -= 1;
        } else {
            j += 1;
        }
    }
}

/// Map Linux keycodes for special keys to ANSI escape sequences.
fn escape_seq_for_keycode(code: usize) -> Option<&'static [u8]> {
    match code {
        103 => Some(b"\x1b[A"),  // KEY_UP
        108 => Some(b"\x1b[B"),  // KEY_DOWN
        106 => Some(b"\x1b[C"),  // KEY_RIGHT
        105 => Some(b"\x1b[D"),  // KEY_LEFT
        102 => Some(b"\x1b[H"),  // KEY_HOME
        107 => Some(b"\x1b[F"),  // KEY_END
        111 => Some(b"\x1b[3~"), // KEY_DELETE
        _ => None,
    }
}

fn handle_key_input(
    ascii: u8,
    console: &mut FbConsole,
    line_disc: &mut LineDiscipline,
    clients: &mut [Option<FbconClient>; MAX_CONSOLE_CLIENTS],
    stdin_idx: usize,
) {
    if line_disc.raw_mode {
        // Raw mode: no echo, fulfill pending read directly
        if let Some(len) = line_disc.push_char(ascii) {
            if stdin_idx != usize::MAX {
                if let Some(ref mut client) = clients[stdin_idx] {
                    if client.has_pending_read {
                        fb_send_data(&client.stdin, line_disc.line_data(len));
                        fb_send_sentinel(&client.stdin);
                        client.has_pending_read = false;
                    }
                }
            }
        }
        return;
    }

    // Echo to console
    match ascii {
        0x7F | 0x08 => {
            console.write_char(0x08);
            console.write_char(b' ');
            console.write_char(0x08);
        }
        b'\r' => {
            console.write_char(b'\r');
            console.write_char(b'\n');
        }
        ch => {
            console.write_char(ch);
        }
    }

    // Feed to line discipline
    if let Some(len) = line_disc.push_char(ascii) {
        let mut buf = [0u8; LINE_BUF_SIZE];
        let data = line_disc.line_data(len);
        buf[..len].copy_from_slice(data);
        if stdin_idx != usize::MAX {
            if let Some(ref mut client) = clients[stdin_idx] {
                if client.has_pending_read {
                    fb_send_data(&client.stdin, &buf[..len]);
                    fb_send_sentinel(&client.stdin);
                    client.has_pending_read = false;
                }
            }
        }
    }
}

/// Swap buffers, wait for swap reply, then copy front→new-back.
fn do_swap(
    window_client: &mut WindowClient<UserTransport>,
    seq: &mut u32,
    fb_base: *mut u32,
    pixels_per_buffer: usize,
    current_back: &mut u8,
) {
    // Send swap request and wait for reply
    let _ = window_client.swap_buffers(*seq);
    *seq = seq.wrapping_add(1);

    // Toggle back buffer
    *current_back = 1 - *current_back;

    // Copy front (what was just presented) → new back buffer
    let front_offset = if *current_back == 0 { pixels_per_buffer } else { 0 };
    let back_offset = if *current_back == 0 { 0 } else { pixels_per_buffer };
    unsafe {
        core::ptr::copy_nonoverlapping(
            fb_base.add(front_offset),
            fb_base.add(back_offset),
            pixels_per_buffer,
        );
    }
}

/// Update FbConsole's fb pointer to point at the current back buffer.
fn update_console_fb(console: &mut FbConsole, fb_base: *mut u32, pixels_per_buffer: usize, current_back: u8) {
    let offset = if current_back == 0 { 0 } else { pixels_per_buffer };
    console.fb = unsafe { fb_base.add(offset) };
}
