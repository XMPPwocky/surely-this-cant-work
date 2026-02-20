extern crate rvos_rt;

use rvos::raw;
use rvos::UserTransport;
use rvos::rvos_wire::Never;
use rvos_proto::window::{
    CreateWindowRequest, CreateWindowResponse,
    WindowReply, WindowEvent, WindowClient,
};
use rvos::Channel;
use termserv::{TermOutput, TermServer};

// --- Font data (shared from rvos-gfx) ---

use rvos_gfx::font::{FONT_8X16, GLYPH_WIDTH, GLYPH_HEIGHT};

const FONT_WIDTH: u32 = GLYPH_WIDTH;
const FONT_HEIGHT: u32 = GLYPH_HEIGHT;

// --- Keymap data (Linux keycodes -> ASCII) ---

static KEYMAP: [u8; 128] = {
    let mut map = [0u8; 128];
    map[1] = 0x1B; // ESC
    map[2] = b'1'; map[3] = b'2'; map[4] = b'3'; map[5] = b'4';
    map[6] = b'5'; map[7] = b'6'; map[8] = b'7'; map[9] = b'8';
    map[10] = b'9'; map[11] = b'0'; map[12] = b'-'; map[13] = b'=';
    map[14] = 0x7F; // Backspace -> DEL
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
    map[14] = 0x7F; // Backspace -> DEL
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
                let n = if p0 == 0 { 1 } else { p0 };
                self.row = self.row.saturating_sub(n);
                self.dirty = true;
            }
            b'B' => {
                let n = if p0 == 0 { 1 } else { p0 };
                self.row = (self.row + n).min(self.rows - 1);
                self.dirty = true;
            }
            b'C' => {
                let n = if p0 == 0 { 1 } else { p0 };
                self.col = (self.col + n).min(self.cols - 1);
                self.dirty = true;
            }
            b'D' => {
                let n = if p0 == 0 { 1 } else { p0 };
                self.col = self.col.saturating_sub(n);
                self.dirty = true;
            }
            b'H' | b'f' => {
                let row = if p0 == 0 { 0 } else { p0 - 1 };
                let col = if p1 == 0 { 0 } else { p1 - 1 };
                self.row = row.min(self.rows - 1);
                self.col = col.min(self.cols - 1);
                self.dirty = true;
            }
            b'J' => {
                if p0 == 2 {
                    let total = (self.stride * self.height) as usize;
                    for i in 0..total {
                        unsafe { *self.fb.add(i) = self.bg; }
                    }
                    self.dirty = true;
                }
            }
            b'K' => {
                if p0 == 0 {
                    for c in self.col..self.cols {
                        self.put_char(c, self.row, b' ');
                    }
                    self.dirty = true;
                }
            }
            _ => {}
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
            for i in copy_pixels..total_pixels {
                *self.fb.add(i) = self.bg;
            }
        }
    }

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

// --- TermOutput implementation for fbcon ---

struct FbOutput<'a> {
    console: &'a mut FbConsole,
}

impl TermOutput for FbOutput<'_> {
    fn write_output(&mut self, data: &[u8]) {
        self.console.write_str(data);
    }

    fn echo_char(&mut self, ch: u8) {
        self.console.write_char(ch);
    }

    fn echo_backspace(&mut self) {
        self.console.write_char(0x08);
        self.console.write_char(b' ');
        self.console.write_char(0x08);
    }

    fn echo_newline(&mut self) {
        self.console.write_char(b'\r');
        self.console.write_char(b'\n');
    }
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

    // 5. GetFramebuffer -> receive SHM handle
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
    let mut term = TermServer::new();
    let mut shift_pressed = false;
    let mut ctrl_pressed = false;
    let mut swap_seq: u32 = 10;

    // Print startup banner
    console.write_str(b"rvOS GUI Console\r\n");
    console.write_str(b"================\r\n\r\n");

    // Do initial present
    do_swap(&mut window_client, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
    update_console_fb(&mut console, fb_base, pixels_per_buffer, current_back);
    console.dirty = false;

    // Spawn /bin/shell with stdin/stdout connected to us
    let (stdin_our, stdin_shell) = raw::sys_chan_create();
    let (stdout_our, stdout_shell) = raw::sys_chan_create();

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

    // Register shell as a terminal client
    term.add_client(stdin_our, stdout_our);

    // Typed event channel
    let mut events = Channel::<Never, WindowEvent>::from_raw_handle(event_chan);

    // Main event loop
    loop {
        let mut handled = false;

        // Check for keyboard events on event channel
        while let Some(event) = events.try_next_message() {
            handled = true;
            match event {
                WindowEvent::KeyDown { code } => {
                    let code = code as usize;
                    if code == 42 || code == 54 {
                        shift_pressed = true;
                    } else if code == 29 || code == 97 {
                        ctrl_pressed = true;
                    } else if let Some(seq) = escape_seq_for_keycode(code) {
                        // Special key: send escape sequence in raw mode
                        if term.is_raw_mode() {
                            term.feed_raw(seq);
                        }
                    } else if code < 128 {
                        let base = if shift_pressed {
                            KEYMAP_SHIFT[code]
                        } else {
                            KEYMAP[code]
                        };
                        let ascii = if ctrl_pressed && base.is_ascii_lowercase() {
                            base & 0x1F
                        } else {
                            base
                        };
                        if ascii != 0 {
                            let mut fb_out = FbOutput { console: &mut console };
                            term.feed_input(ascii, &mut fb_out);
                        }
                    }
                }
                WindowEvent::KeyUp { code } => {
                    let code = code as usize;
                    if code == 42 || code == 54 {
                        shift_pressed = false;
                    } else if code == 29 || code == 97 {
                        ctrl_pressed = false;
                    }
                }
                WindowEvent::CloseRequested {} => {
                    let _ = window_client.close_window();
                    return;
                }
                _ => {}
            }
        }

        // Poll client channels for FileOps requests
        {
            let mut fb_out = FbOutput { console: &mut console };
            if term.poll_stdin() { handled = true; }
            if term.poll_stdout(&mut fb_out) { handled = true; }
        }

        // If console is dirty, present the frame
        if console.dirty {
            console.toggle_cursor();
            do_swap(&mut window_client, &mut swap_seq, fb_base, pixels_per_buffer, &mut current_back);
            update_console_fb(&mut console, fb_base, pixels_per_buffer, current_back);
            console.toggle_cursor();
            console.dirty = false;
            handled = true;
        }

        if !handled {
            raw::sys_chan_poll_add(req_chan);
            events.poll_add();
            term.poll_add_all();
            raw::sys_block();
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

/// Swap buffers, wait for swap reply, then copy front->new-back.
fn do_swap(
    window_client: &mut WindowClient<UserTransport>,
    seq: &mut u32,
    fb_base: *mut u32,
    pixels_per_buffer: usize,
    current_back: &mut u8,
) {
    let _ = window_client.swap_buffers(*seq);
    *seq = seq.wrapping_add(1);
    *current_back = 1 - *current_back;
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
