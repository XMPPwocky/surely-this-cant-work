use std::io::{self, Read, Write};

use rvos::raw;
use rvos::Message;
use rvos::Channel;
use rvos::UserTransport;
use rvos::rvos_wire::{self, Never};
use rvos::rvos_proto;
use rvos_proto::math::MathClient;
use rvos_proto::process::ExitNotification;
use rvos_proto::sysinfo::SysinfoCommand;

/// Request a service from the init server via boot channel (handle 0).
fn request_service(name: &str) -> usize {
    match rvos::connect_to_service(name) {
        Ok(ch) => ch.into_raw_handle(),
        Err(_) => usize::MAX,
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
    println!("Commands:");
    println!("  echo <text>           - Print text");
    println!("  math <op> <a> <b>     - Compute math (add/mul/sub)");
    println!("  ps                    - Show process list");
    println!("  mem                   - Show kernel memory stats");
    println!("  trace [clear]         - Show/clear trace ring buffer");
    println!("  ls [path]             - List directory");
    println!("  cat <path>            - Read file");
    println!("  write <path> <text>   - Write to file");
    println!("  stat <path>           - Show file metadata");
    println!("  run <path> [args...]  - Run program (& for background, > for redirect)");
    println!("  clear                 - Clear screen");
    println!("  help                  - Show this help");
    println!("  shutdown              - Shut down the system");
    println!();
    println!("Line editing:");
    println!("  Left/Right, Ctrl+B/F  - Move cursor");
    println!("  Home/End, Ctrl+A/E    - Jump to start/end of line");
    println!("  Up/Down, Ctrl+P/N     - History navigation");
    println!("  Ctrl+R                - Reverse history search");
    println!("  Tab                   - Auto-complete");
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
    raw::sys_chan_send_blocking(sysinfo_handle, &msg);

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

/// Rebuild the null-separated args blob from argv0 and remaining args string.
/// Returns the total length written into the blob.
fn rebuild_args(blob: &mut [u8; 512], argv0: &str, rest: &str) -> usize {
    let mut len = 0;
    let copy_len = argv0.len().min(512);
    blob[..copy_len].copy_from_slice(argv0.as_bytes());
    len += copy_len;

    if !rest.is_empty() {
        for arg in rest.split_whitespace() {
            if len + 1 + arg.len() > 512 {
                break;
            }
            blob[len] = 0; // null separator
            len += 1;
            blob[len..len + arg.len()].copy_from_slice(arg.as_bytes());
            len += arg.len();
        }
    }
    len
}

/// Wait for a child process to exit via its process handle channel, print exit code.
fn wait_for_exit(proc_handle: usize) {
    let mut proc_ch = Channel::<Never, ExitNotification>::from_raw_handle(proc_handle);
    let exit_code = match proc_ch.next_message() {
        Some(notif) => notif.exit_code,
        None => -1,
    };
    println!("Process exited with code {}", exit_code);
    // Channel dropped here → handle closed automatically
}

fn cmd_run(args: &str) {
    let args_str = args.trim();
    if args_str.is_empty() {
        println!("Usage: run <path> [args...]  (append & to run in background)");
        return;
    }

    // Check for trailing '&' (background execution)
    let (args_str, background) = if let Some(stripped) = args_str.strip_suffix('&') {
        (stripped.trim(), true)
    } else {
        (args_str, false)
    };

    // Split into path and arguments
    let (path, rest) = match args_str.split_once(' ') {
        Some((p, r)) => (p, r.trim()),
        None => (args_str, ""),
    };

    // Build null-separated args blob: argv[0] is the binary name (last component of path)
    let mut args_blob = [0u8; 512];
    let mut args_len = 0;

    // argv[0] = binary name (everything after last '/')
    let argv0 = match path.rfind('/') {
        Some(pos) => &path[pos + 1..],
        None => path,
    };
    let copy_len = argv0.len().min(512);
    args_blob[..copy_len].copy_from_slice(argv0.as_bytes());
    args_len += copy_len;

    // Append remaining arguments, null-separated
    if !rest.is_empty() {
        for arg in rest.split_whitespace() {
            if args_len + 1 + arg.len() > 512 {
                break;
            }
            args_blob[args_len] = 0; // null separator
            args_len += 1;
            args_blob[args_len..args_len + arg.len()].copy_from_slice(arg.as_bytes());
            args_len += arg.len();
        }
    }

    // Parse stdout redirect: > (truncate) or >> (append)
    let mut redirect_path: Option<&str> = None;
    let mut redirect_append = false;
    let mut actual_args_len = args_len;

    // Search for > or >> in the original command (not in args_blob)
    // We'll re-parse from the rest string to find redirect
    if let Some(pos) = rest.find(">>") {
        redirect_path = Some(rest[pos + 2..].trim());
        redirect_append = true;
        // Rebuild args without the redirect part
        let clean_rest = rest[..pos].trim();
        actual_args_len = rebuild_args(&mut args_blob, argv0, clean_rest);
    } else if let Some(pos) = rest.find('>') {
        redirect_path = Some(rest[pos + 1..].trim());
        redirect_append = false;
        let clean_rest = rest[..pos].trim();
        actual_args_len = rebuild_args(&mut args_blob, argv0, clean_rest);
    }

    // If redirecting, open the file and spawn with ns_overrides
    let mut redirect_handle: Option<usize> = None;

    if let Some(redir_path) = redirect_path {
        if redir_path.is_empty() {
            println!("Error: redirect path is empty");
            return;
        }
        use rvos::rvos_proto::fs::OpenFlags;
        let flags = if redirect_append {
            OpenFlags::CREATE.or(OpenFlags::APPEND)
        } else {
            OpenFlags::CREATE.or(OpenFlags::TRUNCATE)
        };
        match rvos::fs::file_open_raw(redir_path, flags) {
            Ok(fh) => {
                redirect_handle = Some(fh);
            }
            Err(_) => {
                println!("Error: could not open {} for redirect", redir_path);
                return;
            }
        }
    }

    // Send Spawn request on boot channel (handle 0)
    if let Some(rh) = redirect_handle {
        // Spawn with stdout redirected to file
        let proc_chan = rvos::spawn_process_with_overrides(
            path,
            &args_blob[..actual_args_len],
            &[rvos::NsOverride::Redirect("stdout", rh)],
        );
        raw::sys_chan_close(rh);
        match proc_chan {
            Ok(ch) => {
                let proc_handle = ch.into_raw_handle();
                if background {
                    println!("Started in background");
                    raw::sys_chan_close(proc_handle);
                } else {
                    wait_for_exit(proc_handle);
                }
            }
            Err(_) => {
                println!("Spawn failed");
                return;
            }
        }
        return;
    }

    match rvos::spawn_process_with_args(path, &args_blob[..actual_args_len]) {
        Ok(ch) => {
            let proc_handle = ch.into_raw_handle();
            if background {
                println!("Started in background");
                raw::sys_chan_close(proc_handle);
            } else {
                wait_for_exit(proc_handle);
            }
        }
        Err(_) => {
            println!("Spawn failed");
        }
    }
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
        } else if let Some(stripped) = prefix.strip_prefix('/') {
            match prefix.rfind('/') {
                Some(0) => ("/", stripped),
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

// --- History Ring ---

const HISTORY_MAX: usize = 64;
const HISTORY_ENTRY_MAX: usize = 256;

struct HistoryRing {
    entries: Box<[[u8; HISTORY_ENTRY_MAX]; HISTORY_MAX]>,
    lengths: [usize; HISTORY_MAX],
    head: usize,
    count: usize,
}

impl HistoryRing {
    fn new() -> Self {
        HistoryRing {
            entries: Box::new([[0u8; HISTORY_ENTRY_MAX]; HISTORY_MAX]),
            lengths: [0; HISTORY_MAX],
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, line: &[u8]) {
        if line.is_empty() { return; }
        let store_len = line.len().min(HISTORY_ENTRY_MAX);
        // Deduplicate consecutive entries
        if self.count > 0 {
            let last = if self.head == 0 { HISTORY_MAX - 1 } else { self.head - 1 };
            if self.lengths[last] == store_len
                && self.entries[last][..store_len] == line[..store_len]
            {
                return;
            }
        }
        self.entries[self.head][..store_len].copy_from_slice(&line[..store_len]);
        self.lengths[self.head] = store_len;
        self.head = (self.head + 1) % HISTORY_MAX;
        if self.count < HISTORY_MAX {
            self.count += 1;
        }
    }

    /// Get entry by index (0 = most recent).
    fn get(&self, index: usize) -> Option<&[u8]> {
        if index >= self.count { return None; }
        let pos = if self.head > index {
            self.head - 1 - index
        } else {
            HISTORY_MAX + self.head - 1 - index
        };
        Some(&self.entries[pos][..self.lengths[pos]])
    }

    /// Search for needle as substring, starting from `start_index`.
    fn search(&self, needle: &[u8], start_index: usize) -> Option<usize> {
        for i in start_index..self.count {
            if let Some(entry) = self.get(i) {
                if bytes_contains(entry, needle) {
                    return Some(i);
                }
            }
        }
        None
    }
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    for i in 0..=haystack.len() - needle.len() {
        if haystack[i..i + needle.len()] == *needle {
            return true;
        }
    }
    false
}

// --- Line Editor ---

const LINE_MAX: usize = 256;
const SEARCH_MAX: usize = 64;
const PROMPT: &str = "rvos> ";

struct LineEditor {
    buf: [u8; LINE_MAX],
    len: usize,
    cursor: usize,
    // History navigation state
    hist_index: Option<usize>,
    saved_buf: [u8; LINE_MAX],
    saved_len: usize,
    // Reverse search state
    search_mode: bool,
    search_buf: [u8; SEARCH_MAX],
    search_len: usize,
    search_match: Option<usize>,
    search_saved_buf: [u8; LINE_MAX],
    search_saved_len: usize,
}

impl LineEditor {
    fn new() -> Self {
        LineEditor {
            buf: [0; LINE_MAX],
            len: 0,
            cursor: 0,
            hist_index: None,
            saved_buf: [0; LINE_MAX],
            saved_len: 0,
            search_mode: false,
            search_buf: [0; SEARCH_MAX],
            search_len: 0,
            search_match: None,
            search_saved_buf: [0; LINE_MAX],
            search_saved_len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.cursor = 0;
        self.hist_index = None;
        self.search_mode = false;
        self.search_len = 0;
        self.search_match = None;
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    /// Redraw the entire line (prompt + buffer + erase trailing + reposition cursor).
    fn refresh_line(&self) {
        let mut out = io::stdout();
        write!(out, "\r{}", PROMPT).ok();
        out.write_all(&self.buf[..self.len]).ok();
        write!(out, "\x1b[K").ok();
        let back = self.len - self.cursor;
        if back > 0 {
            write!(out, "\x1b[{}D", back).ok();
        }
        out.flush().ok();
    }

    fn insert_char(&mut self, ch: u8) {
        if self.len >= LINE_MAX { return; }
        if self.cursor == self.len {
            self.buf[self.len] = ch;
            self.len += 1;
            self.cursor += 1;
            io::stdout().write_all(&[ch]).ok();
            io::stdout().flush().ok();
        } else {
            // Shift right to make room
            let mut i = self.len;
            while i > self.cursor {
                self.buf[i] = self.buf[i - 1];
                i -= 1;
            }
            self.buf[self.cursor] = ch;
            self.len += 1;
            self.cursor += 1;
            self.refresh_line();
        }
    }

    fn delete_at_cursor(&mut self) {
        if self.cursor >= self.len { return; }
        for i in self.cursor..self.len - 1 {
            self.buf[i] = self.buf[i + 1];
        }
        self.len -= 1;
        self.refresh_line();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 { return; }
        self.cursor -= 1;
        self.delete_at_cursor();
    }

    fn move_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            write!(io::stdout(), "\x1b[D").ok();
            io::stdout().flush().ok();
        }
    }

    fn move_right(&mut self) {
        if self.cursor < self.len {
            self.cursor += 1;
            write!(io::stdout(), "\x1b[C").ok();
            io::stdout().flush().ok();
        }
    }

    fn move_home(&mut self) {
        if self.cursor > 0 {
            write!(io::stdout(), "\x1b[{}D", self.cursor).ok();
            self.cursor = 0;
            io::stdout().flush().ok();
        }
    }

    fn move_end(&mut self) {
        if self.cursor < self.len {
            write!(io::stdout(), "\x1b[{}C", self.len - self.cursor).ok();
            self.cursor = self.len;
            io::stdout().flush().ok();
        }
    }

    /// Replace the entire line buffer with new content and redraw.
    fn set_line(&mut self, line: &[u8]) {
        let copy_len = line.len().min(LINE_MAX);
        self.buf[..copy_len].copy_from_slice(&line[..copy_len]);
        self.len = copy_len;
        self.cursor = copy_len;
        self.refresh_line();
    }

    fn history_prev(&mut self, history: &HistoryRing) {
        if history.count == 0 { return; }
        match self.hist_index {
            None => {
                // Save current line before entering history
                self.saved_buf[..self.len].copy_from_slice(&self.buf[..self.len]);
                self.saved_len = self.len;
                self.hist_index = Some(0);
            }
            Some(i) => {
                if i + 1 >= history.count { return; }
                self.hist_index = Some(i + 1);
            }
        }
        if let Some(entry) = history.get(self.hist_index.unwrap()) {
            // Copy through a temp to avoid aliasing issues
            let mut tmp = [0u8; LINE_MAX];
            let tlen = entry.len().min(LINE_MAX);
            tmp[..tlen].copy_from_slice(&entry[..tlen]);
            self.set_line(&tmp[..tlen]);
        }
    }

    fn history_next(&mut self, history: &HistoryRing) {
        match self.hist_index {
            None => (),
            Some(0) => {
                // Restore the saved original line
                self.hist_index = None;
                let len = self.saved_len;
                // Copy saved → buf (fields don't alias)
                self.buf[..len].copy_from_slice(&self.saved_buf[..len]);
                self.len = len;
                self.cursor = len;
                self.refresh_line();
            }
            Some(i) => {
                self.hist_index = Some(i - 1);
                if let Some(entry) = history.get(i - 1) {
                    let mut tmp = [0u8; LINE_MAX];
                    let tlen = entry.len().min(LINE_MAX);
                    tmp[..tlen].copy_from_slice(&entry[..tlen]);
                    self.set_line(&tmp[..tlen]);
                }
            }
        }
    }

    // --- Reverse search ---

    fn enter_search(&mut self) {
        self.search_saved_buf[..self.len].copy_from_slice(&self.buf[..self.len]);
        self.search_saved_len = self.len;
        self.search_mode = true;
        self.search_len = 0;
        self.search_match = None;
        self.refresh_search_prompt(None);
    }

    fn refresh_search_prompt(&self, history: Option<&HistoryRing>) {
        let mut out = io::stdout();
        write!(out, "\r\x1b[K(reverse-i-search)'").ok();
        out.write_all(&self.search_buf[..self.search_len]).ok();
        write!(out, "': ").ok();
        if let (Some(idx), Some(hist)) = (self.search_match, history) {
            if let Some(entry) = hist.get(idx) {
                out.write_all(entry).ok();
            }
        }
        out.flush().ok();
    }

    fn search_push_char(&mut self, ch: u8, history: &HistoryRing) {
        if self.search_len >= SEARCH_MAX { return; }
        self.search_buf[self.search_len] = ch;
        self.search_len += 1;
        // Search from the beginning (or from current match)
        let start = 0;
        self.search_match = history.search(&self.search_buf[..self.search_len], start);
        self.refresh_search_prompt(Some(history));
    }

    fn search_backspace(&mut self, history: &HistoryRing) {
        if self.search_len == 0 { return; }
        self.search_len -= 1;
        // Re-search from beginning with shorter query
        if self.search_len > 0 {
            self.search_match = history.search(&self.search_buf[..self.search_len], 0);
        } else {
            self.search_match = None;
        }
        self.refresh_search_prompt(Some(history));
    }

    fn search_next(&mut self, history: &HistoryRing) {
        if self.search_len == 0 { return; }
        let start = match self.search_match {
            Some(i) => i + 1,
            None => 0,
        };
        if let Some(idx) = history.search(&self.search_buf[..self.search_len], start) {
            self.search_match = Some(idx);
        }
        self.refresh_search_prompt(Some(history));
    }

    /// Accept the current search result: copy matched line into buffer, exit search.
    fn accept_search(&mut self, history: &HistoryRing) {
        self.search_mode = false;
        if let Some(idx) = self.search_match {
            if let Some(entry) = history.get(idx) {
                let copy_len = entry.len().min(LINE_MAX);
                self.buf[..copy_len].copy_from_slice(&entry[..copy_len]);
                self.len = copy_len;
                self.cursor = copy_len;
            }
        }
        // Redraw with normal prompt
        self.hist_index = None;
        self.refresh_line();
    }

    /// Cancel search: restore original line, exit search.
    fn cancel_search(&mut self) {
        self.search_mode = false;
        let len = self.search_saved_len;
        self.buf[..len].copy_from_slice(&self.search_saved_buf[..len]);
        self.len = len;
        self.cursor = len;
        self.refresh_line();
    }
}

// --- Tab completion (cursor-aware) ---

fn handle_tab(editor: &mut LineEditor) {
    let line_str = core::str::from_utf8(&editor.buf[..editor.len]).unwrap_or("");
    match try_complete(line_str) {
        Completion::Single(text, replace_from) => {
            // Replace from replace_from to end of line with the completion + space
            editor.len = replace_from;
            let text_bytes = text.as_bytes();
            let avail = LINE_MAX - editor.len;
            let copy = text_bytes.len().min(avail);
            editor.buf[editor.len..editor.len + copy]
                .copy_from_slice(&text_bytes[..copy]);
            editor.len += copy;
            if editor.len < LINE_MAX {
                editor.buf[editor.len] = b' ';
                editor.len += 1;
            }
            editor.cursor = editor.len;
            editor.refresh_line();
        }
        Completion::Multiple(matches) => {
            print!("\r\n");
            for m in &matches {
                print!("{}  ", m);
            }
            print!("\r\n");
            io::stdout().flush().ok();
            // Reprint prompt + current line
            editor.refresh_line();
        }
        Completion::None => {}
    }
}

// --- Console raw mode control ---

fn set_raw_mode(enable: bool) {
    io::stdout().flush().ok();
    let h = std::os::rvos::stdin_handle();
    if h != 0 {
        let cmd = if enable { rvos_proto::fs::TCRAW } else { rvos_proto::fs::TCCOOKED };
        if let Err(e) = rvos::tty::ioctl(h, cmd, 0) {
            eprintln!("tty ioctl failed: {:?}", e);
        }
    }
}

// --- Escape sequence parser state ---

enum EscState {
    Normal,
    Escape,
    Csi,
}

// --- Main shell loop ---

pub fn run() {
    println!("\nrvOS shell v0.2");
    println!("Type 'help' for available commands.\n");

    set_raw_mode(true);

    let mut history = HistoryRing::new();
    let mut editor = LineEditor::new();
    let mut byte = [0u8; 1];

    loop {
        print!("{}", PROMPT);
        io::stdout().flush().ok();
        editor.clear();

        let mut esc_state = EscState::Normal;
        let mut csi_param: u32 = 0;
        let mut submit = false;

        loop {
            if io::stdin().lock().read(&mut byte).unwrap_or(0) == 0 {
                // EOF on stdin — parent process (e.g. fbcon) exited
                return;
            }
            let ch = byte[0];

            match esc_state {
                EscState::Normal => {
                    if ch == 0x1B {
                        esc_state = EscState::Escape;
                        continue;
                    }
                    if editor.search_mode {
                        match ch {
                            b'\r' | b'\n' => {
                                editor.accept_search(&history);
                                print!("\r\n");
                                io::stdout().flush().ok();
                                submit = true;
                                break;
                            }
                            0x7F | 0x08 => editor.search_backspace(&history),
                            0x12 => editor.search_next(&history), // Ctrl+R
                            0x07 => editor.cancel_search(),        // Ctrl+G
                            0x03 => {
                                // Ctrl+C: cancel search + clear + new prompt
                                editor.search_mode = false;
                                editor.clear();
                                print!("^C\r\n");
                                io::stdout().flush().ok();
                                break;
                            }
                            c if (0x20..0x7F).contains(&c) => {
                                editor.search_push_char(c, &history);
                            }
                            _ => {}
                        }
                    } else {
                        match ch {
                            b'\r' | b'\n' => {
                                print!("\r\n");
                                io::stdout().flush().ok();
                                submit = true;
                                break;
                            }
                            0x7F | 0x08 => editor.backspace(),
                            0x09 => handle_tab(&mut editor),     // Tab
                            0x01 => editor.move_home(),           // Ctrl+A
                            0x02 => editor.move_left(),           // Ctrl+B
                            0x05 => editor.move_end(),            // Ctrl+E
                            0x06 => editor.move_right(),          // Ctrl+F
                            0x10 => editor.history_prev(&history), // Ctrl+P
                            0x0E => editor.history_next(&history), // Ctrl+N
                            0x12 => editor.enter_search(),        // Ctrl+R
                            0x03 => {
                                print!("^C\r\n");
                                io::stdout().flush().ok();
                                editor.clear();
                                break;
                            }
                            c if (0x20..0x7F).contains(&c) => {
                                editor.insert_char(c);
                            }
                            _ => {}
                        }
                    }
                }
                EscState::Escape => {
                    if ch == b'[' {
                        esc_state = EscState::Csi;
                        csi_param = 0;
                    } else if ch == 0x1B {
                        // Double-escape: stay in escape state
                    } else {
                        esc_state = EscState::Normal;
                        // Bare Escape: cancel search if active
                        if editor.search_mode {
                            editor.cancel_search();
                        }
                        // Don't re-process byte (it was consumed as part of escape)
                    }
                }
                EscState::Csi => {
                    if ch.is_ascii_digit() {
                        csi_param = csi_param * 10 + (ch - b'0') as u32;
                        continue;
                    }
                    esc_state = EscState::Normal;

                    // If in search mode, exit search on arrow keys
                    if editor.search_mode {
                        if ch == b'A' || ch == b'B' {
                            editor.accept_search(&history);
                        } else {
                            continue; // ignore other CSI sequences in search
                        }
                    }

                    match ch {
                        b'A' => editor.history_prev(&history), // Up
                        b'B' => editor.history_next(&history), // Down
                        b'C' => editor.move_right(),           // Right
                        b'D' => editor.move_left(),            // Left
                        b'H' => editor.move_home(),            // Home
                        b'F' => editor.move_end(),             // End
                        b'~' => match csi_param {
                            3 => editor.delete_at_cursor(), // Delete
                            1 => editor.move_home(),        // Home (alt)
                            4 => editor.move_end(),         // End (alt)
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }

        if !submit {
            continue;
        }

        let line = editor.as_str().trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Push to history before executing
        history.push(line.as_bytes());

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
                let args = line.split_once(' ').map(|x| x.1).unwrap_or("");
                cmd_trace(args);
            }
            "cat" | "read" => {
                let args = line.split_once(' ').map(|x| x.1).unwrap_or("");
                cmd_cat(args);
            }
            "write" => {
                let args = line.split_once(' ').map(|x| x.1).unwrap_or("");
                cmd_write(args);
            }
            "ls" => {
                let args = line.split_once(' ').map(|x| x.1).unwrap_or("");
                cmd_ls(args);
            }
            "stat" => {
                let args = line.split_once(' ').map(|x| x.1).unwrap_or("");
                cmd_stat(args);
            }
            "run" => {
                let args = line.split_once(' ').map(|x| x.1).unwrap_or("");
                set_raw_mode(false);
                cmd_run(args);
                set_raw_mode(true);
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
