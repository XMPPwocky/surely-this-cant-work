# 0009: Terminal Server Library and nc Exec Mode

**Date:** 2026-02-20
**Status:** Design
**Subsystem:** lib/termserv (new), user/nc, user/fbcon

## Motivation

Users want to spawn a command with its stdio connected to netcat — a
reverse shell (`nc -e /bin/sh host port`). The naive approach (shell pipe
operator with a relay process) requires a middleman because both sides of
a pipe are FileOps *clients* — neither acts as a server.

Better insight: nc should act as a **terminal server** for the spawned
process. The child sends `FileRequest::Write` and nc puts the bytes on
the wire; the child sends `FileRequest::Read` and nc responds with data
from the wire. nc *is* the console, just like fbcon or serial. No relay,
no protocol translation, zero extra processes.

But rvOS already has two things shaped like terminal servers (kernel serial
console, fbcon GUI console), and they share substantial duplicated code:

- LineDiscipline (line buffer, raw/cooked mode, backspace/enter handling)
- FileOps server dispatch (Read, Write, Ioctl request handling)
- Response helpers (Data chunking, WriteOk, IoctlOk, sentinel)
- Client management (stdin/stdout channel pairs, pending-read tracking)
- Stdin stack (multiplexing input to most-recent client)
- Ioctl handling (TCRAW, TCCOOKED, TCSETFG)
- Ctrl+C / foreground PID kill

Rather than copy all this into nc, extract a **terminal server library**
(`lib/termserv`) that handles the shared logic. Backends provide only
three I/O primitives: write output, echo a character, echo
backspace/newline.

The kernel serial console stays as-is (it's a kernel task with different
constraints). The library is user-space only.

## Design

### Overview

Three deliverables:

1. **`lib/termserv`** — user-space library crate. Extracted from fbcon.
   Handles: LineDiscipline, FileOps server protocol, client management,
   stdin stack, ioctl dispatch, Ctrl+C, response serialization.

2. **`nc -e <cmd>`** — exec mode for netcat. nc connects (or listens),
   spawns `<cmd>` with stdio overridden, and runs a TermServer with a
   network backend.

3. **Refactor fbcon** — replace the duplicated logic with termserv calls.
   Behavioral no-op; same functionality, less code.

### Terminal Server Library API

```rust
// lib/termserv/src/lib.rs

/// Backend trait — the only thing each console implementation provides.
pub trait TermOutput {
    /// Data from a client's stdout (they called write/println).
    fn write_output(&mut self, data: &[u8]);
    /// Echo a printable char during cooked-mode line editing.
    fn echo_char(&mut self, ch: u8);
    /// Echo a backspace (BS, space, BS).
    fn echo_backspace(&mut self);
    /// Echo a newline (CR, LF) when Enter is pressed.
    fn echo_newline(&mut self);
}

pub struct TermServer<const N: usize> { ... }

impl<const N: usize> TermServer<N> {
    pub fn new() -> Self;

    /// Register a client. Takes ownership of raw stdin/stdout handles.
    pub fn add_client(&mut self, stdin_h: usize, stdout_h: usize)
        -> Option<usize>;

    /// Feed a byte from the input source (keyboard, network, etc.)
    /// through the line discipline. Delivers to top-of-stack client.
    pub fn feed_input(&mut self, ch: u8, output: &mut impl TermOutput);

    /// Feed raw bytes directly to the pending reader, bypassing line
    /// discipline. For escape sequences, binary data, etc.
    pub fn feed_raw(&mut self, data: &[u8]);

    /// Poll all stdin channels for Read/Ioctl. Returns true if work done.
    pub fn poll_stdin(&mut self) -> bool;

    /// Poll all stdout channels for Write. Returns true if work done.
    pub fn poll_stdout(&mut self, output: &mut impl TermOutput) -> bool;

    /// Register all active client channels for poll_add.
    pub fn poll_add_all(&self);

    /// Any clients still alive?
    pub fn has_active_clients(&self) -> bool;
}
```

**What moves into termserv (from fbcon):**

| Component | fbcon lines | Notes |
|-----------|------------|-------|
| `LineDiscipline` | 344-395 | Unchanged |
| `TermClient` (was `FbconClient`) | 403-407 | Owns typed Channel pairs |
| Response helpers | 410-426 | `send_data`, `send_sentinel`, `send_write_ok`, `send_ioctl_ok` |
| Stdin poll loop | 608-643 | Read/Ioctl dispatch, pending-read tracking |
| Stdout poll loop | 646-677 | Write dispatch, two-phase recv/respond |
| Stdin stack | 489-490, 618-622, 703-716 | Lazy push on first Read, removal on close |
| Key input dispatch | 733-795 | Ctrl+C, raw/cooked branching, line disc feeding |
| Dead client cleanup | 640-643, 672-675 | Channel closed detection |

**What stays in fbcon:**

- `FbConsole` (framebuffer rendering, ANSI escape parsing, glyph rasterization, scrolling, cursor)
- Window server integration (CreateWindow, GetFramebuffer, SwapBuffers)
- Keyboard event handling (keymap tables, shift/ctrl state, escape sequences for special keys)
- `main()` setup

### nc Exec Mode

**Syntax:**

```
nc -e <cmd> <host> <port>        # connect mode: connect, then exec
nc -l -e <cmd> <port>            # listen mode: accept, then exec
```

**Architecture:**

```
Remote host                    rvOS
                          nc (TermServer<8>)            /bin/sh
  terminal  <--TCP--->  NetOutput backend  <--FileOps-->  child
                         (write_output      (Write/Read
                          = send over TCP,   requests on
                          echo = no-op)      overridden
                                             stdin/stdout)
```

**nc exec mode flow:**

1. Parse `-e <cmd>` from arguments
2. Connect to host:port (or listen+accept) — existing nc code
3. Create channel pairs for child's stdin and stdout
4. `spawn_process_with_overrides(cmd, ...)` with stdin/stdout overridden
5. Close the child-side endpoints (shell owns server-side only)
6. Create `TermServer<8>`, add child as client
7. Main loop:
   - `poll_add` on socket channel + `term.poll_add_all()`
   - `sys_block()`
   - Non-blocking recv on socket → `term.feed_input()` for each byte
   - `term.poll_stdin()` + `term.poll_stdout(&mut net_output)`
   - If socket closed or no active clients → break

**NetOutput backend:**

```rust
struct NetOutput { sock_h: usize }

impl TermOutput for NetOutput {
    fn write_output(&mut self, data: &[u8]) {
        // Send data over TCP socket
        socket_send(self.sock_h, data);
    }
    fn echo_char(&mut self, _ch: u8) {}     // no echo — remote handles it
    fn echo_backspace(&mut self) {}
    fn echo_newline(&mut self) {}
}
```

No echo: the remote terminal (the user's local terminal emulator)
handles local echo. nc is a transparent pipe, not a local console.

**Why TermServer<8>?** The spawned child (e.g., /bin/sh) spawns
grandchildren (e.g., /bin/hello). Grandchildren inherit stdin/stdout
overrides via namespace override propagation, so they share the same
channel endpoints. In practice this works for foreground-only shells
because only one process at a time does stdio. TermServer<8> accommodates
the init-server creating additional connections for grandchild processes
if the propagation model changes in the future.

### fbcon Refactoring

fbcon's `main()` becomes:

```rust
fn main() {
    // ... window setup, framebuffer init (unchanged) ...

    let mut term = TermServer::<8>::new();
    let mut fb_output = FbOutput { console: &mut console };

    // Spawn shell, add as client
    let (stdin_our, stdin_shell) = raw::sys_chan_create();
    let (stdout_our, stdout_shell) = raw::sys_chan_create();
    spawn_process_with_overrides("/bin/shell", ...);
    raw::sys_chan_close(stdin_shell);
    raw::sys_chan_close(stdout_shell);
    term.add_client(stdin_our, stdout_our);

    loop {
        // Keyboard events → term.feed_input() / term.feed_raw()
        while let Some(event) = events.try_next_message() {
            let ascii = translate_key(event);
            term.feed_input(ascii, &mut fb_output);
        }

        term.poll_stdin();
        term.poll_stdout(&mut fb_output);

        if console.dirty { swap_buffers(); }

        // Block
        events.poll_add();
        term.poll_add_all();
        raw::sys_block();
    }
}
```

FbConsole, keyboard handling, ANSI rendering, buffer swapping — all stay
in fbcon. Only the FileOps server plumbing moves to termserv.

### TTY Considerations

Programs like the shell call TCRAW/TCCOOKED/TCSETFG ioctls on stdin.
The TermServer handles these regardless of backend:

- **TCRAW/TCCOOKED** toggle the LineDiscipline's raw mode — works the same
  whether the backend is fbcon, serial, or nc
- **TCSETFG** stores the foreground PID for Ctrl+C delivery
- Unknown ioctls → `FileResponse::Error { FsError::Io }`

For nc exec mode: TCRAW enables character-at-a-time delivery (good for
interactive shells). TCSETFG enables Ctrl+C forwarding (nc translates
0x03 from the network into a kill). This all works automatically through
the TermServer.

### Interface Changes

**User-visible:**
- `nc -e <cmd> <host> <port>` — connect and exec
- `nc -l -e <cmd> <port>` — listen, accept, and exec

**New crate:**
- `lib/termserv/` — terminal server library

**Modified crates:**
- `user/nc/` — add `-e` flag and exec mode
- `user/fbcon/` — refactor to use termserv (behavioral no-op)

**No kernel changes. No protocol changes. No std sysroot changes.**

### Internal Changes

**`lib/termserv/src/lib.rs` (new, ~250 lines):**
- `LineDiscipline` struct (from fbcon)
- `TermClient` struct (typed Channel pairs, pending-read flag)
- `TermOutput` trait
- `TermServer<N>` struct and impl
- Response helpers (send_data, send_sentinel, send_write_ok, send_ioctl_ok)

**`user/nc/src/main.rs` (~80 lines added):**
- Parse `-e <cmd>` flag
- `exec_mode()` function — spawn child, run TermServer loop
- `NetOutput` struct implementing `TermOutput`

**`user/fbcon/src/main.rs` (~200 lines removed, ~30 added):**
- Remove: LineDiscipline, FbconClient, response helpers, stdin/stdout
  poll loops, stdin stack, ioctl dispatch, key input dispatch
- Add: `use termserv::*`, `FbOutput` impl, delegate to TermServer

**`Cargo.toml` (workspace):**
- Add `lib/termserv` member

**`Makefile`:**
- Add termserv to lib build dependencies

### Resource Limits

| Resource | nc exec cost | Current limit | OK? |
|----------|-------------|---------------|-----|
| Processes | +1 (child) | 64 (`MAX_PROCS`) | Yes |
| Channels | +2 (stdin/stdout pairs) | 64 (`MAX_CHANNELS`) | Yes |
| Handles | nc: +4 (2 pairs), child: +2 (overrides) | 32 (`MAX_HANDLES`) | Yes |

No limit changes needed. No extra relay process.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| New `lib/termserv` crate | `lib/termserv/` (new), workspace `Cargo.toml` | Low — new code, no existing deps |
| nc `-e` flag | `user/nc/src/main.rs` | Low — additive, existing relay modes untouched |
| fbcon refactor | `user/fbcon/src/main.rs` | **Medium** — replacing working code with library calls; must verify identical behavior |
| nc depends on termserv | `user/nc/Cargo.toml` | Low — additive dependency |
| fbcon depends on termserv | `user/fbcon/Cargo.toml` | Low — replaces inline code |

**Key risk:** fbcon refactoring. Mitigated by: test that GUI console still
boots and accepts keyboard input after the change. The extraction is
mechanical (move code, add trait calls for echo/write), not a redesign.

## Acceptance Criteria

- [ ] `nc -e /bin/sh 10.0.2.2 4444` — reverse shell works (connect mode)
- [ ] `nc -l -e /bin/sh 4444` — reverse shell works (listen mode)
- [ ] Child process exits → nc closes socket and exits
- [ ] Socket closes → child process is killed, nc exits
- [ ] Shell running under nc handles TCRAW/TCCOOKED (line editing works)
- [ ] Ctrl+C over network (0x03 byte) kills foreground child process
- [ ] fbcon still boots, renders text, accepts keyboard after refactoring
- [ ] fbcon shell line editing (raw mode) still works
- [ ] fbcon Ctrl+C still kills foreground process
- [ ] `make clippy` passes with no new warnings
- [ ] `make build` succeeds, system boots to shell
- [ ] No regression in existing nc relay modes (TCP/UDP connect/listen)

## Deferred

| Item | Rationale |
|------|-----------|
| Shell `\|` pipe operator | Needs a relay process; may revisit if raw-stream pipes are added later |
| Kernel serial console refactoring | Different constraints (kernel task, no alloc); not worth forcing into same abstraction |
| `ISATTY` ioctl | Nice to have but programs work without it via TermServer ioctl dispatch |
| nc `-e` with UDP | TCP only for v1; UDP exec is unusual |
| Multiple simultaneous exec sessions | nc accepts one connection and execs one child; could add connection-per-child later |
| Stderr separation | Stderr currently aliases stdout; needs separate stderr service first |

## Implementation Notes

(Updated during Phase 3)

## Verification

(Updated during Phase 4)
