# 0002: Windowed fbcon

**Date:** 2026-02-10
**Status:** Implemented
**Subsystem:** user/fbcon

## Motivation

Currently fbcon is always spawned at boot time as a fullscreen window. There is
no way to open additional terminal windows from the GUI shell. This makes it
impossible to have multiple terminals side-by-side — a basic expectation for any
windowed OS.

This feature lets users type `run /bin/fbcon 640 400` from the GUI shell to
open a new terminal window at the specified pixel dimensions, with its own shell
instance.

## Design

### Overview

fbcon gains argument parsing so it can be launched in **windowed mode** with
user-specified pixel dimensions. In windowed mode, fbcon creates its own
stdin/stdout channel pairs, spawns `/bin/shell` as a child process with those
channels as namespace overrides, and manages the shell as a direct console
client. No kernel or init changes are needed — the ns_overrides mechanism
already supports this pattern (the shell uses it for stdout redirect).

When launched without arguments (or with `0 0`), fbcon retains its current
fullscreen boot-time behavior.

### Interface Changes

**New command-line usage:**

```
fbcon                  # fullscreen (boot-time, existing behavior)
fbcon <width> <height> # windowed mode at WxH pixels, spawns own shell
```

Examples from the GUI shell:
```
run /bin/fbcon 640 400       # 640x400 terminal window
run /bin/fbcon 800 600       # 800x600 terminal window
run /bin/fbcon 640 400 &     # background (shell returns immediately)
```

No new syscalls, IPC protocols, or wire formats.

### Internal Changes

**`user/fbcon/src/main.rs`** — sole file modified:

1. **Argument parsing** (new, ~15 lines): Use `std::env::args()` to read
   width/height. If two numeric args are present and non-zero, enter windowed
   mode. Otherwise, fullscreen.

2. **CreateWindowRequest dimensions** (1-line change): Pass parsed (width,
   height) instead of hardcoded (0, 0). Fullscreen mode still passes (0, 0).

3. **Standalone shell spawning** (new, ~40 lines): In windowed mode, after
   window setup completes:
   - Create two channel pairs via `raw::sys_chan_create()`:
     `(stdin_ours, stdin_theirs)` and `(stdout_ours, stdout_theirs)`
   - Build ns_overrides blob: `[count=2, 5, "stdin", 0, 6, "stdout", 1]`
   - Call `rvos::spawn_process_with_overrides("/bin/shell", &[], ns_overrides, &[stdin_theirs, stdout_theirs])`
   - Close the sent endpoints (`stdin_theirs`, `stdout_theirs`)
   - Register `stdin_ours` and `stdout_ours` directly in the `clients[]`
     array as a new FbconClient (same struct used for boot-time clients)
   - Push the client onto the stdin_stack so it receives keyboard input

4. **Control channel polling** (small change): In windowed mode, skip polling
   `CONSOLE_CONTROL_HANDLE` (handle 1) since it doesn't exist. Guard with a
   boolean flag.

5. **Close handling** (new, ~5 lines): When all clients disconnect (shell
   exits), windowed fbcon sends `CloseWindow` and exits. Boot-time fbcon
   stays alive as today.

### Resource Limits

No new fixed-size tables or limits. Each windowed fbcon occupies:
- 1 window slot in window-server (max 4 total)
- 1 process slot + the child shell = 2 process slots
- 2 channel pairs for stdin/stdout + 2 for window request/event = 4 channels
- 1 SHM region for the window framebuffer

These all fit within existing limits. At MAX_WINDOWS=4, users can have 1
fullscreen fbcon + 3 windowed fbcons (or 4 windowed). Running out of window
slots is already handled: window-server closes the client handle and fbcon's
CreateWindow recv will fail, causing a panic with a clear message.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Arg parsing in fbcon main() | user/fbcon/src/main.rs | Low (additive, no-args = existing path) |
| CreateWindowRequest dimensions | user/fbcon/src/main.rs:326 | Low (1-line change, fullscreen path unchanged) |
| Standalone shell spawn | user/fbcon/src/main.rs (new code) | Low (uses existing spawn_process_with_overrides) |
| Skip control channel in windowed mode | user/fbcon/src/main.rs (event loop) | Low (boolean guard) |

No kernel ABI changes. No protocol changes. No wire format changes. No changes
to window-server, init, shell, or any library crate.

## Acceptance Criteria

- [ ] `make build` succeeds
- [ ] System boots normally; fullscreen fbcon + GUI shell work as before
- [ ] From GUI shell: `run /bin/fbcon 640 400 &` opens a windowed terminal
- [ ] The windowed terminal shows the rvOS banner and a working shell prompt
- [ ] Typing commands in the windowed terminal works (echo, ls, cat, etc.)
- [ ] The windowed terminal has a title bar, close button, and can be dragged
- [ ] Closing the windowed terminal (close button or `exit`) cleans up properly
- [ ] Multiple windowed fbcons can coexist (up to window-server's MAX_WINDOWS)
- [ ] Alt+Tab switches focus between fullscreen and windowed terminals
- [ ] Existing `make bench` shows no regression

## Deferred

| Item | Rationale |
|------|-----------|
| Window resize support | Requires protocol extension (WindowRequest::Resize) and fbcon re-layout; separate feature |
| Custom title text | Nice-to-have; currently shows "Win N" from window-server |
| Spawn arbitrary command (not just shell) | Could add `fbcon 640 400 -- /bin/program args` later |
| Character-based dimensions (e.g., 80x25) | Pixel dimensions are simpler and sufficient for now |

## Implementation Notes

The implementation went further than the original design in two ways:

1. **fbcon always self-spawns its shell** — not just in windowed mode.
   This removed `start_gpu_shell()`, `gpu_shell_launched`, and
   `provides_console: Some(ConsoleType::GpuConsole)` from init. fbcon is now
   fully self-contained.

2. **Console type routing removed from init.** `handle_stdio_request` now
   always routes to the serial console. Programs needing different routing
   use namespace overrides. This removed the tight coupling between init
   and fbcon.

3. **Dead client detection rewritten.** The old `sys_chan_recv`-based dead
   client check silently consumed live messages. Replaced with inline
   detection (ret == 2) in the normal polling loops.

4. **CloseRequested handling added.** fbcon now responds to the window
   close button by sending CloseWindow and exiting.

Files changed:
- `user/fbcon/src/main.rs` — arg parsing, self-spawn, dead client fix, close handling
- `kernel/src/services/init.rs` — removed `start_gpu_shell()`, simplified stdio routing

## Verification

- `make build` succeeds with no new warnings
- Serial shell boots and works
- User manually verified: windowed fbcon opens at correct size with working shell
