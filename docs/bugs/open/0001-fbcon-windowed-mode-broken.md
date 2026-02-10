# 0001: fbcon windowed mode broken — wrong size and no shell

**Reported:** 2026-02-10
**Status:** Open
**Severity:** HIGH
**Subsystem:** window-manager, fbcon, init

## Symptoms

Running `run /bin/fbcon 800 600` in the GUI console creates a new window, but:

1. The window is fullscreen (not 800x600 as requested)
2. The shell doesn't start in the new window — it only shows the banner, nothing else

## Reproduction Steps

1. Boot with `make run-gui`
2. In the fbcon shell, type: `run /bin/fbcon 800 600`
3. Observe: a new fullscreen window appears with only the banner text
4. No shell prompt appears; keyboard input is not processed

## Root Cause

Two distinct bugs, plus an architectural issue:

### Bug A: Window always fullscreen

`fbcon/src/main.rs:466` hardcodes `CreateWindowRequest { width: 0, height: 0 }`.
fbcon never parses command-line arguments, so `800 600` args are ignored.

### Bug B: No shell spawned for user-launched fbcon

Init had special-case orchestration for fbcon: `provides_console`, `start_gpu_shell()`,
`gpu_shell_launched` flag, console_type routing. User-spawned fbcon didn't get any of
this, so no shell was launched. Fundamentally, fbcon should be self-contained — it
should spawn its own shell, not rely on init to orchestrate one.

### Bug C: Console type routing was unnecessary

Init routed stdin/stdout based on `ConsoleType` enum (Serial, GpuConsole, etc.).
This created tight coupling between init and fbcon. The correct model: everything
defaults to serial; programs that need different routing use namespace overrides.

## Fix

1. **fbcon parses args**: `std::env::args()` for width/height, passed to `CreateWindowRequest`
2. **fbcon self-spawns shell**: Creates stdin/stdout channel pairs via `sys_chan_create()`,
   spawns `/bin/shell` with namespace overrides redirecting its stdio
3. **Removed init orchestration**: Deleted `start_gpu_shell()`, `gpu_shell_launched` flag,
   `provides_console` for fbcon. Init always routes stdio to serial console.
4. **Fixed dead client detection**: Old code did `sys_chan_recv` to check for dead channels,
   which silently consumed live messages. Replaced with inline detection (ret == 2) in
   the normal polling loops.
5. **Handle CloseRequested**: fbcon now handles the window close event.

## Verification

- `make build` succeeds
- Serial shell boots and works (expect script: echo hello)
- Manual GUI test by user confirmed windowed mode and shell startup

## Lessons Learned

- Console type routing was unnecessary complexity. Namespace overrides are the right
  mechanism for redirecting stdio.
- Dead client detection via extra `sys_chan_recv` calls is a latent bug pattern —
  it silently consumes messages. Always detect channel closure inline in the normal
  polling path.
