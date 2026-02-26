# 0027: Add Window client wrapper to lib/rvos

**Reported:** 2026-02-26
**Status:** Open
**Severity:** MEDIUM
**Subsystem:** lib/rvos, rvos-gfx, window-server

## Problem

Every GUI app (winclient, fbcon, triangle, gui-bench) repeats 35–40 lines
of identical boilerplate to create a window: connect to the window service,
send CreateWindowRequest, receive response, extract request/event channels,
call GetInfo, call GetFramebuffer, mmap the SHM region, and set up
double-buffer state. `gui-bench` even wrote its own `connect_window()`
helper because the ceremony was too painful.

The socket abstraction (`TcpStream`/`UdpSocket`) hides all IPC behind a
familiar API. GUI apps deserve the same treatment.

See: Architecture Review 8, sections 2a, 2d, 4 ("HIGH: Window Client
Wrapper").

## Scope

Four apps affected: `user/winclient`, `user/fbcon`, `user/triangle`,
`user/gui-bench`. Each has ~40 lines of setup that would reduce to ~3.

## Proposed API

```rust
// lib/rvos/src/window.rs (new file)

pub struct Window {
    client: WindowClient,
    event_channel: RawChannel,
    fb_base: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
    pixels_per_buffer: usize,
    current_back: u8,
    swap_seq: u32,
}

impl Window {
    /// Connect to the window service, create a window, map the framebuffer.
    pub fn create(width: u32, height: u32) -> Result<Self, WindowError>;

    /// Return a `Framebuffer` (from rvos-gfx) pointing at the back buffer.
    pub fn back_buffer(&mut self) -> Framebuffer<'_>;

    /// Swap buffers and present the back buffer to the display.
    pub fn present(&mut self) -> Result<(), WindowError>;

    /// Non-blocking poll for the next window event (key, mouse, resize).
    pub fn poll_event(&mut self) -> Option<WindowEvent>;

    /// Raw event channel handle for use with poll_add / Reactor.
    pub fn event_handle(&self) -> usize;
}

impl Drop for Window {
    fn drop(&mut self) { /* unmap SHM, close channels */ }
}
```

## Acceptance Criteria

1. All four GUI apps converted to use `Window::create()`.
2. Each app's window setup reduces to ≤5 lines.
3. Double-buffer swap logic is internal to `Window`; apps call `present()`.
4. `Framebuffer` from `rvos_gfx` is used for safe pixel access.
5. `make build` + `make clippy` clean.
6. `make test-quick` passes.
7. Manual MCP test: boot with GPU, run a GUI app, confirm rendering works.
