# Window Protocol

The window server is a user-space compositor that manages windows for graphical
clients. Clients connect via the `"window"` service and go through a two-phase
handshake to create a window, then communicate over dedicated per-window
channels.

## Service Discovery

The window server registers as the `"window"` named service. Clients connect
via the boot channel:

```
BootRequest::ConnectService { name: "window" }
```

This returns a **control channel** for the initial CreateWindow handshake.

## Wire Format

All messages use `rvos-wire` serialization. Types are defined in
`rvos-proto::window`.

## Phase 1: Control Channel (CreateWindow Handshake)

The control channel is used once to create a window, then can be dropped.

### CreateWindowRequest (client → server)

```rust
define_message! {
    pub struct CreateWindowRequest {
        width: u32,
        height: u32,
    }
}
```

Width/height of 0 requests the default window size (server decides). Non-zero
values request a specific size (server may adjust).

### CreateWindowResponse (server → client)

```rust
define_message! {
    pub struct CreateWindowResponse {
        window_id: u32,
        width: u32,
        height: u32,
    }
}
```

The response carries **two capabilities**:
- `caps[0]` = **request channel** — for client→server RPC (requests + replies)
- `caps[1]` = **event channel** — for server→client push events (keyboard, mouse, close)

After receiving this response, the client uses the two per-window channels for
all further communication.

## Phase 2: Request Channel (RPC)

The request channel carries request/reply pairs. Clients use the generated
`WindowClient` for type-safe RPC.

### Requests (client → server)

```rust
define_message! {
    pub enum WindowRequest {
        GetInfo(0) { seq: u32 },
        GetFramebuffer(1) { seq: u32 },
        SwapBuffers(2) { seq: u32 },
        CloseWindow(3) {},
    }
}
```

**GetInfo** — query window dimensions, stride, and pixel format. Returns `InfoReply`.

**GetFramebuffer** — request the double-buffered framebuffer SHM handle.
Returns `FbReply` with the SHM capability attached to the message.

**SwapBuffers** — present the current back buffer (toggles front/back).
Returns `SwapReply`.

**CloseWindow** — close the window. Returns `CloseAck`.

The `seq` field is a client-chosen sequence number echoed in the reply.

### Replies (server → client)

```rust
define_message! {
    pub enum WindowReply {
        InfoReply(128) { seq: u32, window_id: u32, width: u32, height: u32, stride: u32, format: u8 },
        FbReply(129) { seq: u32 },
        SwapReply(130) { seq: u32, ok: u8 },
        CloseAck(131) {},
    }
}
```

**InfoReply** (tag 128) — window dimensions and format. `format` 0 = BGRA32.

**FbReply** (tag 129) — message cap carries an SHM handle for the
double-buffered framebuffer. Size is `stride * height * 4 * 2` bytes.

**SwapReply** (tag 130) — acknowledges a buffer swap. `ok` 0 = success.

**CloseAck** (tag 131) — acknowledges window close.

## Phase 2: Event Channel (Push Events)

The event channel is a **receive-only stream** for the client. The server
pushes keyboard events, mouse events, and close notifications. Events can
arrive at any time.

```rust
define_message! {
    pub enum WindowEvent {
        KeyDown(192) { code: u16 },
        KeyUp(193) { code: u16 },
        MouseMove(194) { x: u32, y: u32 },
        MouseButtonDown(195) { x: u32, y: u32, button: u8 },
        MouseButtonUp(196) { x: u32, y: u32, button: u8 },
        CloseRequested(197) {},
    }
}
```

### Keyboard Events

**KeyDown** (tag 192) / **KeyUp** (tag 193) — keyboard events forwarded from
the keyboard server. `code` is a Linux evdev keycode. Only delivered to the
focused (foreground) window.

### Mouse Events

**MouseMove** (tag 194) — cursor moved. `x` and `y` are **window-local
coordinates** (0,0 = top-left of the window's content area, excluding title
bar). Coordinates are clamped to `[0, width-1]` and `[0, height-1]`.

**MouseButtonDown** (tag 195) / **MouseButtonUp** (tag 196) — mouse button
pressed/released. `x` and `y` are window-local coordinates (same as
MouseMove). `button` values: 0 = Left, 1 = Right, 2 = Middle.

Mouse events are only delivered to the **focused (foreground) window**. The
window server handles all coordinate transformation from tablet space to
window-local space.

Clicks in the title bar are consumed by the window server (for dragging).
Clicks on the close button generate a `CloseRequested` event instead. Only
clicks in the content area generate `MouseButtonDown`/`MouseButtonUp` events.

### Close Events

**CloseRequested** (tag 197) — the user clicked the window's close button.
The client should save state and exit gracefully.

### Event Delivery

Events are sent **non-blocking, best-effort**. If the event channel queue is
full, events are silently dropped. This matches the behavior of high-frequency
input devices — occasional dropped events are acceptable.

## Tag Ranges

| Range   | Purpose           |
|---------|-------------------|
| 0-127   | Client requests   |
| 128-191 | Server replies    |
| 192-255 | Server events     |

## Double Buffering

The framebuffer SHM contains two buffers laid out contiguously:

```
Offset 0:                     Buffer 0 (stride * height * 4 bytes)
Offset stride*height*4:       Buffer 1 (stride * height * 4 bytes)
```

The client draws into the back buffer, then calls `SwapBuffers` to present it.
After the swap, the roles toggle: what was the back buffer becomes the front
buffer, and vice versa.

## Window Manager Behavior

The window server acts as a simple compositor with these mouse behaviors:

- **Click to focus**: Left-clicking on a window makes it the foreground window.
- **Title bar drag**: Left-clicking and dragging in a window's title bar moves
  the window.
- **Close button**: Clicking the close button (top-right of title bar) sends
  `CloseRequested` to the client.
- **Alt+Tab**: Cycles focus between active windows.
- **Content area clicks**: Forwarded to the client as `MouseButtonDown`/`Up`.

## Connection Lifecycle

1. Client connects to `"window"` service → gets control channel
2. Client sends `CreateWindowRequest` on control channel
3. Server responds with `CreateWindowResponse` + 2 channel caps
4. Client sends `GetInfo` on request channel → receives `InfoReply`
5. Client sends `GetFramebuffer` → receives `FbReply` + SHM cap
6. Client maps SHM (`sys_mmap`)
7. Render loop: draw → `SwapBuffers` → wait for `SwapReply` → repeat
8. Client drains event channel for keyboard/mouse/close events
9. Client sends `CloseWindow` when done (or exits on `CloseRequested`)

## Example

```
# Phase 1: Create window
Client → Server (control): CreateWindowRequest { width: 400, height: 300 }
Server → Client (control): CreateWindowResponse { window_id: 1, width: 400, height: 300 }
                           caps[0] = <request channel>
                           caps[1] = <event channel>

# Phase 2: Setup
Client → Server (request): WindowRequest::GetInfo { seq: 1 }
Server → Client (request): WindowReply::InfoReply { seq: 1, window_id: 1,
                             width: 400, height: 300, stride: 400, format: 0 }

Client → Server (request): WindowRequest::GetFramebuffer { seq: 2 }
Server → Client (request): WindowReply::FbReply { seq: 2 }
                           cap = <SHM handle>

# Phase 2: Render loop
Client → Server (request): WindowRequest::SwapBuffers { seq: 0 }
Server → Client (request): WindowReply::SwapReply { seq: 0, ok: 0 }

# Asynchronous events (on event channel)
Server → Client (event): WindowEvent::KeyDown { code: 30 }
Server → Client (event): WindowEvent::MouseMove { x: 150, y: 100 }
Server → Client (event): WindowEvent::MouseButtonDown { x: 150, y: 100, button: 0 }
Server → Client (event): WindowEvent::MouseButtonUp { x: 150, y: 100, button: 0 }
Server → Client (event): WindowEvent::CloseRequested {}
```
