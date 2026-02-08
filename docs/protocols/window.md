# Window Protocol

The window server is a user-space compositor that manages windows for graphical
clients. Clients connect via the `"window"` service and go through a two-phase
handshake to create a window, then communicate over a dedicated per-window
channel.

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

The control channel is used once to create a window, then closed.

### CreateWindowRequest (client → server)

```rust
define_message! {
    pub struct CreateWindowRequest {
        width: u32,
        height: u32,
    }
}
```

Width and height are currently ignored (all windows are fullscreen). Reserved
for future multi-window layouts.

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

The response `cap` field carries a **window channel** endpoint for all
subsequent communication. After receiving this response, the client closes the
control channel.

## Phase 2: Window Channel

The window channel is bidirectional and carries both request-response pairs
and server-push events.

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

**GetInfo** queries the window dimensions, stride, and pixel format. Returns
an `InfoReply`.

**GetFramebuffer** requests the double-buffered framebuffer SHM handle. Returns
an `FbReply` with the SHM capability in the message cap field.

**SwapBuffers** presents the current back buffer (toggles front/back). Returns
a `SwapReply`.

**CloseWindow** closes the window. No reply is sent.

The `seq` field is a client-chosen sequence number echoed in the reply, useful
for correlating requests with responses.

### Server Messages (server → client)

Replies and events share the same channel, combined into one enum:

```rust
define_message! {
    pub enum WindowServerMsg {
        InfoReply(128) { seq: u32, window_id: u32, width: u32, height: u32, stride: u32, format: u8 },
        FbReply(129) { seq: u32 },
        SwapReply(130) { seq: u32, ok: u8 },
        KeyDown(192) { code: u16 },
        KeyUp(193) { code: u16 },
    }
}
```

**InfoReply** (tag 128): Window dimensions and format. `format` is `0` for BGRA32.

**FbReply** (tag 129): Message `cap` carries an SHM handle for the double-buffered
framebuffer. Size is `stride * height * 4 * 2` bytes (two buffers).

**SwapReply** (tag 130): Acknowledges a buffer swap. `ok` is `0` for success.

**KeyDown** (tag 192) / **KeyUp** (tag 193): Keyboard events forwarded from the
keyboard server. `code` is a Linux evdev keycode. These can arrive at any time,
including between a request and its reply.

### Tag Ranges

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

## Handling Interleaved Events

Because key events can arrive between a request and its reply, the client must
handle them when waiting for a reply:

```rust
// Send SwapBuffers request
send(win_chan, &WindowRequest::SwapBuffers { seq: frame });

// Wait for SwapReply, handling any key events that arrive first
loop {
    let msg = recv_blocking(win_chan);
    match from_bytes::<WindowServerMsg>(&msg) {
        Ok(WindowServerMsg::SwapReply { .. }) => break,
        Ok(WindowServerMsg::KeyDown { code }) => handle_key(code),
        Ok(WindowServerMsg::KeyUp { code }) => handle_key(code),
        _ => {}
    }
}
```

## Connection Lifecycle

1. Client connects to `"window"` service → gets control channel
2. Client sends `CreateWindowRequest` on control channel
3. Server responds with `CreateWindowResponse` + window channel cap
4. Client closes control channel
5. Client sends `GetInfo` → receives `InfoReply`
6. Client sends `GetFramebuffer` → receives `FbReply` + SHM cap
7. Client maps SHM (`sys_mmap`)
8. Render loop: draw → `SwapBuffers` → wait for `SwapReply` → repeat
9. Client sends `CloseWindow` when done

## Example

```
# Phase 1: Create window
Client → Server (control): CreateWindowRequest { width: 0, height: 0 }
Server → Client (control): CreateWindowResponse { window_id: 1, width: 1024, height: 768 }
                           cap = <window channel>

# Phase 2: Setup
Client → Server (window): WindowRequest::GetInfo { seq: 1 }
Server → Client (window): WindowServerMsg::InfoReply { seq: 1, window_id: 1,
                             width: 1024, height: 768, stride: 1024, format: 0 }

Client → Server (window): WindowRequest::GetFramebuffer { seq: 2 }
Server → Client (window): WindowServerMsg::FbReply { seq: 2 }
                           cap = <SHM handle>

# Phase 2: Render loop
Client → Server (window): WindowRequest::SwapBuffers { seq: 0 }
Server → Client (window): WindowServerMsg::SwapReply { seq: 0, ok: 0 }

# Asynchronous key event
Server → Client (window): WindowServerMsg::KeyDown { code: 30 }
```
