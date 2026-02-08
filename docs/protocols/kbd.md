# Keyboard Protocol

The keyboard server is a kernel task that wraps VirtIO keyboard input. A single
client (the window server) connects via service discovery and receives
push-style key events. There are no request messages — the server pushes events
as keys are pressed and released.

## Service Discovery

The keyboard server registers as the `"kbd"` named service. Clients connect via
the boot channel:

```
BootRequest::ConnectService { name: "kbd" }
```

## Wire Format

All messages use `rvos-wire` serialization. Types are defined in
`rvos-proto::kbd`.

### Events (server → client, push only)

```rust
define_message! {
    pub enum KbdEvent {
        KeyDown(0) { code: u16 },
        KeyUp(1) { code: u16 },
    }
}
```

**KeyDown** is sent when a key is pressed. **KeyUp** is sent when a key is
released. `code` is a Linux evdev keycode (e.g., 28 = Enter, 57 = Space).

## Event Delivery

- Events are **best-effort**: if the client's receive queue is full, events are
  silently dropped rather than blocking the keyboard IRQ pipeline.
- Events are pushed as they occur — the client does not need to poll or request
  them.
- The client should drain events regularly (e.g., between frames) to avoid
  queue overflow.

## Common Keycodes

| Code | Key         | Code | Key         |
|------|-------------|------|-------------|
| 1    | Escape      | 28   | Enter       |
| 2-11 | 1-9, 0      | 57   | Space       |
| 14   | Backspace   | 103  | Up          |
| 15   | Tab         | 105  | Left        |
| 16-25| Q-P         | 106  | Right       |
| 30-38| A-L         | 108  | Down        |
| 44-50| Z-M         | 111  | Delete      |

## Connection Lifecycle

1. Client connects via boot channel (`"kbd"` service)
2. Server begins pushing key events as they occur
3. Client reads events via `sys_chan_recv` (non-blocking) or `sys_chan_recv_blocking`
4. Connection ends when either side closes the channel

## Example

```
# User presses and releases the 'A' key (code 30)

Server → Client: KbdEvent::KeyDown { code: 30 }
Server → Client: KbdEvent::KeyUp { code: 30 }
```
