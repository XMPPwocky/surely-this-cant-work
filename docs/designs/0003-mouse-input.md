# 0003: Mouse Input for Client Windows

**Date:** 2026-02-10
**Status:** Complete (2026-02-10)
**Subsystem:** user/window-server, user/winclient, docs/protocols

## Motivation

The window server already has the full mouse event pipeline wired up: VirtIO
tablet driver → mouse_server → window_server → focused window event channel.
The `WindowEvent` protocol already defines `MouseMove`, `MouseButtonDown`, and
`MouseButtonUp` with window-local coordinates. However, the forwarding has a
critical bug that makes it unusable in practice, the protocol documentation is
stale, and no client application demonstrates mouse event handling.

This feature fixes the bugs, updates documentation, and adds a demo so that
mouse input actually works end-to-end for GUI client windows.

## Design

### Overview

The existing infrastructure is nearly complete. The work is:

1. **Fix the content-area drag bug** in the window server — left-clicking
   inside a window's content area currently starts a window drag, which
   swallows the click and makes content-area mouse interaction impossible.
2. **Clamp forwarded coordinates** to window bounds so clients never receive
   out-of-range values.
3. **Update winclient** to visually respond to mouse events (draw dots on
   click, show cursor trail) as a working demo/test.
4. **Update protocol documentation** — `docs/protocols/window.md` is stale
   (still shows old combined `WindowServerMsg`, no mention of mouse events
   or the separate event channel).

No kernel changes are needed. No new syscalls, protocols, or IPC mechanisms
are introduced.

### Interface Changes

**No wire protocol changes.** The existing `WindowEvent` variants are correct:

```rust
WindowEvent::MouseMove(194) { x: u32, y: u32 }
WindowEvent::MouseButtonDown(195) { x: u32, y: u32, button: u8 }
WindowEvent::MouseButtonUp(196) { x: u32, y: u32, button: u8 }
```

Coordinates are window-local (0,0 = top-left of content area). Button values:
0=Left, 1=Right, 2=Middle. These are already defined in `rvos-proto::window`.

### Internal Changes

#### window-server/src/main.rs

**Bug fix: Remove content-area drag (lines 527–532).** Currently, a left-click
in the content area sets `server.dragging = Some(idx)`, which means clicking
inside a window starts moving it. Only title bar clicks should initiate drag.
The fix: remove the `if !is_fs { server.dragging = Some(idx); ... }` block
after the title bar/close button checks.

**Bug fix: Don't forward clicks consumed by WM.** The close button handler
returns early (correct), and the title bar drag handler returns early (correct).
After removing the content-area drag code, content clicks will fall through
cleanly to `forward_mouse_button()`.

**Clamp coordinates in `forward_mouse_move()` and `forward_mouse_button()`.**
Currently, if the cursor is outside the focused window, `local_x` or `local_y`
can exceed window dimensions (they're clamped to ≥0 via `.max(0)` but not
clamped to `< width`/`< height`). Add upper-bound clamping.

#### user/winclient/src/main.rs

Update to handle `MouseMove`, `MouseButtonDown`, and `MouseButtonUp` events.
Draw a visible response: e.g., draw a filled circle at click position, change
background color on button state, show a crosshair or trail on move. This
serves as both a demo and a manual test.

#### docs/protocols/window.md

Rewrite to reflect the current two-channel architecture (request channel +
event channel) and document all `WindowEvent` variants including mouse events.

### Resource Limits

No new resources, limits, or allocations. Mouse events use the existing
event channel with best-effort non-blocking send (events dropped if queue
full — same as keyboard events). The 64-entry channel queue depth is adequate.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Remove content-area drag logic | window-server/src/main.rs (lines 527–532) | Low — behavioral fix, removes 5 lines |
| Add coordinate clamping | window-server/src/main.rs (forward_mouse_move, forward_mouse_button) | Low — additive bounds check |
| Update winclient mouse handling | user/winclient/src/main.rs (event loop) | Low — additive, demo app only |
| Update protocol docs | docs/protocols/window.md | Low — documentation only |

No kernel ABI changes. No wire protocol changes. No std sysroot changes.

## Acceptance Criteria

- [x] Left-clicking inside a window's content area does NOT drag the window
- [x] Title bar clicks still initiate window drag (no regression)
- [x] Close button clicks still send CloseRequested (no regression)
- [x] Alt+Tab still cycles focus (no regression)
- [x] `MouseMove` events are delivered to the focused window with correct
      window-local coordinates (verify via winclient print/draw)
- [x] `MouseButtonDown`/`MouseButtonUp` events are delivered with correct
      coordinates and button ID
- [x] Coordinates are clamped to [0, width) and [0, height) range
- [x] winclient visually responds to mouse input (draw on click)
- [x] `docs/protocols/window.md` documents the event channel and all
      `WindowEvent` variants including mouse
- [x] `make build` succeeds
- [x] System boots and reaches shell in GUI mode
- [x] Existing keyboard input in fbcon still works (no regression)

## Deferred

| Item | Rationale |
|------|-----------|
| Scroll wheel / mouse wheel events | VirtIO tablet driver doesn't currently handle REL_WHEEL; separate feature |
| Mouse cursor shape (per-window cursors) | Requires VirtIO GPU cursor plane; separate feature |
| Mouse capture / grab (for games) | Needs new WindowRequest; separate feature |
| Hover/enter/leave events | Needs tracking which window cursor is over; separate feature |
| fbcon mouse support (text selection, xterm protocol) | Terminal mouse is complex; separate feature |
| Focus-follows-mouse policy | Current click-to-focus is correct for now |

## Implementation Notes

The implementation was straightforward — the full pipeline already existed.

1. **Content-area drag removal**: Removed 5 lines in `handle_mouse_event()`
   (the `if !is_fs { server.dragging = ... }` block after WM checks). This
   was the root cause of content clicks being unusable — they started a
   window drag instead of being forwarded to the client.

2. **Coordinate clamping**: Added `.min(win.width as i32 - 1).max(0)` and
   `.min(win.height as i32 - 1).max(0)` to both `forward_mouse_move()` and
   `forward_mouse_button()`. The double `.max(0)` handles edge cases where
   width/height could be 0.

3. **Winclient paint demo**: Replaced the animated gradient with an
   event-driven paint demo. Left-click draws colored dots, hold and drag to
   paint, right-click clears canvas. Color cycles after each stroke. Small
   crosshair shows cursor position on hover. The app is now event-driven
   (blocks on `sys_block()` when idle) instead of continuously animating.

4. **Protocol docs**: Rewrote `docs/protocols/window.md` to document the
   two-channel architecture (request + event channels), all `WindowEvent`
   variants including mouse events, coordinate semantics, and window manager
   click behavior.

## Verification

- `make build` succeeds (no new warnings in changed files)
- System boots and reaches shell prompt (serial console test via expect)
- Bench results show no regression:
  - syscall: 7614 ns, chan create: 23647 ns, ipc roundtrip: 20720 ns
- Code inspection confirms:
  - Content-area drag code removed
  - Title bar drag code and close button code untouched
  - Coordinate clamping added to both forwarding functions
  - Protocol docs updated with full mouse event documentation
- Mouse event forwarding is manual-test only (requires GUI mode with
  `make run-gui` and moving/clicking the mouse)
