# 0001: Shell Line Editor with History and Search

**Date:** 2026-02-10
**Status:** Complete (2026-02-10)
**Subsystem:** user/shell, user/fbcon

## Motivation

The rvOS shell currently has minimal line editing: character input, backspace,
tab completion, and Ctrl+C. There is no cursor movement within a line (arrow
keys are silently dropped), no command history, and no history search. This
makes the shell tedious to use for any real work — retyping long commands,
fixing typos mid-line, etc.

The user wants: goto start/end of line, cursor movement, command history with
up/down arrows, and reverse history search (Ctrl+R). Full readline is
explicitly not needed.

## Design

### Overview

Add a `LineEditor` struct to the shell that tracks a line buffer *with cursor
position* and a history ring. The shell's raw-mode input loop already reads
one byte at a time; we extend it with a small escape sequence parser
(ESC `[` + suffix) to recognize arrow keys, Home, End, and Delete. Control
keys (Ctrl+A/E/B/F/K/U/W) provide alternative keybinds.

History is stored in a fixed-size ring buffer (64 entries, in-memory only).
Up/Down arrows navigate history. Ctrl+R enters incremental reverse search
mode.

For fbcon: the keymap must be extended so arrow/Home/End keycodes generate
the corresponding ANSI escape sequences, so the shell sees the same byte
stream on both serial and graphics consoles.

### Interface Changes

**No syscall, IPC, or ABI changes.** This is purely a user-space shell
enhancement.

**New shell keybinds:**

| Key | Action |
|-----|--------|
| Left arrow / Ctrl+B | Move cursor left |
| Right arrow / Ctrl+F | Move cursor right |
| Home / Ctrl+A | Move cursor to start of line |
| End / Ctrl+E | Move cursor to end of line |
| Up arrow / Ctrl+P | Previous history entry |
| Down arrow / Ctrl+N | Next history entry (or empty line) |
| Delete | Delete character under cursor |
| Ctrl+R | Enter reverse incremental search |

**Reverse search mode:**

- Typing characters narrows the search
- Backspace removes last search character
- Ctrl+R finds next (older) match
- Enter accepts the found line
- Ctrl+C / Ctrl+G / Escape cancels, restores original line

**New help text:** `help` output updated with a note about keybinds.

### Internal Changes

**`user/shell/src/shell.rs`** — Major changes:

1. **`LineEditor` struct** (new): Holds line buffer (`[u8; 256]`), cursor
   position, buffer length, history ring, history navigation index, and
   search state.

   ```
   struct LineEditor {
       buf: [u8; 256],
       len: usize,
       cursor: usize,          // byte offset in buf
       history: HistoryRing,
       hist_index: Option<usize>,  // None = editing new line
       saved_line: [u8; 256],     // saved current line when navigating history
       saved_len: usize,
       search_mode: bool,
       search_buf: [u8; 64],
       search_len: usize,
       search_match: Option<usize>, // index into history
   }
   ```

2. **`HistoryRing` struct** (new): Fixed-size ring buffer of history
   entries.

   ```
   const HISTORY_MAX: usize = 64;
   const HISTORY_ENTRY_MAX: usize = 256;

   struct HistoryRing {
       entries: [[u8; HISTORY_ENTRY_MAX]; HISTORY_MAX],
       lengths: [usize; HISTORY_MAX],
       head: usize,   // next write position
       count: usize,  // number of valid entries (≤ HISTORY_MAX)
   }
   ```

   Methods: `push(line)`, `get(index) -> Option<&[u8]>` (0 = most recent),
   `search(needle, start_index) -> Option<usize>`.

3. **Escape sequence parser**: A small state machine in the input loop:
   - State `Normal`: byte → action
   - State `Escape`: saw `0x1B`, waiting for `[` or timeout
   - State `CSI`: saw `ESC [`, accumulate parameter bytes, dispatch on
     final byte (A/B/C/D/H/F/3~)

   This replaces the current flat `match byte[0]` in the main input loop.

4. **Cursor rendering helpers**: Functions to move the terminal cursor
   using ANSI escapes (`ESC[nD`, `ESC[nC`) and to redraw the line from
   the cursor position forward (needed after insert/delete in the middle).

   - `redraw_from_cursor()`: print chars from cursor to end, clear
     trailing garbage with `ESC[K` (erase to end of line), reposition
     cursor.
   - `redraw_full()`: `\r` + print prompt + print full line + reposition
     cursor.

5. **Prompt rendering for search mode**: When Ctrl+R is active, replace
   the prompt with `(reverse-i-search)'needle': matched_line` and update
   it as the user types.

**`user/fbcon/src/main.rs`** — Small changes:

6. **Extend KEYMAP**: Map arrow/Home/End/Delete keycodes to generate
   multi-byte ANSI escape sequences. Since the current keymap only
   produces single bytes, change the key input path: when a keycode maps
   to an escape sequence, push multiple bytes into the line discipline
   (or directly to the raw-mode client).

   Linux keycodes for arrow keys:
   - 103 = Up → `ESC [ A` (0x1B, 0x5B, 0x41)
   - 108 = Down → `ESC [ B` (0x1B, 0x5B, 0x42)
   - 105 = Left → `ESC [ D` (0x1B, 0x5B, 0x44)
   - 106 = Right → `ESC [ C` (0x1B, 0x5B, 0x43)
   - 102 = Home → `ESC [ H` (0x1B, 0x5B, 0x48)
   - 107 = End → `ESC [ F` (0x1B, 0x5B, 0x46)
   - 111 = Delete → `ESC [ 3 ~` (0x1B, 0x5B, 0x33, 0x7E)

   Approach: Add a `KEYMAP_ESCAPE` table mapping keycodes to byte
   sequences, checked before the ASCII keymap. When a match is found,
   feed each byte individually through `handle_key_input`.

**`user/fbcon/src/main.rs`** — ANSI output parsing:

7. **Console ANSI escape output**: The fbcon stdout handler currently
   writes characters directly to the framebuffer. For cursor movement
   sequences emitted by the shell (`ESC[nC`, `ESC[nD`, `ESC[K`, `\r`)
   to work, fbcon needs to handle them. Check what fbcon already handles
   and add any missing sequences.

### Resource Limits

| Resource | Limit | Exhaustion Behavior |
|----------|-------|-------------------|
| History entries | 64 | Oldest entry evicted (ring buffer) |
| History entry size | 256 bytes | Lines longer than 256 bytes not stored |
| Line buffer | 256 bytes | Input capped (same as current behavior) |
| Search buffer | 64 bytes | Search query capped at 64 chars |

Total additional memory: ~20 KiB (64 * 256 + overhead). This is stack/BSS
in the shell process, no kernel impact.

## Blast Radius

| Change | Files Affected | Risk |
|--------|---------------|------|
| Rewrite shell input loop | `user/shell/src/shell.rs` (lines 504-549) | Medium — replaces core input handling |
| Add LineEditor / HistoryRing | `user/shell/src/shell.rs` (new structs) | Low (additive, same file) |
| Extend fbcon keymap for arrows | `user/fbcon/src/main.rs` (key handling ~452-465) | Low — additive, existing keys unchanged |
| fbcon ANSI output sequences | `user/fbcon/src/main.rs` (stdout write handler) | Medium — must not break existing output |
| Tab completion integration | `user/shell/src/shell.rs` `handle_tab` | Low — adapt to use cursor-aware redraw |
| `cmd_help` output | `user/shell/src/shell.rs` | Low (text only) |

**No changes to:** kernel, lib/rvos, lib/rvos-proto, syscalls, wire protocols,
kernel-abi.md, or the std sysroot.

## Acceptance Criteria

- [x] **Cursor movement**: Left/Right arrow keys move cursor within the line;
      characters can be inserted mid-line; backspace/delete work at any position
- [x] **Home/End**: Ctrl+A / Home jumps to start; Ctrl+E / End jumps to end
- [x] **History navigation**: Up/Down arrows cycle through history; current
      line is preserved when navigating away and back
- [x] **History push**: Executed commands are added to history; duplicate
      consecutive commands are not added; empty lines are not added
- [x] **Reverse search**: Ctrl+R enters search mode; typing narrows search;
      Ctrl+R cycles to older matches; Enter accepts; Escape/Ctrl+G cancels
- [x] **Search prompt**: Search mode shows `(reverse-i-search)'query': line`
      and updates incrementally
- [x] **Serial console**: All keybinds work over QEMU serial (`-nographic`)
- [x] **Graphics console**: Arrow keys work in fbcon (escape sequences
      generated from keycodes)
- [x] **fbcon ANSI output**: Cursor movement and erase-to-EOL escape
      sequences rendered correctly in fbcon
- [x] **Tab completion**: Still works, integrated with cursor-aware redraw
- [x] **Ctrl+C**: Still clears line and reprints prompt
- [x] **No regressions**: `make build` succeeds; system boots to shell;
      existing commands work; `make bench` shows no significant regression

## Deferred

| Item | Rationale |
|------|-----------|
| Persistent history (across reboots) | Needs filesystem write at shell exit; add later |
| History expansion (`!!`, `!n`) | Complexity not justified for current use |
| Vi mode | User explicitly said readline not needed |
| Multi-line editing | Not needed for a simple shell |
| Kill keys (Ctrl+K/U/W) | Nice-to-have, can add later |
| Kill ring (yank with Ctrl+Y) | Nice-to-have, can add later |
| Ctrl+L clear screen + redraw | Nice-to-have, can add later |
| Word-wise cursor movement (Ctrl+Left/Right) | Requires parsing ESC sequences with modifiers; defer |
| Signal forwarding (Ctrl+C to child) | Separate feature, not line editing |

## Implementation Notes

- `HistoryRing` uses `Box<[[u8; 256]; 64]>` (~16 KiB heap) to avoid
  blowing the stack.
- The escape sequence parser is a 3-state machine (Normal → Escape → CSI)
  with a numeric parameter accumulator. Handles CSI sequences with `~`
  suffix (e.g., `ESC[3~` for Delete).
- `refresh_line()` uses `\r` + prompt + buffer + `ESC[K` (erase to EOL) +
  `ESC[nD` (cursor reposition). Simple but correct; avoids tracking
  display state.
- For fbcon input: special keycodes send the full multi-byte escape
  sequence as one data chunk (relies on std's BufReader to buffer the
  extra bytes). This avoids needing an input queue.
- For fbcon output: added `emit_char` (raw character rendering) and
  `dispatch_csi` (ANSI CSI handler) to FbConsole. Supports cursor
  movement (A/B/C/D/H/F), erase to EOL (K), and clear screen (J).
- Kill keys (Ctrl+K/U/W) and Ctrl+L deferred per user request for
  simpler keybind set.

## Verification

Tested via expect scripts over serial console (`-nographic`):

| Test | Result |
|------|--------|
| Echo command | PASS |
| History recall (Up arrow) | PASS |
| Ctrl+A / Ctrl+E (Home/End) | PASS |
| Left arrow + insert in middle | PASS |
| Delete key (ESC[3~) | PASS |
| History Up/Down navigation | PASS |
| Ctrl+C clears line | PASS |
| Tab completion | PASS |
| Reverse search (Ctrl+R) | PASS |
| Home/End keys (ESC[H/F) | PASS |

Benchmark (`make bench`): no regression — bench suite completes normally.
